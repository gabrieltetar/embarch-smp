//! A blocking SMP client over any `Read + Write`.
//!
//! Ported from `smpclient.SMPClient` and the serial transport's send/receive
//! (smpclient 7.3.0, Apache-2.0, Intercreate, Inc.). **It never opens a port**
//! (decision 2): the caller opens one, sets a short read timeout on it, and
//! hands it in.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::fragmentation::Fragmentation;
use crate::header::{self, Version};
use crate::message::{ImageState, Request, Response, UploadReply, UploadStart};
use crate::packet::{self, Decoder, LineSplitter};

/// The reference's default per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2500);

/// The reference's default for the first upload chunk, which can wait on the
/// server erasing the whole slot before it answers.
pub const DEFAULT_FIRST_CHUNK_TIMEOUT: Duration = Duration::from_secs(40);

/// Consecutive upload replies that do not advance the offset before the
/// upload is abandoned. The reference loops forever instead (decision 9).
pub const DEFAULT_MAX_STALLS: u32 = 5;

/// How long to wait before reading again when the stream returned at once with
/// nothing (`WouldBlock`, or `Ok(0)`). A serial port's `TimedOut` has already
/// waited out its own read timeout, so it is retried immediately.
const IDLE_POLL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadOptions {
    /// Image number, `image` on the wire.
    pub image: u32,
    /// Send `upgrade`: only accept an image newer than the running one.
    /// The reference sends `false` explicitly, and so do we.
    pub upgrade: bool,
    /// Send the SHA-256 of the whole image with the first chunk.
    pub use_sha: bool,
    pub first_timeout: Duration,
    pub timeout: Duration,
    pub max_stalls: u32,
}

impl Default for UploadOptions {
    fn default() -> Self {
        UploadOptions {
            image: 0,
            upgrade: false,
            use_sha: true,
            first_timeout: DEFAULT_FIRST_CHUNK_TIMEOUT,
            timeout: DEFAULT_TIMEOUT,
            max_stalls: DEFAULT_MAX_STALLS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSummary {
    pub bytes: usize,
    pub requests: usize,
    /// The server's verdict on the SHA-256, where it gave one.
    pub matched: Option<bool>,
}

pub struct Client<T> {
    io: T,
    fragmentation: Fragmentation,
    version: Version,
    sequence: u8,
    splitter: LineSplitter,
    stale_frames: usize,
    pub timeout: Duration,
}

impl<T: Read + Write> Client<T> {
    pub fn new(io: T) -> Self {
        Client {
            io,
            fragmentation: Fragmentation::default(),
            version: Version::default(),
            sequence: 0,
            splitter: LineSplitter::new(),
            stale_frames: 0,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_fragmentation(mut self, fragmentation: Fragmentation) -> Result<Self> {
        fragmentation.validate()?;
        self.fragmentation = fragmentation;
        Ok(self)
    }

    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Start numbering requests from `sequence`, as a test that compares
    /// against recorded bytes needs to.
    pub fn with_sequence(mut self, sequence: u8) -> Self {
        self.sequence = sequence;
        self
    }

    pub fn fragmentation(&self) -> Fragmentation {
        self.fragmentation
    }

    pub fn get_ref(&self) -> &T {
        &self.io
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.io
    }

    pub fn into_inner(self) -> T {
        self.io
    }

    /// Bytes that arrived outside any SMP packet — a console banner, a log
    /// line — drained. Kept rather than dropped, because on a shared console
    /// they are often the only account of why a device went quiet.
    pub fn take_serial_bytes(&mut self) -> Vec<u8> {
        self.splitter.take_serial_bytes()
    }

    /// Responses discarded because their sequence number answered an earlier,
    /// timed-out request (decision 9).
    pub fn stale_frames(&self) -> usize {
        self.stale_frames
    }

    /// Send `request` and wait up to `timeout` for its response. An error
    /// *response* is returned as `Ok`; `Response::ok` turns it into `Err`.
    pub fn request(&mut self, request: &Request, timeout: Duration) -> Result<Response> {
        let sequence = self.next_sequence();
        let message = request.clone().with_version(self.version).encode(sequence)?;
        let max = self.fragmentation.max_unencoded_size();
        if message.len() > max {
            return Err(Error::TooLarge { size: message.len(), max });
        }
        for line in packet::encode(&message, self.fragmentation.line_length())? {
            self.io.write_all(&line)?;
        }
        self.io.flush()?;
        self.receive(sequence, timeout, describe(request))
    }

    /// OS echo.
    pub fn echo(&mut self, d: &str) -> Result<String> {
        let response = self.request(&Request::echo(d), self.timeout)?.ok()?;
        response
            .get("r")
            .and_then(|v| v.as_text())
            .map(str::to_string)
            .ok_or_else(|| Error::Malformed(format!("echo reply without `r`: {:?}", response.body)))
    }

    /// OS reset. The server answers before it resets.
    pub fn reset(&mut self) -> Result<()> {
        self.request(&Request::reset(false), self.timeout)?.ok().map(|_| ())
    }

    /// Image state read.
    pub fn image_states(&mut self) -> Result<Vec<ImageState>> {
        let response = self.request(&Request::image_state_read(), self.timeout)?.ok()?;
        ImageState::list_from(&response)
    }

    /// Upload `image`, calling `progress` with the server's offset after each
    /// chunk. Every chunk is as large as the fragmentation allows, and the
    /// next one starts wherever the server says, not where this side thinks
    /// the last one ended — MCUboot answers with a flash-aligned offset.
    pub fn upload(
        &mut self,
        image: &[u8],
        options: &UploadOptions,
        mut progress: impl FnMut(u64),
    ) -> Result<UploadSummary> {
        let total = image.len() as u64;
        let start = UploadStart {
            image: options.image,
            len: total,
            sha: options.use_sha.then(|| Sha256::digest(image).to_vec()),
            upgrade: Some(options.upgrade),
        };
        let mut reply = self.upload_chunk(image, 0, Some(&start), options.first_timeout)?;
        let mut requests = 1;
        progress(reply.off);

        let mut stalls = 0;
        while reply.off != total {
            if reply.off > total {
                return Err(Error::Upload(format!("server reports offset {} past the {total}-byte image", reply.off)));
            }
            // The reference re-sends `len`, `image` and `upgrade` — never `sha` —
            // whenever the server asks for offset 0 again.
            let restart = UploadStart { sha: None, ..start.clone() };
            let chunk_start = (reply.off == 0).then_some(&restart);
            let next = self.upload_chunk(image, reply.off, chunk_start, options.timeout)?;
            requests += 1;
            if next.off == reply.off {
                stalls += 1;
                if stalls >= options.max_stalls {
                    return Err(Error::Upload(format!(
                        "offset stuck at {} for {stalls} consecutive replies",
                        next.off
                    )));
                }
            } else {
                stalls = 0;
            }
            reply = next;
            progress(reply.off);
        }
        if reply.matched == Some(false) {
            return Err(Error::Upload("server reports the uploaded image does not match its SHA-256".into()));
        }
        Ok(UploadSummary { bytes: image.len(), requests, matched: reply.matched })
    }

    /// The largest chunk that fits, starting at `off`.
    fn upload_chunk(
        &mut self,
        image: &[u8],
        off: u64,
        start: Option<&UploadStart>,
        timeout: Duration,
    ) -> Result<UploadReply> {
        let request = self.maximized_upload(image, off, start)?;
        let response = self.request(&request, timeout)?.ok()?;
        UploadReply::from_response(&response)
    }

    /// Port of the reference's `_maximize_upload_packet`: measure the request
    /// with an empty `data`, then fill what is left, less the bytes that
    /// encoding the data's own length costs.
    pub fn maximized_upload(&self, image: &[u8], off: u64, start: Option<&UploadStart>) -> Result<Request> {
        let off_usize = usize::try_from(off).map_err(|_| Error::Upload(format!("offset {off} out of range")))?;
        let remaining = image.len().checked_sub(off_usize).ok_or_else(|| {
            Error::Upload(format!("offset {off} is past the {}-byte image", image.len()))
        })?;
        let empty = Request::image_upload(off, &[], start).with_version(self.version);
        let empty_size = header::SIZE + empty.encode_body()?.len();
        let available = self.fragmentation.max_unencoded_size().saturating_sub(empty_size);
        let data_size = available.saturating_sub(cbor_integer_size(available)).min(remaining);
        if data_size == 0 && remaining > 0 {
            return Err(Error::TooLarge { size: empty_size + 1, max: self.fragmentation.max_unencoded_size() });
        }
        Ok(Request::image_upload(off, &image[off_usize..off_usize + data_size], start))
    }

    fn next_sequence(&mut self) -> u8 {
        let sequence = self.sequence;
        // The reference counts modulo 0xFF, so 255 is never used.
        self.sequence = ((u16::from(sequence) + 1) % 0xFF) as u8;
        sequence
    }

    fn receive(&mut self, sequence: u8, timeout: Duration, what: &'static str) -> Result<Response> {
        let deadline = Instant::now() + timeout;
        let mut decoder = Decoder::new();
        let mut buf = [0u8; 512];
        loop {
            while let Some(line) = self.splitter.pop_packet() {
                let Some(message) = decoder.push(&line)? else { continue };
                let response = Response::parse(&message)?;
                if response.header.sequence == sequence {
                    return Ok(response);
                }
                // A late answer to a request that already timed out. The
                // reference raises here; we skip it and keep waiting.
                self.stale_frames += 1;
                decoder = Decoder::new();
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout { waited: timeout, what });
            }
            match self.io.read(&mut buf) {
                Ok(0) => std::thread::sleep(IDLE_POLL),
                Ok(n) => self.splitter.feed(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(IDLE_POLL),
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }
}

/// CBOR packs an integer's size as small as it can. Port of the reference's
/// `_cbor_integer_size`.
fn cbor_integer_size(n: usize) -> usize {
    match n {
        0..=23 => 0,
        24..=0xFF => 1,
        0x100..=0xFFFF => 2,
        _ => 4,
    }
}

fn describe(request: &Request) -> &'static str {
    use crate::header::{command, group};
    match (request.group, request.command) {
        (group::OS, command::os::ECHO) => "echo",
        (group::OS, command::os::RESET) => "reset",
        (group::IMAGE, command::image::STATE) => "image state",
        (group::IMAGE, command::image::UPLOAD) => "image upload",
        _ => "request",
    }
}
