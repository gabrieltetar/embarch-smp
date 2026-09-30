//! A simulated MCUboot serial-recovery bootloader, for tests.
//!
//! Not a port: written for this crate, modelled on MCUboot's
//! `boot/boot_serial/src/boot_serial.c`. It implements `Read + Write`, so a
//! [`Client`](crate::Client) drives it exactly as it would a COM port, and a
//! caller's own tests (Core's) can drive it through theirs.
//!
//! **What it models, because the client's correctness depends on each:**
//! - a frame larger than the reassembly buffer, or a line longer than the
//!   line buffer, is dropped without a reply — the client times out;
//! - errors are `{"rc": N}` whatever the header version, and the reply echoes
//!   the request's version and sequence;
//! - an upload at offset 0 needs `len`, erases the slot and starts over;
//! - a chunk at the wrong offset is not written and the reply names the offset
//!   expected;
//! - a chunk is written only up to the flash write alignment unless it is the
//!   last, and the reply's offset says so;
//! - echo and image-state read exist only when "built" with them.
//!
//! **What it does not model:** timing, the 250 ms before a reset takes effect,
//! USB re-enumeration, and image validation at boot.

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ciborium::Value;

use crate::header::{self, command, group, Header};
use crate::image::ImageInfo;
use crate::message::{as_i64, map_get};
use crate::packet::{crc16_xmodem, Decoder, LineSplitter, CONTINUE_DELIMITER, START_DELIMITER};

/// MCUboot's `BOOT_SERIAL_FRAME_MTU`: base64 characters per reply line.
const REPLY_LINE_CHARS: usize = 124;

const EINVAL: i64 = 3;
const ENOTSUP: i64 = 8;

#[derive(Debug, Clone)]
pub struct SimConfig {
    /// `CONFIG_BOOT_SERIAL_MAX_RECEIVE_SIZE`: the largest decoded frame.
    pub buf_size: usize,
    /// `CONFIG_BOOT_MAX_LINE_INPUT_LEN`: the longest line, newline included.
    pub max_line: usize,
    pub slot_size: usize,
    /// Flash write alignment.
    pub write_align: usize,
    /// `CONFIG_BOOT_MGMT_ECHO`.
    pub echo: bool,
    /// `CONFIG_BOOT_SERIAL_IMG_GRP_IMAGE_STATE`.
    pub image_state: bool,
    /// Console bytes emitted ahead of the first reply, as a banner would be.
    pub banner: Vec<u8>,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            buf_size: 1024,
            max_line: 128,
            slot_size: 256 * 1024,
            write_align: 8,
            echo: true,
            image_state: true,
            banner: Vec::new(),
        }
    }
}

/// What the simulator saw, for a test to assert on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub group: u16,
    pub command: u8,
    pub sequence: u8,
    /// Decoded frame size: length, message and CRC.
    pub frame_len: usize,
    pub replied: bool,
}

#[derive(Debug)]
pub struct SimBootloader {
    pub config: SimConfig,
    slot: Vec<u8>,
    img_size: usize,
    curr_off: usize,
    splitter: LineSplitter,
    decoder: Decoder,
    out: VecDeque<u8>,
    resets: usize,
    drop_next: usize,
    seen: Vec<Seen>,
}

impl SimBootloader {
    pub fn new(config: SimConfig) -> Self {
        let mut out = VecDeque::new();
        out.extend(config.banner.iter().copied());
        SimBootloader {
            slot: vec![0xff; config.slot_size],
            config,
            img_size: 0,
            curr_off: 0,
            splitter: LineSplitter::new(),
            decoder: Decoder::new(),
            out,
            resets: 0,
            drop_next: 0,
            seen: Vec::new(),
        }
    }

    /// The bytes of the last upload, as far as they were written.
    pub fn image(&self) -> &[u8] {
        &self.slot[..self.img_size]
    }

    pub fn resets(&self) -> usize {
        self.resets
    }

    pub fn seen(&self) -> &[Seen] {
        &self.seen
    }

    /// Swallow the next `n` replies, as a lost line would.
    pub fn drop_next_replies(&mut self, n: usize) {
        self.drop_next = n;
    }

    fn on_packet(&mut self, line: &[u8]) {
        if line.len() > self.config.max_line {
            self.decoder = Decoder::new();
            return;
        }
        match self.decoder.push(line) {
            Ok(Some(message)) => self.on_message(&message),
            Ok(None) => {}
            Err(_) => self.decoder = Decoder::new(),
        }
    }

    fn on_message(&mut self, message: &[u8]) {
        let Ok(request) = Header::parse(message) else { return };
        let frame_len = message.len() + 4;
        let mut seen = Seen {
            group: request.group,
            command: request.command,
            sequence: request.sequence,
            frame_len,
            replied: false,
        };
        if frame_len > self.config.buf_size {
            self.seen.push(seen);
            return;
        }
        let body: Value = ciborium::from_reader(&message[header::SIZE..]).unwrap_or(Value::Map(vec![]));
        let reply = match (request.group, request.command) {
            (group::IMAGE, command::image::UPLOAD) => self.upload(&body),
            (group::IMAGE, command::image::STATE) if self.config.image_state => self.list(),
            (group::OS, command::os::ECHO) if self.config.echo => match map_get(&body, "d") {
                Some(Value::Text(d)) => vec![("r", Value::Text(d.clone()))],
                _ => rc(EINVAL),
            },
            (group::OS, command::os::RESET) => {
                self.resets += 1;
                rc(0)
            }
            _ => rc(ENOTSUP),
        };
        if self.drop_next > 0 {
            self.drop_next -= 1;
        } else {
            self.reply(&request, reply);
            seen.replied = true;
        }
        self.seen.push(seen);
    }

    fn upload(&mut self, body: &Value) -> Vec<(&'static str, Value)> {
        let off = map_get(body, "off").and_then(as_i64);
        let Some(Value::Bytes(data)) = map_get(body, "data") else { return rc(EINVAL) };
        let Some(off) = off.and_then(|o| usize::try_from(o).ok()) else { return rc(EINVAL) };
        if off == 0 {
            let Some(len) = map_get(body, "len").and_then(as_i64).and_then(|l| usize::try_from(l).ok()) else {
                return rc(EINVAL);
            };
            if len > self.config.slot_size {
                return rc(EINVAL);
            }
            self.img_size = len;
            self.curr_off = 0;
            self.slot.fill(0xff);
        } else if off != self.curr_off {
            return vec![("rc", Value::Integer(0.into())), ("off", Value::Integer(self.curr_off.into()))];
        }
        if self.curr_off + data.len() > self.img_size {
            return rc(EINVAL);
        }
        let mut len = data.len();
        if self.curr_off + len < self.img_size {
            len -= len % self.config.write_align;
        }
        self.slot[self.curr_off..self.curr_off + len].copy_from_slice(&data[..len]);
        self.curr_off += len;
        vec![("rc", Value::Integer(0.into())), ("off", Value::Integer(self.curr_off.into()))]
    }

    fn list(&self) -> Vec<(&'static str, Value)> {
        let mut images = Vec::new();
        if let Ok(info) = ImageInfo::parse(&self.slot[..self.img_size]) {
            let v = info.header.version;
            let mut version = format!("{}.{}.{}", v.major, v.minor, v.revision);
            if v.build_num != 0 {
                version.push_str(&format!(".{}", v.build_num));
            }
            images.push(Value::Map(vec![
                (Value::Text("slot".into()), Value::Integer(0.into())),
                (Value::Text("version".into()), Value::Text(version)),
            ]));
        }
        vec![("images", Value::Array(images))]
    }

    /// Encode a reply the way `boot_serial_output` does: the request's header
    /// with the op advanced, CRC16 over header and body, base64 split every
    /// 124 characters.
    fn reply(&mut self, request: &Header, body: Vec<(&'static str, Value)>) {
        let map = Value::Map(body.into_iter().map(|(k, v)| (Value::Text(k.into()), v)).collect());
        let mut cbor = Vec::new();
        ciborium::into_writer(&map, &mut cbor).expect("a Vec never fails to write");
        let header = Header { op: request.op.response(), flags: 0, length: cbor.len() as u16, ..*request };
        let mut message = header.to_bytes().to_vec();
        message.extend_from_slice(&cbor);

        let mut frame = ((message.len() + 2) as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&message);
        frame.extend_from_slice(&crc16_xmodem(&message).to_be_bytes());
        let encoded = STANDARD.encode(&frame).into_bytes();
        for (i, chunk) in encoded.chunks(REPLY_LINE_CHARS).enumerate() {
            self.out.extend(if i == 0 { START_DELIMITER } else { CONTINUE_DELIMITER });
            self.out.extend(chunk.iter().copied());
            self.out.push_back(b'\n');
        }
    }
}

fn rc(code: i64) -> Vec<(&'static str, Value)> {
    vec![("rc", Value::Integer(code.into()))]
}

impl Read for SimBootloader {
    /// Nothing waiting is `WouldBlock`: unlike a serial port's `TimedOut`, the
    /// simulator did not wait, so the client should.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.out.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no reply waiting"));
        }
        let n = buf.len().min(self.out.len());
        for (slot, byte) in buf.iter_mut().zip(self.out.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

impl Write for SimBootloader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.splitter.feed(buf);
        while let Some(line) = self.splitter.pop_packet() {
            self.on_packet(&line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
