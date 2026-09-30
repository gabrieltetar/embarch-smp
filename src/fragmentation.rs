//! How large a message the server can take, and how it is cut into lines.
//!
//! Ported from `smpclient.transport.serial.encoded` (smpclient 7.3.0,
//! Apache-2.0, Intercreate, Inc.).
//!
//! The reference's default, `Auto`, asks the server for its buffer size with
//! the MCUmgr-parameters command. **MCUboot serial recovery does not implement
//! that command** (its OS group answers echo, echo control and reset only), so
//! `Auto` is not ported; its before-the-answer fallback is our default
//! (decision 7).

use crate::error::{Error, Result};
use crate::packet::{DELIMITER_SIZE, FRAME_OVERHEAD, MIN_LINE_LENGTH};

pub const DEFAULT_LINE_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fragmentation {
    /// The server's decoded reassembly buffer is known — for MCUboot,
    /// `CONFIG_BOOT_SERIAL_MAX_RECEIVE_SIZE` (Kconfig default 1024). A
    /// message may then be `buf_size - 4` bytes: the frame's length and CRC
    /// share that buffer.
    BufferSize { buf_size: usize, line_length: usize },
    /// Bound the message by an *encoded* budget of `line_buffers` lines of
    /// `line_length` bytes. Deliberately conservative.
    BufferParams { line_length: usize, line_buffers: usize },
}

impl Default for Fragmentation {
    /// Two 128-byte lines, the reference's assumption before a server has told
    /// it anything: a 169-byte message, safe for any MCUboot serial-recovery
    /// build and slow for most.
    fn default() -> Self {
        Fragmentation::BufferParams { line_length: DEFAULT_LINE_LENGTH, line_buffers: 2 }
    }
}

impl Fragmentation {
    /// `BufferSize` with the conventional 128-byte line.
    pub fn buffer_size(buf_size: usize) -> Self {
        Fragmentation::BufferSize { buf_size, line_length: DEFAULT_LINE_LENGTH }
    }

    pub fn line_length(&self) -> usize {
        match *self {
            Fragmentation::BufferSize { line_length, .. } | Fragmentation::BufferParams { line_length, .. } => {
                line_length
            }
        }
    }

    /// The largest header-plus-body the server can take in one frame.
    pub fn max_unencoded_size(&self) -> usize {
        match *self {
            Fragmentation::BufferSize { buf_size, .. } => buf_size.saturating_sub(FRAME_OVERHEAD),
            Fragmentation::BufferParams { line_length, line_buffers } => {
                usize::try_from(encoded_budget(line_length * line_buffers, line_buffers)).unwrap_or(0)
            }
        }
    }

    /// Refuse a configuration that could never carry a message, rather than
    /// fail downstream in a way that names the symptom.
    pub fn validate(&self) -> Result<()> {
        if self.line_length() < MIN_LINE_LENGTH {
            return Err(Error::InvalidFragmentation(format!(
                "line length {} is below the minimum of {MIN_LINE_LENGTH}",
                self.line_length()
            )));
        }
        match *self {
            Fragmentation::BufferSize { buf_size, .. } if buf_size <= FRAME_OVERHEAD => {
                Err(Error::InvalidFragmentation(format!(
                    "buffer size {buf_size} does not exceed the {FRAME_OVERHEAD}-byte frame overhead"
                )))
            }
            Fragmentation::BufferParams { line_buffers: 0, .. } => {
                Err(Error::InvalidFragmentation("line buffers must be at least 1".into()))
            }
            Fragmentation::BufferParams { line_length, line_buffers }
                if encoded_budget(line_length * line_buffers, line_buffers) <= 0 =>
            {
                Err(Error::InvalidFragmentation(format!(
                    "{line_buffers} lines of {line_length} bytes cannot carry a message"
                )))
            }
            _ => Ok(()),
        }
    }
}

/// The worst case size required to base64-encode `size` bytes.
fn base64_cost(size: usize) -> i64 {
    if size == 0 {
        0
    } else {
        (4 * size as i64 + 2) / 3 + 2
    }
}

/// Given an encoded budget of `size` bytes, how many bytes it can carry.
fn base64_max(size: usize) -> i64 {
    if size < 4 {
        0
    } else {
        (3 * size as i64) / 4 - 2
    }
}

/// Unencoded capacity within an encoded budget of `mtu` bytes spread over
/// `line_buffers` lines. May be negative when `mtu` cannot hold the framing.
fn encoded_budget(mtu: usize, line_buffers: usize) -> i64 {
    let packet_framing = (base64_cost(FRAME_OVERHEAD) + DELIMITER_SIZE as i64) * line_buffers as i64 + 1;
    base64_max(mtu) - packet_framing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_reference() {
        assert_eq!(Fragmentation::default().max_unencoded_size(), 169);
        assert_eq!(Fragmentation::buffer_size(1024).max_unencoded_size(), 1020);
    }

    #[test]
    fn nonsense_is_refused() {
        assert!(Fragmentation::buffer_size(4).validate().is_err());
        assert!(Fragmentation::BufferParams { line_length: 7, line_buffers: 2 }.validate().is_err());
        assert!(Fragmentation::BufferParams { line_length: 128, line_buffers: 0 }.validate().is_err());
        assert!(Fragmentation::BufferParams { line_length: 8, line_buffers: 1 }.validate().is_err());
    }
}
