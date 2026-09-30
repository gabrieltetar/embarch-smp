//! Serial framing — what Zephyr calls "SMP over console".
//!
//! Ported from `smp.packet` (smp 4.2.0, Apache-2.0, J.P. Hutchins).
//!
//! A message is wrapped as `[u16 length][message][u16 CRC16]`, big-endian,
//! where the length counts the message and the CRC but not itself and the CRC
//! covers the message alone. That frame is base64-encoded and split into
//! lines: the first starts with [`START_DELIMITER`], the rest with
//! [`CONTINUE_DELIMITER`], and each ends in `\n`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::{Error, Result};

pub const START_DELIMITER: [u8; 2] = [6, 9];
pub const CONTINUE_DELIMITER: [u8; 2] = [4, 20];
pub const END_DELIMITER: u8 = b'\n';
pub const DELIMITER_SIZE: usize = 2;

/// The length and the CRC16 that wrap every message.
pub const FRAME_OVERHEAD: usize = 4;

/// "you'd think it's 3, len(delimiter) + len(CR)" — the reference's own words.
const LINE_LENGTH_SUBTRACTOR: usize = 4;

/// The smallest line length that carries any base64 at all: below it the
/// per-line payload is zero and fragmentation never finishes.
pub const MIN_LINE_LENGTH: usize = 8;

/// CRC-16/XMODEM: polynomial 0x1021, initial value 0, no reflection, no final
/// XOR. MCUboot calls the same function `crc16_itu_t`.
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Encode `message` into serial packets of at most `line_length` bytes each,
/// delimiters and newline included.
pub fn encode(message: &[u8], line_length: usize) -> Result<Vec<Vec<u8>>> {
    if line_length < MIN_LINE_LENGTH {
        return Err(Error::InvalidFragmentation(format!(
            "line length {line_length} is below the minimum of {MIN_LINE_LENGTH}"
        )));
    }
    let frame_length = message.len() + 2;
    let frame_length = u16::try_from(frame_length)
        .map_err(|_| Error::TooLarge { size: message.len(), max: usize::from(u16::MAX) - 2 })?;

    let mut frame = Vec::with_capacity(message.len() + FRAME_OVERHEAD);
    frame.extend_from_slice(&frame_length.to_be_bytes());
    frame.extend_from_slice(message);
    frame.extend_from_slice(&crc16_xmodem(message).to_be_bytes());
    let encoded = STANDARD.encode(&frame).into_bytes();

    let packet_size = ((line_length - LINE_LENGTH_SUBTRACTOR) / 4) * 4;
    let mut packets = Vec::with_capacity(encoded.len() / packet_size + 1);
    for (index, chunk) in encoded.chunks(packet_size).enumerate() {
        let delimiter = if index == 0 { START_DELIMITER } else { CONTINUE_DELIMITER };
        let mut packet = Vec::with_capacity(DELIMITER_SIZE + chunk.len() + 1);
        packet.extend_from_slice(&delimiter);
        packet.extend_from_slice(chunk);
        packet.push(END_DELIMITER);
        packets.push(packet);
    }
    Ok(packets)
}

/// Reassembles one frame from its packets, in order.
///
/// Each packet's base64 is decoded on its own, as the reference does: both
/// the reference encoder and MCUboot's (`BOOT_SERIAL_FRAME_MTU` = 124) split
/// lines on a multiple of four base64 characters.
#[derive(Debug, Default)]
pub struct Decoder {
    frame: Vec<u8>,
    frame_length: Option<usize>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one packet, delimiter through newline. Returns the message once
    /// the frame is complete and its CRC checks.
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        let expected = if self.frame_length.is_none() { START_DELIMITER } else { CONTINUE_DELIMITER };
        if packet.len() < DELIMITER_SIZE + 1 || packet[..DELIMITER_SIZE] != expected {
            return Err(Error::BadDelimiter {
                expected,
                got: packet[..packet.len().min(DELIMITER_SIZE)].to_vec(),
            });
        }
        let body = &packet[DELIMITER_SIZE..packet.len() - 1];
        let decoded = STANDARD
            .decode(body)
            .map_err(|e| Error::Malformed(format!("packet base64: {e}")))?;
        self.frame.extend_from_slice(&decoded);

        if self.frame_length.is_none() {
            if self.frame.len() < 2 {
                return Err(Error::Malformed("first packet shorter than the frame length".into()));
            }
            self.frame_length = Some(usize::from(u16::from_be_bytes([self.frame[0], self.frame[1]])));
            self.frame.drain(..2);
        }
        let frame_length = self.frame_length.unwrap_or_default();
        if self.frame.len() < frame_length {
            return Ok(None);
        }
        // Stricter than the reference, which would read a CRC off the end of an
        // over-long frame and fail there: say what actually happened.
        if self.frame.len() > frame_length || frame_length < 2 {
            return Err(Error::Malformed(format!(
                "frame declares {frame_length} bytes, carried {}",
                self.frame.len()
            )));
        }
        let crc_at = frame_length - 2;
        let received = u16::from_be_bytes([self.frame[crc_at], self.frame[crc_at + 1]]);
        let calculated = crc16_xmodem(&self.frame[..crc_at]);
        if received != calculated {
            return Err(Error::BadCrc { received, calculated });
        }
        self.frame.truncate(crc_at);
        self.frame_length = None;
        Ok(Some(std::mem::take(&mut self.frame)))
    }
}

/// Separates SMP packets from any other bytes sharing the line, such as a
/// console banner — ported from the buffer state machine in smpclient's
/// `SMPSerialTransport` (smpclient 7.3.0).
#[derive(Debug, Default)]
pub struct LineSplitter {
    buffer: Vec<u8>,
    in_packet: bool,
    serial: Vec<u8>,
    packets: std::collections::VecDeque<Vec<u8>>,
}

impl LineSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        loop {
            let more = if self.in_packet { self.take_packet() } else { self.take_serial() };
            if !more {
                break;
            }
        }
    }

    /// The next complete packet, delimiter through newline.
    pub fn pop_packet(&mut self) -> Option<Vec<u8>> {
        self.packets.pop_front()
    }

    /// Every non-SMP byte seen so far, drained.
    pub fn take_serial_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.serial)
    }

    fn take_serial(&mut self) -> bool {
        if self.buffer.is_empty() {
            return false;
        }
        let start = [find(&self.buffer, &START_DELIMITER), find(&self.buffer, &CONTINUE_DELIMITER)]
            .into_iter()
            .flatten()
            .min();
        if let Some(start) = start {
            self.serial.extend(self.buffer.drain(..start));
            self.in_packet = true;
            return true;
        }
        // The last byte could be the first half of a delimiter: keep it.
        let last = self.buffer[self.buffer.len() - 1];
        let keep = usize::from(last == START_DELIMITER[0] || last == CONTINUE_DELIMITER[0]);
        let end = self.buffer.len() - keep;
        self.serial.extend(self.buffer.drain(..end));
        false
    }

    fn take_packet(&mut self) -> bool {
        let Some(end) = self.buffer.iter().position(|&b| b == END_DELIMITER) else {
            return false;
        };
        let packet: Vec<u8> = self.buffer.drain(..=end).collect();
        self.packets.push_back(packet);
        self.in_packet = false;
        !self.buffer.is_empty()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitter_keeps_console_text_out_of_packets() {
        let mut s = LineSplitter::new();
        s.feed(b"*** Booting ***\r\n\x06\x09AAAA\n tail\x04");
        s.feed(b"\x14BBBB\n");
        assert_eq!(s.pop_packet().unwrap(), b"\x06\x09AAAA\n");
        assert_eq!(s.pop_packet().unwrap(), b"\x04\x14BBBB\n");
        assert!(s.pop_packet().is_none());
        assert_eq!(s.take_serial_bytes(), b"*** Booting ***\r\n tail");
    }

    #[test]
    fn packet_split_across_reads_is_reassembled() {
        let mut s = LineSplitter::new();
        s.feed(b"\x06");
        s.feed(b"\x09AA");
        assert!(s.pop_packet().is_none());
        s.feed(b"AA\n");
        assert_eq!(s.pop_packet().unwrap(), b"\x06\x09AAAA\n");
    }

    #[test]
    fn decoder_refuses_a_continuation_first() {
        let mut d = Decoder::new();
        assert!(matches!(d.push(b"\x04\x14AAAA\n"), Err(Error::BadDelimiter { .. })));
    }
}
