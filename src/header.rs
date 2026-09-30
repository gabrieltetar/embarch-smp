//! The 8-byte SMP header.
//!
//! Ported from `smp.header` (smp 4.2.0, Apache-2.0, J.P. Hutchins).
//!
//! Layout, big-endian: `[res:3 | version:2 | op:3] [flags] [length:16]
//! [group:16] [sequence] [command]`.

use crate::error::{Error, Result};

pub const SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read = 0,
    ReadRsp = 1,
    Write = 2,
    WriteRsp = 3,
}

impl Op {
    fn from_bits(bits: u8) -> Result<Self> {
        Ok(match bits {
            0 => Op::Read,
            1 => Op::ReadRsp,
            2 => Op::Write,
            3 => Op::WriteRsp,
            other => return Err(Error::Malformed(format!("header op {other}"))),
        })
    }

    /// The op a server answers this one with.
    pub fn response(self) -> Op {
        match self {
            Op::Read | Op::ReadRsp => Op::ReadRsp,
            Op::Write | Op::WriteRsp => Op::WriteRsp,
        }
    }
}

/// SMP protocol version. v2 is the reference's default and ours; MCUboot
/// serial recovery accepts either and echoes it back (embarch-smp decision 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Version {
    V1 = 0,
    #[default]
    V2 = 1,
}

impl Version {
    fn from_bits(bits: u8) -> Result<Self> {
        Ok(match bits {
            0 => Version::V1,
            1 => Version::V2,
            other => return Err(Error::Malformed(format!("header version {other}"))),
        })
    }
}

/// Management group IDs this crate uses.
pub mod group {
    pub const OS: u16 = 0;
    pub const IMAGE: u16 = 1;
}

/// Command IDs this crate uses, per group.
pub mod command {
    pub mod os {
        pub const ECHO: u8 = 0;
        pub const RESET: u8 = 5;
    }
    pub mod image {
        pub const STATE: u8 = 0;
        pub const UPLOAD: u8 = 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub op: Op,
    pub version: Version,
    pub flags: u8,
    pub length: u16,
    pub group: u16,
    pub sequence: u8,
    pub command: u8,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; SIZE] {
        let [len_hi, len_lo] = self.length.to_be_bytes();
        let [group_hi, group_lo] = self.group.to_be_bytes();
        [
            (self.op as u8) | ((self.version as u8) << 3),
            self.flags,
            len_hi,
            len_lo,
            group_hi,
            group_lo,
            self.sequence,
            self.command,
        ]
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SIZE {
            return Err(Error::Malformed(format!("header needs {SIZE} bytes, got {}", bytes.len())));
        }
        Ok(Header {
            op: Op::from_bits(bytes[0] & 0b111)?,
            version: Version::from_bits((bytes[0] >> 3) & 0b11)?,
            flags: bytes[1],
            length: u16::from_be_bytes([bytes[2], bytes[3]]),
            group: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence: bytes[6],
            command: bytes[7],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = Header {
            op: Op::WriteRsp,
            version: Version::V2,
            flags: 0,
            length: 0x1234,
            group: group::IMAGE,
            sequence: 254,
            command: command::image::UPLOAD,
        };
        assert_eq!(h.to_bytes(), [0x0b, 0, 0x12, 0x34, 0, 1, 254, 1]);
        assert_eq!(Header::parse(&h.to_bytes()).unwrap(), h);
    }
}
