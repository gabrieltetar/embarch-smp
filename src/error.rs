//! The one error type every fallible call in this crate returns.

use std::fmt;
use std::time::Duration;

/// What went wrong, in terms a caller can act on without reading the wire.
#[derive(Debug)]
pub enum Error {
    /// The stream the caller handed in failed.
    Io(std::io::Error),
    /// No complete response arrived before the deadline.
    Timeout { waited: Duration, what: &'static str },
    /// A serial packet did not start with the delimiter its position requires.
    BadDelimiter { expected: [u8; 2], got: Vec<u8> },
    /// A frame's CRC16 did not match its contents.
    BadCrc { received: u16, calculated: u16 },
    /// Bytes that do not parse as what they claim to be.
    Malformed(String),
    /// A request that cannot fit the server's buffer, as configured.
    TooLarge { size: usize, max: usize },
    /// A fragmentation configuration that cannot carry a message at all.
    InvalidFragmentation(String),
    /// The server answered with an error: a non-zero `rc`, or a v2 `err` map.
    Smp(SmpError),
    /// The upload stopped making progress, or the server reported a state the
    /// upload cannot continue from.
    Upload(String),
}

/// An error response from the SMP server.
///
/// **MCUboot serial recovery answers every failure as `{"rc": N}`**, whatever
/// header version the request carried (embarch-smp decision 8), so `group` is
/// `None` there; a Zephyr SMP server speaking v2 fills it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmpError {
    pub rc: i64,
    pub group: Option<u16>,
    pub reason: Option<String>,
}

impl SmpError {
    /// The name of a general `MGMT_ERR` code, where `rc` is one. A v2 error's
    /// `rc` is group-specific, so this is only meaningful when `group` is `None`.
    pub fn mgmt_name(&self) -> Option<&'static str> {
        Some(match self.rc {
            0 => "EOK",
            1 => "EUNKNOWN",
            2 => "ENOMEM",
            3 => "EINVAL",
            4 => "ETIMEOUT",
            5 => "ENOENT",
            6 => "EBADSTATE",
            7 => "EMSGSIZE",
            8 => "ENOTSUP",
            9 => "ECORRUPT",
            10 => "EBUSY",
            11 => "EACCESSDENIED",
            12 => "UNSUPPORTED_TOO_OLD",
            13 => "UNSUPPORTED_TOO_NEW",
            _ => return None,
        })
    }
}

impl fmt::Display for SmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.group, self.mgmt_name()) {
            (Some(group), _) => write!(f, "group {group} rc {}", self.rc)?,
            (None, Some(name)) => write!(f, "rc {} ({name})", self.rc)?,
            (None, None) => write!(f, "rc {}", self.rc)?,
        }
        if let Some(reason) = &self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O: {e}"),
            Error::Timeout { waited, what } => {
                write!(f, "no response to {what} within {} ms", waited.as_millis())
            }
            Error::BadDelimiter { expected, got } => {
                write!(f, "bad packet delimiter: expected {expected:02x?}, got {got:02x?}")
            }
            Error::BadCrc { received, calculated } => {
                write!(f, "bad CRC16: frame carries {received:#06x}, contents give {calculated:#06x}")
            }
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::TooLarge { size, max } => {
                write!(f, "request is {size} bytes, the configured buffer carries at most {max}")
            }
            Error::InvalidFragmentation(m) => write!(f, "invalid fragmentation: {m}"),
            Error::Smp(e) => write!(f, "server error: {e}"),
            Error::Upload(m) => write!(f, "upload: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
