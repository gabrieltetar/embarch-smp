//! Requests and responses: a header plus a CBOR map.
//!
//! Ported from `smp.message`, `smp.os_management`, `smp.image_management` and
//! `smp.error` (smp 4.2.0, Apache-2.0, J.P. Hutchins) — the four commands
//! MCUboot serial recovery answers, not the whole protocol (decision 4).
//!
//! **Bodies are encoded canonically**, keys ordered shortest first and then
//! bytewise, as the reference's `cbor2.dumps(..., canonical=True)` does
//! (decision 6). That is what makes the fixtures a byte-for-byte check rather
//! than a semantic one.

use ciborium::Value;

use crate::error::{Error, Result, SmpError};
use crate::header::{self, command, group, Header, Op, Version};

/// One SMP request, before a sequence number is assigned.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub op: Op,
    pub group: u16,
    pub command: u8,
    pub version: Version,
    pub body: Vec<(String, Value)>,
}

/// The fields only the first upload chunk carries.
#[derive(Debug, Clone, PartialEq)]
pub struct UploadStart {
    /// Image number; `image` on the wire. 0 unless the device has several.
    pub image: u32,
    pub len: u64,
    /// SHA-256 of the whole upload, if sent.
    pub sha: Option<Vec<u8>>,
    pub upgrade: Option<bool>,
}

impl Request {
    fn new(op: Op, group: u16, command: u8, body: Vec<(&str, Value)>) -> Self {
        Request {
            op,
            group,
            command,
            version: Version::default(),
            body: body.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        }
    }

    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// OS echo: the server returns `d` as `r`. MCUboot answers it only when
    /// built with `CONFIG_BOOT_MGMT_ECHO`.
    pub fn echo(d: &str) -> Self {
        Self::new(Op::Write, group::OS, command::os::ECHO, vec![("d", Value::Text(d.into()))])
    }

    /// OS reset. `force` asks a server that answered `EBUSY` to reset anyway.
    pub fn reset(force: bool) -> Self {
        let body = if force { vec![("force", Value::Integer(1.into()))] } else { vec![] };
        Self::new(Op::Write, group::OS, command::os::RESET, body)
    }

    /// Image state read. Optional in MCUboot serial recovery
    /// (`CONFIG_BOOT_SERIAL_IMG_GRP_IMAGE_STATE`).
    pub fn image_state_read() -> Self {
        Self::new(Op::Read, group::IMAGE, command::image::STATE, vec![])
    }

    /// One image upload chunk. `start` is `Some` exactly for the chunks the
    /// reference sends `len`/`image`/`upgrade` with: the one at offset 0.
    pub fn image_upload(off: u64, data: &[u8], start: Option<&UploadStart>) -> Self {
        let mut body = vec![("off", Value::Integer(off.into())), ("data", Value::Bytes(data.to_vec()))];
        if let Some(start) = start {
            body.push(("image", Value::Integer(start.image.into())));
            body.push(("len", Value::Integer(start.len.into())));
            if let Some(sha) = &start.sha {
                body.push(("sha", Value::Bytes(sha.clone())));
            }
            if let Some(upgrade) = start.upgrade {
                body.push(("upgrade", Value::Bool(upgrade)));
            }
        }
        Self::new(Op::Write, group::IMAGE, command::image::UPLOAD, body)
    }

    /// The canonical CBOR body alone.
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<&(String, Value)> = self.body.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes())));
        let map = Value::Map(entries.into_iter().map(|(k, v)| (Value::Text(k.clone()), v.clone())).collect());
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).map_err(|e| Error::Malformed(format!("CBOR encode: {e}")))?;
        Ok(out)
    }

    /// Header and body, as they go into a frame.
    pub fn encode(&self, sequence: u8) -> Result<Vec<u8>> {
        let body = self.encode_body()?;
        let length = u16::try_from(body.len())
            .map_err(|_| Error::TooLarge { size: body.len(), max: usize::from(u16::MAX) })?;
        let header = Header {
            op: self.op,
            version: self.version,
            flags: 0,
            length,
            group: self.group,
            sequence,
            command: self.command,
        };
        let mut out = Vec::with_capacity(header::SIZE + body.len());
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// One SMP response: its header and its decoded CBOR body.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub header: Header,
    pub body: Value,
}

impl Response {
    pub fn parse(message: &[u8]) -> Result<Self> {
        let header = Header::parse(message)?;
        let rest = &message[header::SIZE..];
        if rest.len() != usize::from(header.length) {
            return Err(Error::Malformed(format!(
                "header declares a {}-byte body, frame carries {}",
                header.length,
                rest.len()
            )));
        }
        let body = if rest.is_empty() {
            Value::Map(vec![])
        } else {
            ciborium::from_reader(rest).map_err(|e| Error::Malformed(format!("CBOR body: {e}")))?
        };
        if !matches!(body, Value::Map(_)) {
            return Err(Error::Malformed("response body is not a CBOR map".into()));
        }
        Ok(Response { header, body })
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        map_get(&self.body, key)
    }

    /// The server's error, if this response is one.
    ///
    /// **A non-zero `rc` is an error in any response, and `rc: 0` is success**
    /// (decision 8). The reference instead tries the success shape first, so
    /// an upload reply of `{"rc": 3}` parses as a success with no offset; the
    /// upload then fails, with a less useful message.
    pub fn error(&self) -> Option<SmpError> {
        if let Some(err) = self.get("err") {
            let rc = map_get(err, "rc").and_then(as_i64).unwrap_or(0);
            if rc != 0 {
                return Some(SmpError {
                    rc,
                    group: map_get(err, "group").and_then(as_i64).and_then(|g| u16::try_from(g).ok()),
                    reason: None,
                });
            }
        }
        let rc = self.get("rc").and_then(as_i64).unwrap_or(0);
        (rc != 0).then(|| SmpError {
            rc,
            group: None,
            reason: self.get("rsn").and_then(|v| v.as_text()).map(str::to_string),
        })
    }

    /// `Err` for an error response, so a typed accessor can `?` it first.
    pub fn ok(self) -> Result<Self> {
        match self.error() {
            Some(e) => Err(Error::Smp(e)),
            None => Ok(self),
        }
    }
}

/// An upload chunk's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadReply {
    /// The offset of the next byte the server expects.
    pub off: u64,
    /// Whether the finished upload matched the `sha` sent, when the server says.
    pub matched: Option<bool>,
}

impl UploadReply {
    pub fn from_response(response: &Response) -> Result<Self> {
        let off = response
            .get("off")
            .and_then(as_i64)
            .ok_or_else(|| Error::Upload(format!("no offset in the reply: {:?}", response.body)))?;
        Ok(UploadReply {
            off: u64::try_from(off).map_err(|_| Error::Upload(format!("negative offset {off}")))?,
            matched: response.get("match").and_then(|v| v.as_bool()),
        })
    }
}

/// One entry of an image state read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageState {
    pub image: Option<u32>,
    pub slot: u32,
    pub version: String,
    pub hash: Option<Vec<u8>>,
    pub bootable: bool,
    pub pending: bool,
    pub confirmed: bool,
    pub active: bool,
    pub permanent: bool,
}

impl ImageState {
    pub fn list_from(response: &Response) -> Result<Vec<Self>> {
        let Some(Value::Array(images)) = response.get("images") else {
            return Err(Error::Malformed(format!("no `images` array: {:?}", response.body)));
        };
        images
            .iter()
            .map(|entry| {
                let flag = |key| map_get(entry, key).and_then(|v| v.as_bool()).unwrap_or(false);
                Ok(ImageState {
                    image: map_get(entry, "image").and_then(as_i64).and_then(|i| u32::try_from(i).ok()),
                    slot: map_get(entry, "slot")
                        .and_then(as_i64)
                        .and_then(|s| u32::try_from(s).ok())
                        .ok_or_else(|| Error::Malformed(format!("image entry without a slot: {entry:?}")))?,
                    version: map_get(entry, "version")
                        .and_then(|v| v.as_text())
                        .unwrap_or_default()
                        .to_string(),
                    hash: map_get(entry, "hash").and_then(|v| v.as_bytes()).cloned(),
                    bootable: flag("bootable"),
                    pending: flag("pending"),
                    confirmed: flag("confirmed"),
                    active: flag("active"),
                    permanent: flag("permanent"),
                })
            })
            .collect()
    }
}

pub(crate) fn map_get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    match map {
        Value::Map(entries) => entries.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v),
        _ => None,
    }
}

pub(crate) fn as_i64(value: &Value) -> Option<i64> {
    value.as_integer().and_then(|i| i64::try_from(i).ok())
}
