//! Inspecting an MCUboot image before it is sent anywhere.
//!
//! Ported from `smpclient.mcuboot` (smpclient 7.3.0, Apache-2.0, Intercreate,
//! Inc.). Specification: <https://docs.mcuboot.com/design.html>.
//!
//! The point, for a caller, is to refuse an unsigned `zephyr.bin` *before* a
//! serial-recovery upload erases the running application to make room for it.

use std::fmt;

pub const IMAGE_MAGIC: u32 = 0x96f3_b83d;
pub const IMAGE_HEADER_SIZE: usize = 32;
pub const TLV_INFO_MAGIC: u16 = 0x6907;
pub const TLV_PROT_INFO_MAGIC: u16 = 0x6908;

/// TLV types this crate names. Anything else is still parsed and kept.
pub mod tlv {
    pub const KEYHASH: u16 = 0x01;
    pub const PUBKEY: u16 = 0x02;
    pub const SHA256: u16 = 0x10;
    pub const SHA384: u16 = 0x11;
    pub const SHA512: u16 = 0x12;
    pub const RSA2048_PSS: u16 = 0x20;
    pub const ECDSA_SIG: u16 = 0x22;
    pub const RSA3072_PSS: u16 = 0x23;
    pub const ED25519: u16 = 0x24;
    pub const SIG_PURE: u16 = 0x25;
    pub const SEC_CNT: u16 = 0x50;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageError(pub String);

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not an MCUboot image: {}", self.0)
    }
}

impl std::error::Error for ImageError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageVersion {
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub build_num: u32,
}

impl fmt::Display for ImageVersion {
    /// The reference's rendering: `1.2.3-build4`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}-build{}", self.major, self.minor, self.revision, self.build_num)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageHeader {
    pub load_addr: u32,
    pub hdr_size: u16,
    pub protect_tlv_size: u16,
    pub img_size: u32,
    pub flags: u32,
    pub version: ImageVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub kind: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub header: ImageHeader,
    pub protected_tlvs: Vec<Tlv>,
    pub tlvs: Vec<Tlv>,
    /// Header, body and both TLV areas: the bytes MCUboot reads. A file longer
    /// than this carries padding (`imgtool --pad`) or trailing data.
    pub total_len: usize,
}

impl ImageInfo {
    pub fn parse(bytes: &[u8]) -> Result<Self, ImageError> {
        let at = |offset: usize, len: usize| -> Result<&[u8], ImageError> {
            bytes.get(offset..offset + len).ok_or_else(|| {
                ImageError(format!("{} bytes, needs at least {}", bytes.len(), offset + len))
            })
        };
        let h = at(0, IMAGE_HEADER_SIZE)?;
        let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let u32_at = |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);

        let magic = u32_at(h, 0);
        if magic != IMAGE_MAGIC {
            return Err(ImageError(format!("magic is {magic:#010x}, expected {IMAGE_MAGIC:#010x}")));
        }
        let header = ImageHeader {
            load_addr: u32_at(h, 4),
            hdr_size: u16_at(h, 8),
            protect_tlv_size: u16_at(h, 10),
            img_size: u32_at(h, 12),
            flags: u32_at(h, 16),
            version: ImageVersion {
                major: h[20],
                minor: h[21],
                revision: u16_at(h, 22),
                build_num: u32_at(h, 24),
            },
        };
        if usize::from(header.hdr_size) < IMAGE_HEADER_SIZE {
            return Err(ImageError(format!("header size {} is below {IMAGE_HEADER_SIZE}", header.hdr_size)));
        }

        // Protected TLVs, when there are any, come first.
        let mut offset = usize::from(header.hdr_size) + header.img_size as usize;
        let mut protected_tlvs = Vec::new();
        if header.protect_tlv_size > 0 {
            let (tlvs, tot) = read_tlv_area(&at, offset, TLV_PROT_INFO_MAGIC)?;
            if tot != usize::from(header.protect_tlv_size) {
                return Err(ImageError(format!(
                    "protected TLV area is {tot} bytes, header says {}",
                    header.protect_tlv_size
                )));
            }
            protected_tlvs = tlvs;
            offset += tot;
        }
        let (tlvs, tot) = read_tlv_area(&at, offset, TLV_INFO_MAGIC)?;
        Ok(ImageInfo { header, protected_tlvs, tlvs, total_len: offset + tot })
    }

    /// The first TLV of `kind`, protected area included.
    pub fn tlv(&self, kind: u16) -> Option<&Tlv> {
        self.protected_tlvs.iter().chain(&self.tlvs).find(|t| t.kind == kind)
    }

    /// Whether the image carries a hash MCUboot can validate against.
    pub fn has_hash(&self) -> bool {
        [tlv::SHA256, tlv::SHA384, tlv::SHA512].iter().any(|&k| self.tlv(k).is_some())
    }

    /// Whether the image carries a signature. An unsigned-but-hashed image
    /// boots only on an MCUboot built without signature checking, which this
    /// crate cannot see from here.
    pub fn has_signature(&self) -> bool {
        [tlv::RSA2048_PSS, tlv::ECDSA_SIG, tlv::RSA3072_PSS, tlv::ED25519, tlv::SIG_PURE]
            .iter()
            .any(|&k| self.tlv(k).is_some())
    }
}

type At<'a> = dyn Fn(usize, usize) -> Result<&'a [u8], ImageError> + 'a;

/// One TLV area — its 4-byte info header, then entries — and its total size.
fn read_tlv_area<'a>(at: &At<'a>, offset: usize, magic: u16) -> Result<(Vec<Tlv>, usize), ImageError> {
    let info = at(offset, 4)?;
    let found = u16::from_le_bytes([info[0], info[1]]);
    if found != magic {
        return Err(ImageError(format!("TLV info magic at {offset:#x} is {found:#06x}, expected {magic:#06x}")));
    }
    let tot = usize::from(u16::from_le_bytes([info[2], info[3]]));
    let mut tlvs = Vec::new();
    let mut cursor = offset + 4;
    while cursor < offset + tot {
        let entry = at(cursor, 4)?;
        // `struct image_tlv { uint16_t it_type; uint16_t it_len; }`. The
        // reference reads a byte and skips one, which agrees below 0x100.
        let kind = u16::from_le_bytes([entry[0], entry[1]]);
        let len = usize::from(u16::from_le_bytes([entry[2], entry[3]]));
        tlvs.push(Tlv { kind, value: at(cursor + 4, len)?.to_vec() });
        cursor += 4 + len;
    }
    if cursor != offset + tot {
        return Err(ImageError(format!("TLV entries overrun their area by {} bytes", cursor - (offset + tot))));
    }
    Ok((tlvs, tot))
}
