//! Byte-for-byte agreement with the Python reference (decision 5).
//!
//! `tests/fixtures/reference.json` is produced by `tools/gen_fixtures.py`
//! from the pinned `smp` and `smpclient` releases it names.

use embarch_smp::header::Version;
use embarch_smp::image::ImageInfo;
use embarch_smp::message::{ImageState, Request, Response, UploadReply, UploadStart};
use embarch_smp::packet::{self, crc16_xmodem, Decoder};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Fixtures {
    reference: serde_json::Value,
    crc16_xmodem: Vec<CrcCase>,
    packets: Vec<PacketCase>,
    requests: Vec<BytesCase>,
    responses: Vec<BytesCase>,
    // Driven through the simulator, so read only under `--features sim`.
    #[cfg_attr(not(feature = "sim"), allow(dead_code))]
    uploads: Vec<UploadCase>,
    images: Vec<ImageCase>,
}

#[derive(Deserialize)]
struct CrcCase {
    data: String,
    crc: u16,
}

#[derive(Deserialize)]
struct PacketCase {
    message: String,
    line_length: usize,
    packets: Vec<String>,
}

#[derive(Deserialize)]
struct BytesCase {
    name: String,
    bytes: String,
    #[serde(default)]
    sequence: Option<u8>,
}

#[derive(Deserialize)]
pub struct UploadCase {
    pub strategy: String,
    pub max_unencoded_size: usize,
    pub line_length: usize,
    pub image_len: usize,
    pub use_sha: bool,
    pub upgrade: bool,
    pub first_sequence: u8,
    pub requests: Vec<String>,
}

#[derive(Deserialize)]
struct ImageCase {
    name: String,
    bytes: String,
    load_addr: u32,
    hdr_size: u16,
    protect_tlv_size: u16,
    img_size: u32,
    flags: u32,
    version: (u8, u8, u16, u32),
    version_str: String,
    tlvs: Vec<(u16, String)>,
    protected_tlvs: Vec<(u16, String)>,
}

fn fixtures() -> Fixtures {
    serde_json::from_str(include_str!("fixtures/reference.json")).expect("fixtures parse")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("fixture hex")
}

/// The generator's deterministic payload.
pub fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + seed) % 256) as u8).collect()
}

#[test]
fn fixtures_name_the_pinned_reference() {
    let f = fixtures();
    assert_eq!(f.reference["smp"], "4.2.0");
    assert_eq!(f.reference["smpclient"], "7.3.0");
}

#[test]
fn crc16_matches() {
    for case in fixtures().crc16_xmodem {
        assert_eq!(crc16_xmodem(&unhex(&case.data)), case.crc, "data {}", case.data);
    }
}

#[test]
fn packets_encode_and_decode_identically() {
    let cases = fixtures().packets;
    assert!(cases.len() >= 30);
    for case in cases {
        let message = unhex(&case.message);
        let expected: Vec<Vec<u8>> = case.packets.iter().map(|p| unhex(p)).collect();
        let got = packet::encode(&message, case.line_length).unwrap();
        assert_eq!(got, expected, "encode {} bytes at line length {}", message.len(), case.line_length);

        let mut decoder = Decoder::new();
        let mut decoded = None;
        for (i, p) in expected.iter().enumerate() {
            let out = decoder.push(p).unwrap();
            assert_eq!(out.is_some(), i == expected.len() - 1);
            decoded = out.or(decoded);
        }
        assert_eq!(decoded.unwrap(), message);
    }
}

#[test]
fn requests_encode_identically() {
    for case in fixtures().requests {
        let request = match case.name.as_str() {
            "echo" => Request::echo("Hello, World!"),
            "echo_v1" => Request::echo("hi").with_version(Version::V1),
            "reset" => Request::reset(false),
            "reset_force" => Request::reset(true),
            "image_state_read" => Request::image_state_read(),
            "upload_first" => Request::image_upload(
                0,
                &pattern(64, 3),
                Some(&UploadStart {
                    image: 0,
                    len: 5000,
                    sha: Some(Sha256::digest(b"x").to_vec()),
                    upgrade: Some(false),
                }),
            ),
            "upload_next" => Request::image_upload(64, &pattern(64, 9), None),
            "upload_big_offset" => Request::image_upload(70000, &pattern(300, 3), None),
            other => panic!("fixture request {other} has no Rust counterpart"),
        };
        let got = request.encode(case.sequence.unwrap()).unwrap();
        assert_eq!(hex::encode(got), case.bytes, "request {}", case.name);
    }
}

#[test]
fn responses_parse_to_what_they_mean() {
    for case in fixtures().responses {
        let r = Response::parse(&unhex(&case.bytes)).unwrap();
        let name = case.name.as_str();
        match name {
            "echo_ok" => {
                assert_eq!(r.error(), None);
                assert_eq!(r.get("r").and_then(|v| v.as_text()), Some("Hello, World!"));
                assert_eq!(r.header.sequence, 7);
            }
            "upload_ok" => assert_eq!(UploadReply::from_response(&r).unwrap(), UploadReply { off: 1024, matched: None }),
            "upload_done_match" => assert_eq!(UploadReply::from_response(&r).unwrap().matched, Some(true)),
            "upload_done_mismatch" => assert_eq!(UploadReply::from_response(&r).unwrap().matched, Some(false)),
            "error_v1" => {
                let e = r.error().unwrap();
                assert_eq!((e.rc, e.group, e.reason.as_deref()), (3, None, Some("bad")));
                assert_eq!(e.to_string(), "rc 3 (EINVAL): bad");
            }
            "error_v2" => {
                let e = r.error().unwrap();
                assert_eq!((e.rc, e.group), (14, Some(1)));
            }
            "mcuboot_upload_ok" => {
                assert_eq!(r.header.version, Version::V1);
                assert_eq!(r.error(), None);
                assert_eq!(UploadReply::from_response(&r).unwrap().off, 2048);
            }
            "mcuboot_rc_only_ok" => assert_eq!(r.error(), None),
            "mcuboot_rc_enotsup" => assert_eq!(r.error().unwrap().mgmt_name(), Some("ENOTSUP")),
            "image_states" => {
                let states = ImageState::list_from(&r).unwrap();
                assert_eq!(states.len(), 2);
                assert_eq!(states[0].version, "1.2.3");
                assert_eq!(states[0].image, Some(0));
                assert_eq!(states[0].hash.as_deref(), Some(&(0u8..32).collect::<Vec<_>>()[..]));
                assert!(states[0].bootable && states[0].active && states[0].confirmed);
                assert!(!states[0].pending);
                assert_eq!((states[1].slot, states[1].version.as_str(), states[1].pending), (1, "1.2.4.5", true));
            }
            "image_states_empty" => assert!(ImageState::list_from(&r).unwrap().is_empty()),
            other => panic!("fixture response {other} is not asserted on"),
        }
    }
}

#[test]
fn images_parse_like_the_reference() {
    for case in fixtures().images {
        let bytes = unhex(&case.bytes);
        let info = ImageInfo::parse(&bytes).unwrap();
        let h = info.header;
        assert_eq!(
            (h.load_addr, h.hdr_size, h.protect_tlv_size, h.img_size, h.flags),
            (case.load_addr, case.hdr_size, case.protect_tlv_size, case.img_size, case.flags),
            "image {}",
            case.name
        );
        assert_eq!((h.version.major, h.version.minor, h.version.revision, h.version.build_num), case.version);
        assert_eq!(h.version.to_string(), case.version_str);
        let tlvs = |t: &[embarch_smp::image::Tlv]| t.iter().map(|t| (t.kind, hex::encode(&t.value))).collect::<Vec<_>>();
        assert_eq!(tlvs(&info.tlvs), case.tlvs);
        assert_eq!(tlvs(&info.protected_tlvs), case.protected_tlvs);
        assert_eq!(info.total_len, bytes.len());
        assert!(info.has_hash() && info.has_signature());
    }
}

#[test]
fn a_file_that_is_not_an_image_is_named_as_such() {
    let err = ImageInfo::parse(&[0u8; 64]).unwrap_err();
    assert!(err.to_string().contains("magic"), "{err}");
    let mut truncated = unhex(&fixtures().images[0].bytes);
    truncated.truncate(truncated.len() - 10);
    assert!(ImageInfo::parse(&truncated).is_err());
}

#[cfg(feature = "sim")]
mod through_the_client {
    use super::*;
    use embarch_smp::packet::LineSplitter;
    use embarch_smp::sim::{SimBootloader, SimConfig};
    use embarch_smp::{Client, Fragmentation, UploadOptions};
    use std::io::{Read, Write};

    /// A simulator that keeps a copy of every byte the client wrote.
    struct Recorder {
        sim: SimBootloader,
        written: Vec<u8>,
    }

    impl Read for Recorder {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.sim.read(buf)
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            self.sim.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn messages(wire: &[u8]) -> Vec<String> {
        let mut splitter = LineSplitter::new();
        splitter.feed(wire);
        let mut decoder = Decoder::new();
        let mut out = Vec::new();
        while let Some(line) = splitter.pop_packet() {
            if let Some(message) = decoder.push(&line).unwrap() {
                out.push(hex::encode(message));
            }
        }
        out
    }

    fn fragmentation(case: &UploadCase) -> Fragmentation {
        match case.strategy.as_str() {
            "buffer_params_128x2" => Fragmentation::BufferParams { line_length: 128, line_buffers: 2 },
            "buffer_size_1024" => Fragmentation::buffer_size(1024),
            "buffer_size_512_line_64" => Fragmentation::BufferSize { buf_size: 512, line_length: 64 },
            other => panic!("strategy {other}"),
        }
    }

    /// Every chunk `Client::upload` sends is the chunk smpclient would send,
    /// when the server acknowledges each one in full.
    #[test]
    fn uploads_send_the_reference_requests() {
        let cases = super::fixtures().uploads;
        assert_eq!(cases.len(), 18);
        for case in cases {
            let frag = fragmentation(&case);
            assert_eq!(frag.max_unencoded_size(), case.max_unencoded_size, "{}", case.strategy);
            assert_eq!(frag.line_length(), case.line_length);

            let sim = SimBootloader::new(SimConfig { write_align: 1, ..SimConfig::default() });
            let mut client = Client::new(Recorder { sim, written: Vec::new() })
                .with_fragmentation(frag)
                .unwrap()
                .with_sequence(case.first_sequence);
            let image = pattern(case.image_len, 3);
            let options = UploadOptions { use_sha: case.use_sha, upgrade: case.upgrade, ..UploadOptions::default() };
            let summary = client.upload(&image, &options, |_| {}).unwrap();
            assert_eq!(summary.requests, case.requests.len());

            let recorder = client.into_inner();
            assert_eq!(recorder.sim.image(), &image[..]);
            assert_eq!(
                messages(&recorder.written),
                case.requests,
                "{} image_len {} sha {} upgrade {}",
                case.strategy,
                case.image_len,
                case.use_sha,
                case.upgrade
            );
        }
    }
}
