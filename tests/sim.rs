//! The client against the simulated serial-recovery bootloader, and against
//! scripted servers for the cases the simulator does not produce.

#![cfg(feature = "sim")]

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::time::Duration;

use ciborium::Value;
use embarch_smp::header::{Header, Version};
use embarch_smp::packet::{self, Decoder, LineSplitter};
use embarch_smp::sim::{SimBootloader, SimConfig};
use embarch_smp::{Client, Error, Fragmentation, UploadOptions};

const SHORT: Duration = Duration::from_millis(60);

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 13 + 5) % 251) as u8).collect()
}

fn quick() -> UploadOptions {
    UploadOptions { first_timeout: SHORT, timeout: SHORT, ..UploadOptions::default() }
}

#[test]
fn upload_lands_whole_through_flash_alignment() {
    for frag in [Fragmentation::default(), Fragmentation::buffer_size(1024), Fragmentation::buffer_size(512)] {
        let image = pattern(40_000 + 3);
        let mut client = Client::new(SimBootloader::new(SimConfig::default())).with_fragmentation(frag).unwrap();
        let mut offsets = Vec::new();
        let summary = client.upload(&image, &quick(), |off| offsets.push(off)).unwrap();
        let sim = client.into_inner();
        assert_eq!(sim.image(), &image[..], "{frag:?}");
        assert_eq!(*offsets.last().unwrap(), image.len() as u64);
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "offsets only move forward");
        // Every offset the server returned before the last is write-aligned.
        assert!(offsets[..offsets.len() - 1].iter().all(|o| o % 8 == 0));
        assert_eq!(summary.requests, offsets.len());
        assert!(sim.seen().iter().all(|s| s.frame_len <= frag.max_unencoded_size() + 4));
    }
}

#[test]
fn a_bigger_buffer_means_fewer_round_trips() {
    let image = pattern(20_000);
    let count = |frag| {
        let mut c = Client::new(SimBootloader::new(SimConfig::default())).with_fragmentation(frag).unwrap();
        c.upload(&image, &quick(), |_| {}).unwrap().requests
    };
    let (small, large) = (count(Fragmentation::default()), count(Fragmentation::buffer_size(1024)));
    assert!(large * 5 < small, "1024-byte buffer: {large} requests, default: {small}");
}

#[test]
fn a_buffer_declared_larger_than_the_bootloader_has_times_out() {
    // The engineer declared 2048; the bootloader was built with 1024.
    let sim = SimBootloader::new(SimConfig { buf_size: 1024, ..SimConfig::default() });
    let mut client = Client::new(sim).with_fragmentation(Fragmentation::buffer_size(2048)).unwrap();
    let err = client.upload(&pattern(5000), &quick(), |_| {}).unwrap_err();
    assert!(matches!(err, Error::Timeout { what: "image upload", .. }), "{err}");
    let seen = client.get_ref().seen();
    assert!(seen[0].frame_len > 1024 && !seen[0].replied);
}

#[test]
fn console_bytes_are_kept_apart_from_replies() {
    let sim = SimBootloader::new(SimConfig { banner: b"*** Booting MCUboot ***\r\n".to_vec(), ..SimConfig::default() });
    let mut client = Client::new(sim);
    assert_eq!(client.echo("ping").unwrap(), "ping");
    assert_eq!(client.take_serial_bytes(), b"*** Booting MCUboot ***\r\n");
}

#[test]
fn a_lost_reply_is_a_timeout_and_the_next_request_still_works() {
    let mut client = Client::new(SimBootloader::new(SimConfig::default()));
    client.timeout = SHORT;
    client.get_mut().drop_next_replies(1);
    assert!(matches!(client.echo("one"), Err(Error::Timeout { what: "echo", .. })));
    assert_eq!(client.echo("two").unwrap(), "two");
}

#[test]
fn a_command_the_bootloader_was_built_without_is_an_smp_error() {
    let mut client = Client::new(SimBootloader::new(SimConfig { echo: false, image_state: false, ..SimConfig::default() }));
    for err in [client.echo("x").unwrap_err(), client.image_states().unwrap_err()] {
        let Error::Smp(e) = err else { panic!("{err}") };
        assert_eq!(e.mgmt_name(), Some("ENOTSUP"));
    }
}

#[test]
fn reset_is_acknowledged_and_counted() {
    let mut client = Client::new(SimBootloader::new(SimConfig::default()));
    client.reset().unwrap();
    assert_eq!(client.get_ref().resets(), 1);
}

#[test]
fn v1_headers_are_echoed_back_as_v1() {
    let mut client = Client::new(SimBootloader::new(SimConfig::default())).with_version(Version::V1);
    assert_eq!(client.echo("v1").unwrap(), "v1");
}

#[test]
fn image_state_reads_the_uploaded_image() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!("fixtures/reference.json")).unwrap();
    let image = hex::decode(fixtures["images"][0]["bytes"].as_str().unwrap()).unwrap();
    let mut client = Client::new(SimBootloader::new(SimConfig::default()));
    assert!(client.image_states().unwrap().is_empty());
    client.upload(&image, &quick(), |_| {}).unwrap();
    let states = client.image_states().unwrap();
    assert_eq!((states[0].slot, states[0].version.as_str()), (0, "1.2.3.4"));
}

#[test]
fn an_image_larger_than_the_slot_is_refused_by_the_bootloader() {
    let mut client = Client::new(SimBootloader::new(SimConfig { slot_size: 1000, ..SimConfig::default() }));
    let Err(Error::Smp(e)) = client.upload(&pattern(1001), &quick(), |_| {}) else { panic!() };
    assert_eq!(e.mgmt_name(), Some("EINVAL"));
}

/// A server whose replies a test writes: each request's decoded header and
/// body go to `reply`, which returns the frames to send back, in order.
struct Scripted<F> {
    splitter: LineSplitter,
    decoder: Decoder,
    out: VecDeque<u8>,
    reply: F,
}

impl<F: FnMut(&Header, &Value) -> Vec<(u8, Vec<(&'static str, Value)>)>> Scripted<F> {
    fn new(reply: F) -> Self {
        Scripted { splitter: LineSplitter::new(), decoder: Decoder::new(), out: VecDeque::new(), reply }
    }
}

impl<F> Read for Scripted<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.out.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.out.len());
        for (slot, byte) in buf.iter_mut().zip(self.out.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

impl<F: FnMut(&Header, &Value) -> Vec<(u8, Vec<(&'static str, Value)>)>> Write for Scripted<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.splitter.feed(buf);
        while let Some(line) = self.splitter.pop_packet() {
            let Some(message) = self.decoder.push(&line).unwrap() else { continue };
            let header = Header::parse(&message).unwrap();
            let body: Value = ciborium::from_reader(&message[8..]).unwrap();
            for (sequence, entries) in (self.reply)(&header, &body) {
                let map = Value::Map(entries.into_iter().map(|(k, v)| (Value::Text(k.into()), v)).collect());
                let mut cbor = Vec::new();
                ciborium::into_writer(&map, &mut cbor).unwrap();
                let reply = Header { op: header.op.response(), length: cbor.len() as u16, sequence, ..header };
                let mut bytes = reply.to_bytes().to_vec();
                bytes.extend_from_slice(&cbor);
                for p in packet::encode(&bytes, 128).unwrap() {
                    self.out.extend(p);
                }
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn off(n: u64) -> Vec<(&'static str, Value)> {
    vec![("rc", Value::Integer(0.into())), ("off", Value::Integer(n.into()))]
}

#[test]
fn a_late_reply_to_an_earlier_request_is_skipped() {
    let port = Scripted::new(|h: &Header, body: &Value| {
        let d = body.as_map().unwrap()[0].1.clone();
        // A stale answer under the previous sequence number, then the real one.
        vec![(h.sequence.wrapping_sub(1), vec![("r", Value::Text("stale".into()))]), (h.sequence, vec![("r", d)])]
    });
    let mut client = Client::new(port).with_sequence(5);
    assert_eq!(client.echo("fresh").unwrap(), "fresh");
    assert_eq!(client.stale_frames(), 1);
}

#[test]
fn an_offset_that_never_moves_abandons_the_upload() {
    let port = Scripted::new(|h: &Header, _: &Value| vec![(h.sequence, off(16))]);
    let mut client = Client::new(port);
    let err = client.upload(&pattern(1000), &quick(), |_| {}).unwrap_err();
    assert!(matches!(&err, Error::Upload(m) if m.contains("stuck at 16")), "{err}");
}

#[test]
fn an_offset_past_the_image_is_refused() {
    let port = Scripted::new(|h: &Header, _: &Value| vec![(h.sequence, off(5000))]);
    let err = Client::new(port).upload(&pattern(1000), &quick(), |_| {}).unwrap_err();
    assert!(matches!(&err, Error::Upload(m) if m.contains("past")), "{err}");
}

#[test]
fn a_sha_mismatch_at_the_end_fails_the_upload() {
    let port = Scripted::new(|h: &Header, _: &Value| {
        vec![(h.sequence, vec![("off", Value::Integer(10.into())), ("match", Value::Bool(false))])]
    });
    let err = Client::new(port).upload(&pattern(10), &quick(), |_| {}).unwrap_err();
    assert!(matches!(&err, Error::Upload(m) if m.contains("SHA-256")), "{err}");
}

#[test]
fn a_server_asking_for_offset_zero_again_gets_len_but_not_sha() {
    let mut first = true;
    let mut restart_body = None;
    let port = Scripted::new(move |h: &Header, body: &Value| {
        let keys: Vec<String> =
            body.as_map().unwrap().iter().map(|(k, _)| k.as_text().unwrap().to_string()).collect();
        if first {
            first = false;
            return vec![(h.sequence, off(0))];
        }
        if restart_body.is_none() {
            restart_body = Some(keys.clone());
            assert_eq!(keys, ["len", "off", "data", "image", "upgrade"]);
        }
        vec![(h.sequence, off(20))]
    });
    Client::new(port).upload(&pattern(20), &quick(), |_| {}).unwrap();
}
