"""Generate tests/fixtures/reference.json from the Python reference implementation.

embarch-smp is a port of `smp` and `smpclient`; this script records what the
originals produce so the Rust tests can assert byte-for-byte agreement.
Python is a fixture generator only, never a build or runtime dependency
(embarch-smp decision 5). Regenerate deliberately and review the diff:

    uv run --no-project --with smp==4.2.0 --with 'smpclient[serial]==7.3.0' \
        python tools/gen_fixtures.py > tests/fixtures/reference.json

Everything here is synthetic: no image, key or payload comes from real firmware.
"""

import importlib.metadata
import json
import struct
import sys
import tempfile
from hashlib import sha256

import cbor2
from crcmod.predefined import mkPredefinedCrcFun
from smp import header as smphdr
from smp import image_management as smpimg
from smp import os_management as smpos
from smp import packet as smppacket
from smpclient import SMPClient
from smpclient.mcuboot import ImageInfo
from smpclient.requests.image_management import ImageStatesRead, ImageUploadWrite
from smpclient.requests.os_management import EchoWrite, ResetWrite
from smpclient.transport.serial import BufferParams, BufferSize, SMPSerialTransport

V1 = smphdr.Version.V1
V2 = smphdr.Version.V2


def pattern(n: int, seed: int = 3) -> bytes:
    return bytes((i * 7 + seed) % 256 for i in range(n))


def crc_cases() -> list[dict]:
    crc16 = mkPredefinedCrcFun("xmodem")
    return [{"data": d.hex(), "crc": crc16(d)} for d in (b"", b"123456789", pattern(300))]


def packet_cases() -> list[dict]:
    cases = []
    for message in (b"Hello, world!", b"", b"x", pattern(90), pattern(91), pattern(93), pattern(300), pattern(1020)):
        for line_length in (8, 32, 127, 128):
            packets = list(smppacket.encode(message, line_length=line_length))
            cases.append(
                {"message": message.hex(), "line_length": line_length, "packets": [p.hex() for p in packets]}
            )
    return cases


def request_cases() -> list[dict]:
    def case(name: str, request) -> dict:
        return {
            "name": name,
            "sequence": request.header.sequence,
            "version": int(request.header.version),
            "bytes": request.BYTES.hex(),
        }

    return [
        case("echo", EchoWrite(d="Hello, World!", sequence=7)),
        case("echo_v1", EchoWrite(d="hi", sequence=0, version=V1)),
        case("reset", ResetWrite(sequence=12)),
        case("reset_force", ResetWrite(force=1, sequence=13)),
        case("image_state_read", ImageStatesRead(sequence=200)),
        case(
            "upload_first",
            ImageUploadWrite(
                off=0, data=pattern(64), image=0, len=5000, sha=sha256(b"x").digest(), upgrade=False, sequence=1
            ),
        ),
        case("upload_next", ImageUploadWrite(off=64, data=pattern(64, 9), sequence=2)),
        case("upload_big_offset", ImageUploadWrite(off=70000, data=pattern(300), sequence=254)),
    ]


def response_cases() -> list[dict]:
    def case(name: str, message) -> dict:
        return {"name": name, "bytes": message.BYTES.hex()}

    def hdr(op, group, command, length, sequence=5, version=V2):
        return smphdr.Header(
            op=op, version=version, flags=smphdr.Flag(0), length=length,
            group_id=group, sequence=sequence, command_id=command,
        )

    wr = smphdr.OP.WRITE_RSP
    rr = smphdr.OP.READ_RSP
    os_g = smphdr.GroupId.OS_MANAGEMENT
    img_g = smphdr.GroupId.IMAGE_MANAGEMENT
    echo = smphdr.CommandId.OSManagement.ECHO
    reset = smphdr.CommandId.OSManagement.RESET
    upload = smphdr.CommandId.ImageManagement.UPLOAD
    state = smphdr.CommandId.ImageManagement.STATE

    def raw(name, op, group, command, body, sequence=5, version=V2):
        data = cbor2.dumps(body, canonical=True)
        return {"name": name, "bytes": (bytes(hdr(op, group, command, len(data), sequence, version)) + data).hex()}

    return [
        case("echo_ok", smpos.EchoWriteResponse(r="Hello, World!", sequence=7)),
        case("upload_ok", smpimg.ImageUploadWriteResponse(off=1024, sequence=3)),
        case("upload_done_match", smpimg.ImageUploadWriteResponse(off=5000, match=True, sequence=4)),
        case("upload_done_mismatch", smpimg.ImageUploadWriteResponse(off=5000, match=False, sequence=4)),
        raw("error_v1", wr, img_g, upload, {"rc": 3, "rsn": "bad"}),
        raw("error_v2", wr, img_g, upload, {"err": {"group": 1, "rc": 14}}),
        # MCUboot serial recovery's own shapes (boot_serial.c): rc beside off, rc alone.
        raw("mcuboot_upload_ok", wr, img_g, upload, {"rc": 0, "off": 2048}, version=V1),
        raw("mcuboot_rc_only_ok", wr, os_g, reset, {"rc": 0}, version=V1),
        raw("mcuboot_rc_enotsup", wr, os_g, echo, {"rc": 8}, version=V1),
        case(
            "image_states",
            smpimg.ImageStatesReadResponse(
                images=[
                    smpimg.ImageState(
                        slot=0, version="1.2.3", image=0, hash=bytes(range(32)),
                        bootable=True, active=True, confirmed=True,
                    ),
                    smpimg.ImageState(slot=1, version="1.2.4.5", pending=True),
                ],
                sequence=9,
            ),
        ),
        raw("image_states_empty", rr, img_g, state, {"images": []}, version=V1),
    ]


def upload_cases() -> list[dict]:
    """Every request smpclient would send, if the server acknowledged each chunk in full."""
    strategies = {
        "buffer_params_128x2": BufferParams(line_length=128, line_buffers=2),
        "buffer_size_1024": BufferSize(buf_size=1024),
        "buffer_size_512_line_64": BufferSize(buf_size=512, line_length=64),
    }
    cases = []
    for strategy_name, strategy in strategies.items():
        transport = SMPSerialTransport(fragmentation_strategy=strategy)
        client = SMPClient(transport, "unused")
        for image_len in (1, 100, 2500):
            for use_sha, upgrade in ((True, False), (False, True)):
                image = pattern(image_len)
                sequence = 40
                requests = []
                request = client._maximize_upload_packet(
                    ImageUploadWrite(
                        off=0, data=b"", image=0, len=len(image),
                        sha=sha256(image).digest() if use_sha else None, upgrade=upgrade, sequence=sequence,
                    ),
                    image,
                )
                requests.append(request.BYTES.hex())
                off = request.off + len(request.data)
                while off != len(image):
                    sequence = (sequence + 1) % 0xFF
                    request = client._maximize_upload_packet(
                        ImageUploadWrite(off=off, data=b"", sequence=sequence), image
                    )
                    requests.append(request.BYTES.hex())
                    off = request.off + len(request.data)
                cases.append(
                    {
                        "strategy": strategy_name,
                        "max_unencoded_size": transport.max_unencoded_size,
                        "line_length": transport._line_length,
                        "image_len": image_len,
                        "use_sha": use_sha,
                        "upgrade": upgrade,
                        "first_sequence": 40,
                        "requests": requests,
                    }
                )
    return cases


def make_image(body_len: int, protected: bool, version=(1, 2, 3, 4), flags: int = 0) -> bytes:
    """A synthetic MCUboot image: header, body, optional protected TLVs, TLVs."""
    hdr_size = 0x200
    prot = b""
    if protected:
        entries = struct.pack("<HH", 0x50, 4) + struct.pack("<I", 7)  # SEC_CNT
        prot = struct.pack("<HH", 0x6908, 4 + len(entries)) + entries
    header = struct.pack(
        "<LLHHLLBBHL4x", 0x96F3B83D, 0, hdr_size, len(prot), body_len, flags, *version
    )
    image = header + bytes(hdr_size - len(header)) + pattern(body_len, 11)
    digest = sha256(image + prot).digest()
    entries = struct.pack("<HH", 0x10, 32) + digest + struct.pack("<HH", 0x22, 8) + bytes(range(8))
    return image + prot + struct.pack("<HH", 0x6907, 4 + len(entries)) + entries


def image_cases() -> list[dict]:
    cases = []
    for name, image in (
        ("plain", make_image(1000, protected=False)),
        ("protected", make_image(333, protected=True, version=(0, 1, 0, 0), flags=0x10)),
    ):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(image)
            path = f.name
        info = ImageInfo.load_file(path)
        h = info.header
        cases.append(
            {
                "name": name,
                "bytes": image.hex(),
                "load_addr": h.load_addr,
                "hdr_size": h.hdr_size,
                "protect_tlv_size": h.protect_tlv_size,
                "img_size": h.img_size,
                "flags": int(h.flags),
                "version": [h.ver.major, h.ver.minor, h.ver.revision, h.ver.build_num],
                "version_str": str(h.ver),
                "tlvs": [[int(t.header.type), t.value.hex()] for t in info.tlvs],
                "protected_tlvs": [[int(t.header.type), t.value.hex()] for t in (info.protected_tlvs or [])],
            }
        )
    return cases


def main() -> None:
    fixtures = {
        "generated_by": "tools/gen_fixtures.py",
        "reference": {
            "smp": importlib.metadata.version("smp"),
            "smpclient": importlib.metadata.version("smpclient"),
            "cbor2": importlib.metadata.version("cbor2"),
        },
        "crc16_xmodem": crc_cases(),
        "packets": packet_cases(),
        "requests": request_cases(),
        "responses": response_cases(),
        "uploads": upload_cases(),
        "images": image_cases(),
    }
    json.dump(fixtures, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
