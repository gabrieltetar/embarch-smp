# embarch-smp

A Rust client for the Simple Management Protocol (SMP) — the protocol mcumgr and MCUboot speak — ported from [smpclient](https://github.com/intercreate/smpclient) and [smp](https://github.com/JPHutchins/smp).

Part of the [EmbArch](https://github.com/gabrieltetar/embarch-doc) suite, where it lets Core upload a signed firmware image to a device's MCUboot serial-recovery bootloader over USB CDC ACM.

- **Serial transport only**: the line-oriented, base64, CRC16-checked framing.
- **Four commands**: echo, reset, image state, image upload.
- **Never opens a port**: every call takes a `std::io::Read + Write` the caller opened.
- **Blocking**, no async runtime.

Design and status: [embarch-doc/embarch-smp](https://github.com/gabrieltetar/embarch-doc/tree/main/embarch-smp).

## License

Apache-2.0, as the works it is ported from. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
