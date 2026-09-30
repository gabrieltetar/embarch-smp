//! SMP (Simple Management Protocol) over the serial transport, ported from
//! the Python `smp` and `smpclient` packages. See `NOTICE`.
//!
//! **This crate never opens a port** (embarch-smp decision 2): every call
//! takes a `std::io::Read + Write` the caller already opened.

#![forbid(unsafe_code)]
