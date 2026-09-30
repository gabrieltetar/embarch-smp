//! SMP (Simple Management Protocol) over the serial transport, ported from
//! the Python `smp` and `smpclient` packages. See `NOTICE`.
//!
//! **This crate never opens a port** (embarch-smp decision 2): every call
//! takes a `std::io::Read + Write` the caller already opened.
//!
//! ```no_run
//! # fn port() -> std::fs::File { unimplemented!() }
//! use embarch_smp::{Client, Fragmentation, UploadOptions};
//!
//! let image = std::fs::read("zephyr.signed.bin")?;
//! let mut client = Client::new(port()).with_fragmentation(Fragmentation::buffer_size(1024))?;
//! client.upload(&image, &UploadOptions::default(), |off| eprintln!("{off}/{}", image.len()))?;
//! client.reset()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod fragmentation;
pub mod header;
pub mod image;
pub mod message;
pub mod packet;
#[cfg(feature = "sim")]
pub mod sim;

pub use client::{Client, UploadOptions, UploadSummary};
pub use error::{Error, Result, SmpError};
pub use fragmentation::Fragmentation;
pub use image::{ImageError, ImageInfo};
pub use message::{ImageState, Request, Response};
