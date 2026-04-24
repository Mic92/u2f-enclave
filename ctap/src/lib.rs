//! Platform-agnostic FIDO2 authenticator core.
//!
//! The crate is `no_std` + `alloc` so the exact same code runs in the
//! SEV-SNP unikernel and in the host simulator. All I/O is done by the
//! embedder: feed 64-byte HID reports in via
//! [`Authenticator::process_report`] and ship the returned reports out on
//! whatever transport (vsock, unix socket, USB) is available.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod authenticator;
pub mod cbor;
pub mod ctap2;
pub mod hid;

pub use authenticator::{Authenticator, Platform};
pub use hid::{Report, HID_REPORT_SIZE};

/// Project AAGUID (randomly generated, identifies this authenticator model).
/// Regenerate before any real deployment.
pub const AAGUID: [u8; 16] = [
    0x9d, 0x39, 0xb9, 0x6a, 0x7c, 0x0e, 0x4f, 0xd1, 0xa3, 0xe8, 0x55, 0x02, 0x1b, 0x6c, 0xfa, 0x11,
];
