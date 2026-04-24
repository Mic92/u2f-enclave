//! CTAPHID framing (CTAP spec §11.2).
//!
//! The transport is a stream of fixed-size HID reports. A logical message is
//! split into one INIT packet followed by 0..=127 CONT packets. This module
//! only deals with the wire format; reassembly state lives in
//! [`crate::authenticator`].

use alloc::vec::Vec;

pub const HID_REPORT_SIZE: usize = 64;
pub type Report = [u8; HID_REPORT_SIZE];

pub const INIT_DATA_SIZE: usize = HID_REPORT_SIZE - 7;
pub const CONT_DATA_SIZE: usize = HID_REPORT_SIZE - 5;
/// 7609 bytes — hard upper bound from the CTAPHID framing.
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA_SIZE + 128 * CONT_DATA_SIZE;

pub const CID_BROADCAST: u32 = 0xFFFF_FFFF;

// Commands (bit 7 of byte 4 is the INIT/CONT discriminator and is masked off).
pub const CTAPHID_PING: u8 = 0x01;
pub const CTAPHID_MSG: u8 = 0x03;
pub const CTAPHID_INIT: u8 = 0x06;
pub const CTAPHID_WINK: u8 = 0x08;
pub const CTAPHID_CBOR: u8 = 0x10;
pub const CTAPHID_CANCEL: u8 = 0x11;
pub const CTAPHID_ERROR: u8 = 0x3F;

// Capability bits advertised in the INIT response.
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;

// CTAPHID_ERROR codes.
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;

/// Split `payload` into CTAPHID packets for `cid`/`cmd`.
pub fn fragment(cid: u32, cmd: u8, payload: &[u8]) -> Vec<Report> {
    debug_assert!(payload.len() <= MAX_MESSAGE_SIZE);
    let mut out = Vec::new();

    let mut r = [0u8; HID_REPORT_SIZE];
    r[0..4].copy_from_slice(&cid.to_be_bytes());
    r[4] = 0x80 | cmd;
    r[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let n = payload.len().min(INIT_DATA_SIZE);
    r[7..7 + n].copy_from_slice(&payload[..n]);
    out.push(r);

    let mut off = n;
    let mut seq = 0u8;
    while off < payload.len() {
        let mut r = [0u8; HID_REPORT_SIZE];
        r[0..4].copy_from_slice(&cid.to_be_bytes());
        r[4] = seq;
        let n = (payload.len() - off).min(CONT_DATA_SIZE);
        r[5..5 + n].copy_from_slice(&payload[off..off + n]);
        out.push(r);
        off += n;
        seq = seq.wrapping_add(1);
    }
    out
}

pub fn error(cid: u32, code: u8) -> Vec<Report> {
    fragment(cid, CTAPHID_ERROR, &[code])
}
