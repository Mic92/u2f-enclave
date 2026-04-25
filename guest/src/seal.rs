//! AES-256-GCM seal/open of the random master with the measurement-bound
//! PSP key as KEK, and the one-report-each-way vsock prelude that
//! loads/stores it.  60-byte blob fits a 64-byte report so CTAPHID framing
//! is reused.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::platform::fill_rdrand;
use crate::{greq, vsock};

const LEN: usize = 60; // nonce[12] ‖ ct[32] ‖ tag[16]

// Prelude reply byte 0; mirrored in `host/src/state.rs`.
const ST_FRESH: u8 = 0;
const ST_UNSEALED: u8 = 1;
const ST_UNSEAL_FAILED: u8 = 2;

/// Host sends `[flag, 0,0,0, sealed[60]]`; guest replies `[status, 0,0,0,
/// sealed'[60]]`.  Tag failure means the binary changed.
pub fn prelude(vs: &mut vsock::Vsock) -> [u8; 32] {
    let Some(kek) = greq::derived_key() else {
        crate::serial::print("u2f-enclave: MSG_KEY_REQ failed\n");
        crate::debug_exit(0x32);
    };
    let mut buf = [0u8; 64];
    vs.read_report(&mut buf);
    let (master, st) = if buf[0] == 1 {
        match open(&kek, buf[4..64].try_into().unwrap()) {
            Some(m) => (m, ST_UNSEALED),
            None => (rand32(), ST_UNSEAL_FAILED),
        }
    } else {
        (rand32(), ST_FRESH)
    };
    let mut out = [0u8; 64];
    out[0] = st;
    out[4..64].copy_from_slice(&seal(&kek, &master));
    vs.write_report(&out);
    crate::serial::print(match st {
        ST_UNSEALED => "u2f-enclave: master key unsealed\n",
        ST_FRESH => "u2f-enclave: fresh master key\n",
        _ => "u2f-enclave: unseal FAILED (binary changed?); fresh master key\n",
    });
    master
}

fn rand32() -> [u8; 32] {
    let mut m = [0u8; 32];
    fill_rdrand(&mut m);
    m
}

fn seal(kek: &[u8; 32], master: &[u8; 32]) -> [u8; LEN] {
    let mut nonce = [0u8; 12];
    fill_rdrand(&mut nonce);
    let mut ct = *master;
    let tag = Aes256Gcm::new(kek.into())
        .encrypt_in_place_detached((&nonce).into(), b"", &mut ct)
        .expect("aes-gcm");
    let mut out = [0u8; LEN];
    out[..12].copy_from_slice(&nonce);
    out[12..44].copy_from_slice(&ct);
    out[44..60].copy_from_slice(&tag);
    out
}

fn open(kek: &[u8; 32], blob: &[u8; LEN]) -> Option<[u8; 32]> {
    let nonce: [u8; 12] = blob[..12].try_into().unwrap();
    let mut buf: [u8; 32] = blob[12..44].try_into().unwrap();
    let tag: [u8; 16] = blob[44..60].try_into().unwrap();
    Aes256Gcm::new(kek.into())
        .decrypt_in_place_detached((&nonce).into(), b"", &mut buf, (&tag).into())
        .ok()?;
    Some(buf)
}
