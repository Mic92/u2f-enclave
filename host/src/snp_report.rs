//! `no_std` view over an SNP `ATTESTATION_REPORT` plus VCEK signature check.
//! Shared between the host CLI and the guest (via `#[path]`-include) so both
//! parse the same offsets and run the same P-384 verify.
//!
//! Refs: SNP firmware ABI §7.3 Table 22; AMD KDS spec.
#![allow(dead_code)]

use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha384};

pub const REPORT_LEN: usize = 1184;
const SIGNED_LEN: usize = 0x2a0;

/// Borrowed view; signature covers `[0..0x2a0]`.
pub struct Report<'a>(pub &'a [u8; REPORT_LEN]);

impl Report<'_> {
    pub fn guest_svn(&self) -> u32 {
        u32::from_le_bytes(self.0[0x4..0x8].try_into().unwrap())
    }
    pub fn policy(&self) -> u64 {
        u64::from_le_bytes(self.0[0x8..0x10].try_into().unwrap())
    }
    pub fn author_key_en(&self) -> bool {
        self.0[0x48] & 1 != 0
    }
    pub fn report_data(&self) -> &[u8] {
        &self.0[0x50..0x90]
    }
    pub fn measurement(&self) -> &[u8] {
        &self.0[0x90..0xc0]
    }
    pub fn id_key_digest(&self) -> &[u8] {
        &self.0[0xe0..0x110]
    }
    pub fn author_key_digest(&self) -> &[u8] {
        &self.0[0x110..0x140]
    }
    pub fn reported_tcb(&self) -> u64 {
        u64::from_le_bytes(self.0[0x180..0x188].try_into().unwrap())
    }
    pub fn chip_id(&self) -> &[u8] {
        &self.0[0x1a0..0x1e0]
    }
    /// `r‖s` big-endian. On-wire format is 72-byte LE-padded per component.
    fn sig_be(&self) -> [u8; 96] {
        let mut rs = [0u8; 96];
        for (h, w) in [(0, SIGNED_LEN), (48, SIGNED_LEN + 72)] {
            rs[h..h + 48].copy_from_slice(&self.0[w..w + 48]);
            rs[h..h + 48].reverse();
        }
        rs
    }
}

/// Verify the report's ECDSA P-384 signature against a SEC1-encoded VCEK
/// public key.  No certificate chain — callers establish trust in `vcek`
/// separately (HTTPS-from-AMD on the host CLI; same-chip self-check in the
/// guest).
pub fn verify_sig(r: &Report<'_>, vcek: &[u8; 97]) -> Result<(), &'static str> {
    let vk = VerifyingKey::from_sec1_bytes(vcek).map_err(|_| "VCEK key not on curve")?;
    let sig = Signature::from_slice(&r.sig_be()).map_err(|_| "report signature malformed")?;
    vk.verify_prehash(&Sha384::digest(&r.0[..SIGNED_LEN]), &sig)
        .map_err(|_| "VCEK signature on report does not verify")
}

/// Pull the uncompressed SEC1 P-384 point out of an X.509 DER cert.  AMD's
/// VCEK certs always carry it as `BIT STRING(98){0x00, 0x04, x[48], y[48]}`;
/// scanning for that header avoids a full X.509 parser and is unambiguous
/// for these fixed-shape certs.
pub fn cert_p384_pubkey(der: &[u8]) -> Option<[u8; 97]> {
    let i = der.windows(4).position(|w| w == [0x03, 0x62, 0x00, 0x04])?;
    der.get(i + 3..i + 100)?.try_into().ok()
}
