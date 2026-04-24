//! Stateless credential derivation.
//!
//! We never store per-credential keys. Instead the credential ID returned to
//! the relying party *is* the key material: a random nonce plus a MAC binding
//! it to the RP. On `getAssertion` we re-derive the private key from
//! `(master_secret, rpIdHash, nonce)` and reject IDs whose MAC does not
//! match. This is the same trick hardware keys use to be "infinite-slot"
//! without flash, and it means M1 needs no persistence at all.
//!
//! ```text
//! mac_key    = HMAC-SHA256(master_secret, "u2fe/mac")
//! derive_key = HMAC-SHA256(master_secret, "u2fe/key")
//! credId     = nonce[32] || HMAC-SHA256(mac_key, rpIdHash || nonce)[..16]
//! priv       = HMAC-SHA256(derive_key, rpIdHash || nonce || ctr)   (first ctr
//!                                                              that yields a
//!                                                              valid scalar)
//! ```

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const CRED_ID_LEN: usize = 48;
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;

pub struct MasterKeys {
    mac_key: [u8; 32],
    derive_key: [u8; 32],
}

impl MasterKeys {
    pub fn derive(master_secret: &[u8; 32]) -> Self {
        Self {
            mac_key: hmac(master_secret, &[b"u2fe/mac"]),
            derive_key: hmac(master_secret, &[b"u2fe/key"]),
        }
    }

    fn tag(&self, rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; TAG_LEN] {
        let full = hmac(&self.mac_key, &[rp_id_hash, nonce]);
        full[..TAG_LEN].try_into().unwrap()
    }

    fn signing_key(&self, rp_id_hash: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> SigningKey {
        // P-256's order is ~2^-32 short of 2^256, so a uniformly random
        // 32-byte string is occasionally >= n. Retry with a counter; the
        // chance of needing more than one round is negligible but handled.
        let mut ctr = 0u8;
        loop {
            let d = hmac(&self.derive_key, &[rp_id_hash, nonce, &[ctr]]);
            if let Ok(sk) = SigningKey::from_slice(&d) {
                return sk;
            }
            ctr = ctr.wrapping_add(1);
        }
    }

    /// Re-derive the signing key for `cred_id`, or `None` if the ID was not
    /// minted by this authenticator for this RP. Constant-time in the tag
    /// comparison so an attacker cannot use timing to forge IDs.
    pub fn lookup(&self, rp_id_hash: &[u8; 32], cred_id: &[u8]) -> Option<SigningKey> {
        if cred_id.len() != CRED_ID_LEN {
            return None;
        }
        let nonce: &[u8; NONCE_LEN] = cred_id[..NONCE_LEN].try_into().unwrap();
        let tag: &[u8; TAG_LEN] = cred_id[NONCE_LEN..].try_into().unwrap();
        if !bool::from(self.tag(rp_id_hash, nonce).ct_eq(tag)) {
            return None;
        }
        Some(self.signing_key(rp_id_hash, nonce))
    }
}

pub struct NewCredential {
    pub id: [u8; CRED_ID_LEN],
    pub x: [u8; 32],
    pub y: [u8; 32],
}

pub fn make<P: crate::Platform>(
    platform: &mut P,
    keys: &MasterKeys,
    rp_id_hash: &[u8; 32],
) -> NewCredential {
    let mut nonce = [0u8; NONCE_LEN];
    platform.random_bytes(&mut nonce);
    let tag = keys.tag(rp_id_hash, &nonce);

    let mut id = [0u8; CRED_ID_LEN];
    id[..NONCE_LEN].copy_from_slice(&nonce);
    id[NONCE_LEN..].copy_from_slice(&tag);

    let sk = keys.signing_key(rp_id_hash, &nonce);
    let pk = sk.verifying_key().to_encoded_point(false);
    NewCredential {
        id,
        x: pk.x().unwrap()[..].try_into().unwrap(),
        y: pk.y().unwrap()[..].try_into().unwrap(),
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Encode a raw P-256 ECDSA signature (`r || s`) as ASN.1 DER, which is what
/// WebAuthn ES256 puts on the wire. Hand-rolled to avoid pulling the `der`
/// crate into the TCB for ~20 lines of logic.
pub fn der_ecdsa(rs: &[u8; 64]) -> Vec<u8> {
    fn push_int(out: &mut Vec<u8>, v: &[u8]) {
        // DER INTEGER is minimal two's-complement: strip leading zeros, then
        // prepend one 0x00 if the MSB is set so it is not read as negative.
        let mut i = 0;
        while i + 1 < v.len() && v[i] == 0 {
            i += 1;
        }
        let v = &v[i..];
        let pad = v[0] & 0x80 != 0;
        out.push(0x02);
        out.push((v.len() + pad as usize) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
    }
    let mut body = Vec::with_capacity(72);
    push_int(&mut body, &rs[..32]);
    push_int(&mut body, &rs[32..]);
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

/// CTAP2 COSE_Key for an uncompressed P-256 public key (kty=EC2, alg=ES256).
pub fn cose_es256_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    use crate::cbor::Writer;
    let mut w = Writer::new();
    w.map(5);
    w.int(1);
    w.int(2); // kty: EC2
    w.int(3);
    w.int(-7); // alg: ES256
    w.int(-1);
    w.int(1); // crv: P-256
    w.int(-2);
    w.bytes(x);
    w.int(-3);
    w.bytes(y);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_roundtrips_and_binds_rp() {
        let keys = MasterKeys::derive(&[7u8; 32]);
        let rp = sha256(b"example.org");
        let nonce = [1u8; 32];
        let tag = keys.tag(&rp, &nonce);
        let mut id = [0u8; CRED_ID_LEN];
        id[..32].copy_from_slice(&nonce);
        id[32..].copy_from_slice(&tag);

        assert!(keys.lookup(&rp, &id).is_some());
        assert!(keys.lookup(&sha256(b"evil.org"), &id).is_none());
        let mut bad = id;
        bad[47] ^= 1;
        assert!(keys.lookup(&rp, &bad).is_none());
    }

    #[test]
    fn der_minimal_encoding() {
        // r with leading zeros + non-negative MSB, s with MSB set.
        let mut rs = [0u8; 64];
        rs[30] = 0x01;
        rs[31] = 0x02;
        rs[32] = 0x80;
        let der = der_ecdsa(&rs);
        assert_eq!(
            der,
            [
                0x30, 0x27, // SEQUENCE, len 39
                0x02, 0x02, 0x01, 0x02, // INTEGER 0x0102
                0x02, 0x21, 0x00, 0x80, // INTEGER, 33 bytes, 0x00 pad, 0x80, then 31 zeros
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0,
            ]
        );
    }
}
