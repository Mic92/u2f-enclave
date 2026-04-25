//! Mutual-attestation key handover between two SNP guests on the same chip.
//!
//! When this binary's KEK can't open the sealed master, the host relaunches
//! the *previous* guest from `snp.state` as a donor.  Each side gets a
//! fresh PSP-signed report
//! that binds an ephemeral P-256 public key; each side checks the other's
//! report is ① VCEK-signed (genuine PSP) ② same `author_key_digest` (same
//! operator key signed both builds) ③ same chip ④ debug-off, and the donor
//! additionally refuses a recipient with lower `guest_svn`.  Then a one-shot
//! ECDH+AES-GCM moves the 32-byte master across.
//!
//! Trust in the host-supplied VCEK pubkey is established by *self-pin*: a
//! guest first verifies its **own** fresh report (which only the real chip
//! VCEK could have signed) against it, so a forged key is rejected without
//! needing the RSA-4096 ASK/ARK chain.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use sha2::{Digest, Sha256, Sha512};

use crate::greq;
use crate::platform::fill_rdrand;
use crate::snp_report::{verify_sig, Report, REPORT_LEN};
use crate::vsock::Vsock;

const PUB_LEN: usize = 65;
/// `eph_pub[65] ‖ own_report[1184]`
const HELLO_LEN: usize = PUB_LEN + REPORT_LEN;
const VCEK_LEN: usize = 97;
/// `ct[32] ‖ tag[16]` — nonce is fixed-zero (key is one-shot).
const WRAPPED_LEN: usize = 48;

const POLICY_DEBUG: u64 = 1 << 19;

/// `RngCore` adapter so RustCrypto's keygen can draw from the on-die DRNG.
struct Rd;
impl RngCore for Rd {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        fill_rdrand(&mut b);
        u32::from_ne_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        fill_rdrand(&mut b);
        u64::from_ne_bytes(b)
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        fill_rdrand(d)
    }
    fn try_fill_bytes(
        &mut self,
        d: &mut [u8],
    ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
        fill_rdrand(d);
        Ok(())
    }
}
impl CryptoRng for Rd {}

fn read_n(vs: &mut Vsock, out: &mut [u8]) {
    let mut r = [0u8; 64];
    for c in out.chunks_mut(64) {
        vs.read_report(&mut r);
        c.copy_from_slice(&r[..c.len()]);
    }
}
fn write_n(vs: &mut Vsock, data: &[u8]) {
    let mut r = [0u8; 64];
    for c in data.chunks(64) {
        r.fill(0);
        r[..c.len()].copy_from_slice(c);
        vs.write_report(&r);
    }
}

/// Ephemeral keypair + own report with `report_data = SHA512(eph_pub)`.
fn hello() -> Option<(EphemeralSecret, [u8; HELLO_LEN], [u8; REPORT_LEN])> {
    let sk = EphemeralSecret::random(&mut Rd);
    let pk = sk.public_key().to_encoded_point(false);
    let pk: [u8; PUB_LEN] = pk.as_bytes().try_into().ok()?;
    let rd: [u8; 64] = Sha512::digest(pk).into();
    let rep = greq::report(&rd)?;
    let mut h = [0u8; HELLO_LEN];
    h[..PUB_LEN].copy_from_slice(&pk);
    h[PUB_LEN..].copy_from_slice(&rep);
    Some((sk, h, rep))
}

/// Checks common to both directions.  `mine` is this guest's own report.
fn verify_peer(
    vcek: &[u8; VCEK_LEN],
    mine: &[u8; REPORT_LEN],
    peer_hello: &[u8; HELLO_LEN],
    require_svn_ge: bool,
) -> Option<([u8; PUB_LEN], [u8; REPORT_LEN])> {
    let peer_pk: [u8; PUB_LEN] = peer_hello[..PUB_LEN].try_into().unwrap();
    let peer_rep: [u8; REPORT_LEN] = peer_hello[PUB_LEN..].try_into().unwrap();
    let m = Report(mine);
    let p = Report(&peer_rep);
    // Self-pin: only the real chip VCEK could have signed *our* report.
    verify_sig(&m, vcek).ok()?;
    verify_sig(&p, vcek).ok()?;
    let rd: [u8; 64] = Sha512::digest(peer_pk).into();
    if p.report_data() != rd
        || !p.author_key_en()
        || p.author_key_digest() != m.author_key_digest()
        || p.policy() & POLICY_DEBUG != 0
        || p.chip_id() != m.chip_id()
        || (require_svn_ge && p.guest_svn() < m.guest_svn())
    {
        return None;
    }
    Some((peer_pk, peer_rep))
}

/// Wrap key binds the ECDH secret *and* both attested transcripts, so a
/// relayed-but-tampered report breaks the GCM tag even if some field check
/// were missed.
fn wrap_key(
    sk: EphemeralSecret,
    peer_pk: &[u8; PUB_LEN],
    r_rep: &[u8],
    d_rep: &[u8],
) -> Option<[u8; 32]> {
    let pk = PublicKey::from_sec1_bytes(peer_pk).ok()?;
    let shared = sk.diffie_hellman(&pk);
    let mut h = Sha256::new();
    h.update(shared.raw_secret_bytes());
    h.update(r_rep);
    h.update(d_rep);
    Some(h.finalize().into())
}

/// New-binary side.  Sends its hello first so the host can look up the VCEK
/// from the embedded report; then waits for `[mode]`: 0 = host gave up
/// (offline / no donor), 1 = donor accepted, proceed.
pub fn recipient(vs: &mut Vsock) -> Option<[u8; 32]> {
    let (sk, my_hello, my_rep) = hello()?;
    write_n(vs, &my_hello);

    let mut mode = [0u8; 64];
    vs.read_report(&mut mode);
    if mode[0] != 1 {
        return None;
    }
    let mut vcek = [0u8; VCEK_LEN];
    read_n(vs, &mut vcek);
    let mut peer = [0u8; HELLO_LEN];
    read_n(vs, &mut peer);
    let mut w = [0u8; WRAPPED_LEN];
    // Drain everything the host sent *before* any check so a verify failure
    // doesn't leave a stray report in the RX queue for the CTAPHID loop.
    read_n(vs, &mut w);
    let (peer_pk, peer_rep) = verify_peer(&vcek, &my_rep, &peer, false)?;
    let key = wrap_key(sk, &peer_pk, &my_rep, &peer_rep)?;
    let mut ct: [u8; 32] = w[..32].try_into().unwrap();
    let tag: [u8; 16] = w[32..].try_into().unwrap();
    Aes256Gcm::new((&key).into())
        .decrypt_in_place_detached((&[0u8; 12]).into(), b"", &mut ct, (&tag).into())
        .ok()?;
    Some(ct)
}

/// Old-binary side.  Already holds `master` (it just unsealed it).
pub fn donor(vs: &mut Vsock, master: &[u8; 32]) {
    let mut vcek = [0u8; VCEK_LEN];
    read_n(vs, &mut vcek);
    let mut peer = [0u8; HELLO_LEN];
    read_n(vs, &mut peer);

    let Some((sk, my_hello, my_rep)) = hello() else {
        write_n(vs, &[0u8; 64]);
        return;
    };
    let Some((peer_pk, peer_rep)) = verify_peer(&vcek, &my_rep, &peer, true) else {
        write_n(vs, &[0u8; 64]);
        return;
    };
    let Some(key) = wrap_key(sk, &peer_pk, &peer_rep, &my_rep) else {
        write_n(vs, &[0u8; 64]);
        return;
    };
    write_n(vs, &[1u8; 1]);
    write_n(vs, &my_hello);

    let mut ct = *master;
    let tag = Aes256Gcm::new((&key).into())
        .encrypt_in_place_detached((&[0u8; 12]).into(), b"", &mut ct)
        .unwrap();
    let mut w = [0u8; WRAPPED_LEN];
    w[..32].copy_from_slice(&ct);
    w[32..].copy_from_slice(&tag);
    write_n(vs, &w);
}
