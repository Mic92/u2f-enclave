//! CTAP2 command layer (carried inside `CTAPHID_CBOR`).

use crate::cbor::{self, Reader, Writer};
use crate::cred::{self, MasterKeys};
use crate::{hid, Platform};
use alloc::vec;
use alloc::vec::Vec;
use p256::ecdsa::signature::Signer;

// Command bytes (first byte of the CBOR request).
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_RESET: u8 = 0x07;

pub mod status {
    pub const OK: u8 = 0x00;
    pub const ERR_INVALID_COMMAND: u8 = 0x01;
    pub const ERR_INVALID_LENGTH: u8 = 0x03;
    pub const ERR_INVALID_CBOR: u8 = 0x12;
    pub const ERR_MISSING_PARAMETER: u8 = 0x14;
    pub const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const ERR_INVALID_OPTION: u8 = 0x2C;
    pub const ERR_NO_CREDENTIALS: u8 = 0x2E;
}

/// Any CBOR parse failure maps to a single CTAP status; finer detail would
/// only help fingerprinting.
impl From<cbor::Error> for u8 {
    fn from(_: cbor::Error) -> u8 {
        status::ERR_INVALID_CBOR
    }
}

pub struct Ctx<'a, P: Platform> {
    pub platform: &'a mut P,
    pub aaguid: &'a [u8; 16],
    pub keys: &'a MasterKeys,
}

/// Dispatch a CTAP2 request. Returns `status || optional_cbor`.
pub fn handle<P: Platform>(ctx: &mut Ctx<'_, P>, payload: &[u8]) -> Vec<u8> {
    let Some((&cmd, params)) = payload.split_first() else {
        return vec![status::ERR_INVALID_LENGTH];
    };
    let res = match cmd {
        CMD_GET_INFO => Ok(get_info(ctx.aaguid)),
        CMD_MAKE_CREDENTIAL => make_credential(ctx, params),
        CMD_GET_ASSERTION => get_assertion(ctx, params),
        CMD_RESET => Ok(vec![status::OK]),
        _ => Ok(vec![status::ERR_INVALID_COMMAND]),
    };
    res.unwrap_or_else(|e| vec![e])
}

fn get_info(aaguid: &[u8; 16]) -> Vec<u8> {
    let mut w = Writer::with_prefix(status::OK);
    w.map(4);
    w.unsigned(0x01);
    w.array(1);
    w.text("FIDO_2_0");
    w.unsigned(0x03);
    w.bytes(aaguid);
    w.unsigned(0x04);
    w.map(2);
    w.text("rk");
    w.bool(false);
    w.text("up");
    w.bool(true);
    w.unsigned(0x05);
    w.unsigned(hid::MAX_MESSAGE_SIZE as u64);
    w.into_vec()
}

// ---------------------------------------------------------- makeCredential ---

fn make_credential<P: Platform>(ctx: &mut Ctx<'_, P>, params: &[u8]) -> Result<Vec<u8>, u8> {
    let mut r = Reader::new(params);
    let n = r.map()?;

    let mut client_data_hash: Option<[u8; 32]> = None;
    let mut rp_id: Option<&str> = None;
    let mut have_user = false;
    let mut es256_ok = false;
    let mut exclude: Vec<Vec<u8>> = Vec::new();

    for _ in 0..n {
        match r.unsigned()? {
            1 => client_data_hash = Some(read_hash(&mut r)?),
            2 => rp_id = Some(read_entity_id_text(&mut r)?),
            3 => {
                // user: required by spec; for non-resident creds we only need
                // to know it was supplied.
                r.skip()?;
                have_user = true;
            }
            4 => es256_ok = read_pubkey_params(&mut r)?,
            5 => exclude = read_cred_descriptor_ids(&mut r)?,
            7 => read_mc_options(&mut r)?,
            _ => r.skip()?,
        }
    }

    let _cdh = client_data_hash.ok_or(status::ERR_MISSING_PARAMETER)?;
    let rp_id = rp_id.ok_or(status::ERR_MISSING_PARAMETER)?;
    if !have_user {
        return Err(status::ERR_MISSING_PARAMETER);
    }
    if !es256_ok {
        return Err(status::ERR_UNSUPPORTED_ALGORITHM);
    }

    let rp_id_hash = cred::sha256(rp_id.as_bytes());
    // Evaluated after parsing so the check is independent of map key order;
    // a non-canonical request must not be able to skip exclusion.
    if exclude
        .iter()
        .any(|id| ctx.keys.lookup(&rp_id_hash, id).is_some())
    {
        return Err(status::ERR_CREDENTIAL_EXCLUDED);
    }
    let c = cred::make(ctx.platform, ctx.keys, &rp_id_hash);

    // authenticatorData (WebAuthn §6.1)
    let mut ad = Vec::with_capacity(37 + 16 + 2 + cred::CRED_ID_LEN + 77);
    ad.extend_from_slice(&rp_id_hash);
    ad.push(0x41); // flags: UP | AT
    ad.extend_from_slice(&0u32.to_be_bytes()); // signCount
    ad.extend_from_slice(ctx.aaguid);
    ad.extend_from_slice(&(cred::CRED_ID_LEN as u16).to_be_bytes());
    ad.extend_from_slice(&c.id);
    ad.extend_from_slice(&cred::cose_es256_key(&c.x, &c.y));

    let mut w = Writer::with_prefix(status::OK);
    w.map(3);
    w.unsigned(1);
    w.text("none");
    w.unsigned(2);
    w.bytes(&ad);
    w.unsigned(3);
    w.map(0);
    Ok(w.into_vec())
}

// ------------------------------------------------------------ getAssertion ---

fn get_assertion<P: Platform>(ctx: &mut Ctx<'_, P>, params: &[u8]) -> Result<Vec<u8>, u8> {
    let mut r = Reader::new(params);
    let n = r.map()?;

    let mut rp_id: Option<&str> = None;
    let mut client_data_hash: Option<[u8; 32]> = None;
    let mut allow: Vec<Vec<u8>> = Vec::new();

    for _ in 0..n {
        match r.unsigned()? {
            1 => rp_id = Some(r.text()?),
            2 => client_data_hash = Some(read_hash(&mut r)?),
            3 => allow = read_cred_descriptor_ids(&mut r)?,
            5 => read_ga_options(&mut r)?,
            _ => r.skip()?,
        }
    }

    let rp_id = rp_id.ok_or(status::ERR_MISSING_PARAMETER)?;
    let cdh = client_data_hash.ok_or(status::ERR_MISSING_PARAMETER)?;
    let rp_id_hash = cred::sha256(rp_id.as_bytes());

    let (id, sk) = allow
        .iter()
        .find_map(|id| ctx.keys.lookup(&rp_id_hash, id).map(|sk| (id, sk)))
        .ok_or(status::ERR_NO_CREDENTIALS)?;

    let mut ad = [0u8; 37];
    ad[..32].copy_from_slice(&rp_id_hash);
    ad[32] = 0x01; // flags: UP

    let sig: p256::ecdsa::Signature = sk.sign(&[&ad[..], &cdh].concat());
    let der = cred::der_ecdsa(&sig.to_bytes().into());

    let mut w = Writer::with_prefix(status::OK);
    w.map(3);
    w.unsigned(1);
    w.map(2);
    w.text("id");
    w.bytes(id);
    w.text("type");
    w.text("public-key");
    w.unsigned(2);
    w.bytes(&ad);
    w.unsigned(3);
    w.bytes(&der);
    Ok(w.into_vec())
}

// --------------------------------------------------------------- helpers ---

fn read_hash(r: &mut Reader<'_>) -> Result<[u8; 32], u8> {
    r.bytes()?
        .try_into()
        .map_err(|_| status::ERR_INVALID_LENGTH)
}

/// Parse a `PublicKeyCredentialRpEntity`/`UserEntity` and return its `"id"`
/// as text. Other fields (name, icon, displayName) are ignored.
fn read_entity_id_text<'a>(r: &mut Reader<'a>) -> Result<&'a str, u8> {
    let n = r.map()?;
    let mut id = None;
    for _ in 0..n {
        if r.text()? == "id" {
            id = Some(r.text()?);
        } else {
            r.skip()?;
        }
    }
    id.ok_or(status::ERR_MISSING_PARAMETER)
}

/// Returns true iff at least one entry is `{type:"public-key", alg:-7}`.
fn read_pubkey_params(r: &mut Reader<'_>) -> Result<bool, u8> {
    let mut ok = false;
    let n = r.array()?;
    for _ in 0..n {
        let m = r.map()?;
        let mut alg = 0i64;
        let mut ty_ok = false;
        for _ in 0..m {
            match r.text()? {
                "alg" => alg = r.int()?,
                "type" => ty_ok = r.text()? == "public-key",
                _ => r.skip()?,
            }
        }
        ok |= ty_ok && alg == -7;
    }
    Ok(ok)
}

fn read_cred_descriptor_ids(r: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, u8> {
    let n = r.array()?;
    // `n` is attacker-controlled; pre-reserving would let a 5-byte header
    // request gigabytes. Growth is bounded by the actual entries decoded,
    // which is bounded by the request buffer.
    let mut out = Vec::new();
    for _ in 0..n {
        let m = r.map()?;
        let mut id: Option<&[u8]> = None;
        for _ in 0..m {
            match r.text()? {
                "id" => id = Some(r.bytes()?),
                _ => r.skip()?,
            }
        }
        if let Some(id) = id {
            out.push(id.to_vec());
        }
    }
    Ok(out)
}

fn read_mc_options(r: &mut Reader<'_>) -> Result<(), u8> {
    let n = r.map()?;
    for _ in 0..n {
        match r.text()? {
            "rk" => {
                if r.bool()? {
                    return Err(status::ERR_UNSUPPORTED_OPTION);
                }
            }
            "uv" => {
                if r.bool()? {
                    return Err(status::ERR_INVALID_OPTION);
                }
            }
            _ => r.skip()?,
        }
    }
    Ok(())
}

fn read_ga_options(r: &mut Reader<'_>) -> Result<(), u8> {
    let n = r.map()?;
    for _ in 0..n {
        match r.text()? {
            "uv" => {
                if r.bool()? {
                    return Err(status::ERR_INVALID_OPTION);
                }
            }
            _ => r.skip()?,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    struct TestPlat {
        seed: u8,
        secret: [u8; 32],
    }
    impl Platform for TestPlat {
        fn random_bytes(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.seed = self.seed.wrapping_add(1);
                *b = self.seed;
            }
        }
        fn master_secret(&self) -> [u8; 32] {
            self.secret
        }
    }

    fn ctx() -> (TestPlat, MasterKeys, [u8; 16]) {
        let p = TestPlat {
            seed: 0,
            secret: [0x42; 32],
        };
        let k = MasterKeys::derive(&p.master_secret());
        (p, k, crate::AAGUID)
    }

    fn mc_request(rp: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(4);
        w.unsigned(1);
        w.bytes(&[0x11; 32]);
        w.unsigned(2);
        w.map(1);
        w.text("id");
        w.text(rp);
        w.unsigned(3);
        w.map(1);
        w.text("id");
        w.bytes(&[0x55; 8]);
        w.unsigned(4);
        w.array(1);
        w.map(2);
        w.text("alg");
        w.int(-7);
        w.text("type");
        w.text("public-key");
        let mut out = vec![CMD_MAKE_CREDENTIAL];
        out.extend(w.into_vec());
        out
    }

    fn ga_request(rp: &str, cred_id: &[u8], cdh: &[u8; 32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(3);
        w.unsigned(1);
        w.text(rp);
        w.unsigned(2);
        w.bytes(cdh);
        w.unsigned(3);
        w.array(1);
        w.map(2);
        w.text("id");
        w.bytes(cred_id);
        w.text("type");
        w.text("public-key");
        let mut out = vec![CMD_GET_ASSERTION];
        out.extend(w.into_vec());
        out
    }

    /// `r||s` from a DER ECDSA sig. Test-only; the authenticator only encodes.
    fn der_to_raw(der: &[u8]) -> [u8; 64] {
        assert_eq!(der[0], 0x30);
        let mut i = 2;
        let mut out = [0u8; 64];
        for half in 0..2 {
            assert_eq!(der[i], 0x02);
            let l = der[i + 1] as usize;
            let v = &der[i + 2..i + 2 + l];
            let v = if v[0] == 0 && v.len() > 32 {
                &v[1..]
            } else {
                v
            };
            out[half * 32 + 32 - v.len()..half * 32 + 32].copy_from_slice(v);
            i += 2 + l;
        }
        out
    }

    #[test]
    fn register_then_sign_verifies() {
        let (mut p, keys, aaguid) = ctx();
        let mut cx = Ctx {
            platform: &mut p,
            aaguid: &aaguid,
            keys: &keys,
        };

        // ---- makeCredential ----
        let resp = handle(&mut cx, &mc_request("example.org"));
        assert_eq!(resp[0], status::OK);
        let mut rd = Reader::new(&resp[1..]);
        assert_eq!(rd.map().unwrap(), 3);
        assert_eq!(rd.unsigned().unwrap(), 1);
        assert_eq!(rd.text().unwrap(), "none");
        assert_eq!(rd.unsigned().unwrap(), 2);
        let ad = rd.bytes().unwrap();

        // Pull credId and COSE pubkey out of authenticatorData.
        assert_eq!(&ad[..32], &cred::sha256(b"example.org"));
        assert_eq!(ad[32], 0x41);
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        assert_eq!(cred_len, cred::CRED_ID_LEN);
        let cred_id = &ad[55..55 + cred_len];
        let mut krd = Reader::new(&ad[55 + cred_len..]);
        assert_eq!(krd.map().unwrap(), 5);
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        for _ in 0..5 {
            match krd.int().unwrap() {
                -2 => x.copy_from_slice(krd.bytes().unwrap()),
                -3 => y.copy_from_slice(krd.bytes().unwrap()),
                _ => krd.skip().unwrap(),
            }
        }
        let mut sec1 = [4u8; 65];
        sec1[1..33].copy_from_slice(&x);
        sec1[33..].copy_from_slice(&y);
        let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();

        // ---- getAssertion ----
        let cdh = [0x22u8; 32];
        let resp = handle(&mut cx, &ga_request("example.org", cred_id, &cdh));
        assert_eq!(resp[0], status::OK);
        let mut rd = Reader::new(&resp[1..]);
        assert_eq!(rd.map().unwrap(), 3);
        let mut auth_data = &[][..];
        let mut sig_der = &[][..];
        for _ in 0..3 {
            match rd.unsigned().unwrap() {
                2 => auth_data = rd.bytes().unwrap(),
                3 => sig_der = rd.bytes().unwrap(),
                _ => rd.skip().unwrap(),
            }
        }
        let sig = Signature::from_slice(&der_to_raw(sig_der)).unwrap();
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&cdh);
        vk.verify(&msg, &sig).expect("signature verifies");

        // Wrong RP must not resolve the same credId.
        let resp = handle(&mut cx, &ga_request("evil.org", cred_id, &cdh));
        assert_eq!(resp[0], status::ERR_NO_CREDENTIALS);
    }

    #[test]
    fn huge_array_header_is_not_preallocated() {
        // allowList claiming 2^32-1 entries but supplying none must fail
        // cleanly, not OOM.
        let (mut p, keys, aaguid) = ctx();
        let mut cx = Ctx {
            platform: &mut p,
            aaguid: &aaguid,
            keys: &keys,
        };
        let mut w = Writer::new();
        w.map(3);
        w.unsigned(1);
        w.text("a");
        w.unsigned(2);
        w.bytes(&[0; 32]);
        w.unsigned(3);
        let mut req = vec![CMD_GET_ASSERTION];
        req.extend(w.into_vec());
        req.extend_from_slice(&[0x9A, 0xFF, 0xFF, 0xFF, 0xFF]); // array(2^32-1)
        assert_eq!(handle(&mut cx, &req)[0], status::ERR_INVALID_CBOR);
    }

    #[test]
    fn exclude_list_independent_of_key_order() {
        let (mut p, keys, aaguid) = ctx();
        let rp_hash = cred::sha256(b"example.org");
        let existing = cred::make(&mut p, &keys, &rp_hash);
        let mut cx = Ctx {
            platform: &mut p,
            aaguid: &aaguid,
            keys: &keys,
        };
        // Deliberately non-canonical: excludeList (5) before rp (2).
        let mut w = Writer::new();
        w.map(5);
        w.unsigned(5);
        w.array(1);
        w.map(2);
        w.text("id");
        w.bytes(&existing.id);
        w.text("type");
        w.text("public-key");
        w.unsigned(1);
        w.bytes(&[0; 32]);
        w.unsigned(2);
        w.map(1);
        w.text("id");
        w.text("example.org");
        w.unsigned(3);
        w.map(1);
        w.text("id");
        w.bytes(&[1]);
        w.unsigned(4);
        w.array(1);
        w.map(2);
        w.text("alg");
        w.int(-7);
        w.text("type");
        w.text("public-key");
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend(w.into_vec());
        assert_eq!(handle(&mut cx, &req)[0], status::ERR_CREDENTIAL_EXCLUDED);
    }

    #[test]
    fn rejects_unsupported_alg() {
        let (mut p, keys, aaguid) = ctx();
        let mut cx = Ctx {
            platform: &mut p,
            aaguid: &aaguid,
            keys: &keys,
        };
        let mut w = Writer::new();
        w.map(4);
        w.unsigned(1);
        w.bytes(&[0; 32]);
        w.unsigned(2);
        w.map(1);
        w.text("id");
        w.text("a");
        w.unsigned(3);
        w.map(1);
        w.text("id");
        w.bytes(&[1]);
        w.unsigned(4);
        w.array(1);
        w.map(2);
        w.text("alg");
        w.int(-257); // RS256
        w.text("type");
        w.text("public-key");
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend(w.into_vec());
        assert_eq!(handle(&mut cx, &req)[0], status::ERR_UNSUPPORTED_ALGORITHM);
    }
}
