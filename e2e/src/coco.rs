//! Raw CTAPHID-over-hidraw driver so the test can read the
//! `attStmt["snp"]`/`attStmt["tdx"]` entry that stock libfido2 ignores.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use ctap::cbor::Reader;
use ctap::hid;

/// Minimal CTAPHID client over Linux hidraw: write 65 (leading report-id 0),
/// read 64.
struct Hid {
    f: File,
    cid: u32,
}
impl Hid {
    fn open(dev: &Path) -> Self {
        let mut h = Self {
            f: OpenOptions::new().read(true).write(true).open(dev).unwrap(),
            cid: hid::CID_BROADCAST,
        };
        let nonce = [0x42u8; 8];
        let r = h.xact(hid::CTAPHID_INIT, &nonce);
        assert_eq!(&r[..8], &nonce);
        h.cid = u32::from_be_bytes(r[8..12].try_into().unwrap());
        h
    }
    fn xact(&mut self, cmd: u8, payload: &[u8]) -> Vec<u8> {
        for r in hid::fragment(self.cid, cmd, payload) {
            let mut out = [0u8; 65];
            out[1..].copy_from_slice(&r);
            self.f.write_all(&out).unwrap();
        }
        let mut r0 = [0u8; 64];
        self.f.read_exact(&mut r0).unwrap();
        assert_eq!(r0[4] & 0x80, 0x80, "expected init pkt");
        let bcnt = u16::from_be_bytes([r0[5], r0[6]]) as usize;
        let mut buf = Vec::with_capacity(bcnt);
        buf.extend_from_slice(&r0[7..7 + bcnt.min(hid::INIT_DATA_SIZE)]);
        while buf.len() < bcnt {
            let mut r = [0u8; 64];
            self.f.read_exact(&mut r).unwrap();
            let n = (bcnt - buf.len()).min(hid::CONT_DATA_SIZE);
            buf.extend_from_slice(&r[5..5 + n]);
        }
        buf
    }
}

/// Issue a `makeCredential` and return `(authData, attStmt[key])`. Panics
/// if `key` is absent — that is the property under test.
pub fn make_credential(dev: &Path, cdh: &[u8; 32], rp: &str, key: &str) -> (Vec<u8>, Vec<u8>) {
    use ctap::cbor::Writer;
    let mut w = Writer::new();
    w.map(4);
    w.unsigned(1);
    w.bytes(cdh);
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
    let mut req = vec![ctap::ctap2::CMD_MAKE_CREDENTIAL];
    req.extend(w.into_vec());

    let mut h = Hid::open(dev);
    let resp = h.xact(hid::CTAPHID_CBOR, &req);
    assert_eq!(resp[0], 0, "ctap status {:#x}", resp[0]);

    let mut rd = Reader::new(&resp[1..]);
    let mut auth_data = Vec::new();
    let mut rep = Vec::new();
    let n = rd.map().unwrap();
    for _ in 0..n {
        match rd.unsigned().unwrap() {
            2 => auth_data = rd.bytes().unwrap().to_vec(),
            3 => {
                let m = rd.map().unwrap();
                for _ in 0..m {
                    if rd.text().unwrap() == key {
                        rep = rd.bytes().unwrap().to_vec();
                    } else {
                        rd.skip().unwrap();
                    }
                }
            }
            _ => rd.skip().unwrap(),
        }
    }
    assert!(!rep.is_empty(), "no {key:?} in attStmt");
    (auth_data, rep)
}

/// Issue a `getAssertion` for `cred_id`; returns the CTAP2 status byte.
/// `OK` here proves the authenticator's master key re-derived the same
/// signing key — the direct persistence test.
pub fn get_assertion(dev: &Path, cdh: &[u8; 32], rp: &str, cred_id: &[u8]) -> u8 {
    use ctap::cbor::Writer;
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
    let mut req = vec![ctap::ctap2::CMD_GET_ASSERTION];
    req.extend(w.into_vec());
    Hid::open(dev).xact(hid::CTAPHID_CBOR, &req)[0]
}

pub fn cred_id(auth_data: &[u8]) -> &[u8] {
    let n = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    &auth_data[55..55 + n]
}
