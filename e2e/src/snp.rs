//! SNP attestation verifier (relying-party side, host code, not in TCB).
//!
//! Talks raw CTAPHID over `/dev/hidrawN` so we can read the `"snp"` attStmt
//! key that stock libfido2 ignores; reuses the same CBOR codec the enclave
//! uses.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use ctap::cbor::Reader;
use ctap::hid;
use sha2::{Digest, Sha512};

/// SNP `ATTESTATION_REPORT` structure (firmware ABI §7.3, Table 22).
/// 1184 bytes; signature covers `[0..0x2a0]`.
pub struct Report<'a>(pub &'a [u8]);
impl<'a> Report<'a> {
    pub const LEN: usize = 1184;
    pub fn report_data(&self) -> &[u8] {
        &self.0[0x50..0x90]
    }
    pub fn measurement(&self) -> &[u8] {
        &self.0[0x90..0xc0]
    }
    pub fn reported_tcb(&self) -> u64 {
        u64::from_le_bytes(self.0[0x180..0x188].try_into().unwrap())
    }
    pub fn chip_id(&self) -> &[u8] {
        &self.0[0x1a0..0x1e0]
    }
    pub fn signed(&self) -> &[u8] {
        &self.0[..0x2a0]
    }
    /// (r, s) as 48-byte big-endian — the on-wire format is 72-byte
    /// little-endian-padded per component.
    pub fn sig_rs(&self) -> ([u8; 48], [u8; 48]) {
        let f = |o: usize| {
            let mut v: [u8; 48] = self.0[o..o + 48].try_into().unwrap();
            v.reverse();
            v
        };
        (f(0x2a0), f(0x2a0 + 72))
    }
}

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

/// Issue a `makeCredential` and return `(authData, snp_report)`. Panics if
/// the response carries no `"snp"` key — that is the property under test.
pub fn make_credential(dev: &Path, cdh: &[u8; 32], rp: &str) -> (Vec<u8>, Vec<u8>) {
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
    let mut snp = Vec::new();
    let n = rd.map().unwrap();
    for _ in 0..n {
        match rd.unsigned().unwrap() {
            2 => auth_data = rd.bytes().unwrap().to_vec(),
            3 => {
                let m = rd.map().unwrap();
                for _ in 0..m {
                    if rd.text().unwrap() == "snp" {
                        snp = rd.bytes().unwrap().to_vec();
                    } else {
                        rd.skip().unwrap();
                    }
                }
            }
            _ => rd.skip().unwrap(),
        }
    }
    assert_eq!(snp.len(), Report::LEN, "no/short snp report in attStmt");
    (auth_data, snp)
}

/// Relying-party check: the report's `report_data` is the SHA-512 of the
/// exact bytes the credential signature covers, so a valid report binds the
/// PSP-measured guest to this credential's public key.
pub fn check_binding(auth_data: &[u8], cdh: &[u8; 32], report: &Report<'_>) {
    let mut h = Sha512::new();
    h.update(auth_data);
    h.update(cdh);
    assert_eq!(
        report.report_data(),
        &h.finalize()[..],
        "report_data does not bind authData||cdh"
    );
    assert_ne!(report.measurement(), [0u8; 48], "zero measurement");
}
