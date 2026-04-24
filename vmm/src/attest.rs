//! `u2f-enclave attest`: CLI stand-in for a WebAuthn client. Issues a
//! `makeCredential` over raw hidraw, pulls `attStmt["snp"]`, does the
//! credential-binding check (the one `verify` leaves to the caller), and
//! writes the raw report to stdout so it pipes into `verify`.
//!
//! Not a security boundary — this is the *client* side. Useful for demoing
//! the full flow on a headless host without a browser.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ctap::cbor::{Reader, Writer};
use ctap::hid;
use sha2::{Digest, Sha512};

use crate::verify::{hex, REPORT_LEN};

const HID_NAME: &str = "u2f-enclave";

pub fn cmd(dev: Option<String>) -> i32 {
    let dev = match dev.map(PathBuf::from).or_else(find_hidraw) {
        Some(p) => p,
        None => {
            eprintln!("attest: no '{HID_NAME}' hidraw device found; is `u2f-enclave` running?");
            return 2;
        }
    };
    eprintln!("attest: using {}", dev.display());

    let mut cdh = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut cdh))
        .expect("urandom");

    let (auth_data, rep) = match make_credential(&dev, &cdh, "localhost") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("attest: {e}");
            return 2;
        }
    };
    if rep.len() != REPORT_LEN {
        eprintln!(
            "attest: response has no attStmt[\"snp\"] (got {} bytes); \
             the authenticator is not running under --snp",
            rep.len()
        );
        return 1;
    }

    let mut h = Sha512::new();
    h.update(&auth_data);
    h.update(cdh);
    let bind = h.finalize();
    let bound = rep[0x50..0x90] == bind[..];
    eprintln!(
        "attest: report_data {} SHA-512(authData||cdh){}",
        if bound { "==" } else { "!=" },
        if bound { "" } else { "  ← FAIL" },
    );
    eprintln!("attest: cred_id      {}", hex(cred_id(&auth_data)));

    io::stdout().write_all(&rep).expect("stdout");
    if bound {
        0
    } else {
        1
    }
}

/// Minimal CTAPHID client over Linux hidraw: write 65 (leading report-id 0),
/// read 64.
struct Hid(File, u32);
impl Hid {
    fn open(dev: &Path) -> io::Result<Self> {
        let mut h = Self(
            OpenOptions::new().read(true).write(true).open(dev)?,
            hid::CID_BROADCAST,
        );
        let nonce = [0x42u8; 8];
        let r = h.xact(hid::CTAPHID_INIT, &nonce)?;
        h.1 = u32::from_be_bytes(r[8..12].try_into().unwrap());
        Ok(h)
    }
    fn xact(&mut self, cmd: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
        for r in hid::fragment(self.1, cmd, payload) {
            let mut out = [0u8; 65];
            out[1..].copy_from_slice(&r);
            self.0.write_all(&out)?;
        }
        let mut r0 = [0u8; 64];
        self.0.read_exact(&mut r0)?;
        let bcnt = u16::from_be_bytes([r0[5], r0[6]]) as usize;
        let mut buf = Vec::with_capacity(bcnt);
        buf.extend_from_slice(&r0[7..7 + bcnt.min(hid::INIT_DATA_SIZE)]);
        while buf.len() < bcnt {
            let mut r = [0u8; 64];
            self.0.read_exact(&mut r)?;
            let n = (bcnt - buf.len()).min(hid::CONT_DATA_SIZE);
            buf.extend_from_slice(&r[5..5 + n]);
        }
        Ok(buf)
    }
}

fn make_credential(dev: &Path, cdh: &[u8; 32], rp: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
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
    w.bytes(b"demo");
    w.unsigned(4);
    w.array(1);
    w.map(2);
    w.text("alg");
    w.int(-7);
    w.text("type");
    w.text("public-key");
    let mut req = vec![ctap::ctap2::CMD_MAKE_CREDENTIAL];
    req.extend(w.into_vec());

    let resp = Hid::open(dev)?.xact(hid::CTAPHID_CBOR, &req)?;
    if resp[0] != 0 {
        return Err(io::Error::other(format!("CTAP2 status {:#x}", resp[0])));
    }
    parse(&resp[1..]).ok_or_else(|| io::Error::other("malformed makeCredential response"))
}

fn parse(body: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut rd = Reader::new(body);
    let (mut ad, mut rep) = (Vec::new(), Vec::new());
    for _ in 0..rd.map().ok()? {
        match rd.unsigned().ok()? {
            2 => ad = rd.bytes().ok()?.to_vec(),
            3 => {
                for _ in 0..rd.map().ok()? {
                    if rd.text().ok()? == "snp" {
                        rep = rd.bytes().ok()?.to_vec();
                    } else {
                        rd.skip().ok()?;
                    }
                }
            }
            _ => rd.skip().ok()?,
        }
    }
    Some((ad, rep))
}

fn cred_id(auth_data: &[u8]) -> &[u8] {
    let n = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    &auth_data[55..55 + n]
}

fn find_hidraw() -> Option<PathBuf> {
    let needle = format!("HID_NAME={HID_NAME}");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        for e in fs::read_dir("/sys/class/hidraw").ok()?.flatten() {
            if fs::read_to_string(e.path().join("device/uevent")).is_ok_and(|s| s.contains(&needle))
            {
                return Some(PathBuf::from("/dev").join(e.file_name()));
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
