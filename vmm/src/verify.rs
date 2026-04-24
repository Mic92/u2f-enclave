//! Relying-party side: parse an SNP attestation report, verify its VCEK
//! signature, and check the measurement against this build's expected value.
//! Host code, not in the TCB.
//!
//! Refs: SNP firmware ABI §7.3 (Table 22 report layout), AMD KDS spec.

use std::io::{self, Read};
use std::path::PathBuf;
use std::{env, fs};

use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha384};

pub const REPORT_LEN: usize = 1184;

/// Borrowed view over a 1184-byte `ATTESTATION_REPORT`. Signature covers
/// `[0..0x2a0]`.
pub struct Report<'a>(pub &'a [u8; REPORT_LEN]);
impl Report<'_> {
    pub fn version(&self) -> u32 {
        u32::from_le_bytes(self.0[..4].try_into().unwrap())
    }
    pub fn policy(&self) -> u64 {
        u64::from_le_bytes(self.0[8..16].try_into().unwrap())
    }
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
    /// `r||s` big-endian. On-wire format is 72-byte LE-padded per component.
    fn sig_be(&self) -> [u8; 96] {
        let mut rs = [0u8; 96];
        for (h, w) in [(0, 0x2a0), (48, 0x2a0 + 72)] {
            rs[h..h + 48].copy_from_slice(&self.0[w..w + 48]);
            rs[h..h + 48].reverse();
        }
        rs
    }
}

/// Verify the report's ECDSA P-384 signature against the VCEK leaf cert.
/// (ASK/ARK chain check would additionally prove the VCEK is AMD-issued; the
/// HTTPS fetch already pins to AMD's endpoint.)
pub fn verify_signature(r: &Report<'_>, vcek_der: &[u8]) -> Result<(), String> {
    let sig = Signature::from_slice(&r.sig_be()).map_err(|e| format!("bad signature: {e}"))?;
    vcek_pubkey(vcek_der)?
        .verify_prehash(&Sha384::digest(&r.0[..0x2a0]), &sig)
        .map_err(|_| "VCEK signature on report does not verify".into())
}

/// Pull the SEC1 uncompressed point out of an x509 DER cert. VCEK certs
/// always carry the EC pubkey as `BIT STRING(98){0x00, 0x04, x[48], y[48]}`;
/// scanning for that header avoids a full x509 parser and is unambiguous for
/// these fixed-shape AMD certs.
fn vcek_pubkey(der: &[u8]) -> Result<VerifyingKey, String> {
    let i = der
        .windows(4)
        .position(|w| w == [0x03, 0x62, 0x00, 0x04])
        .ok_or("no P-384 SEC1 point in VCEK cert")?;
    VerifyingKey::from_sec1_bytes(&der[i + 3..i + 100]).map_err(|e| format!("VCEK pubkey: {e}"))
}

/// AMD KDS lookup by `(chip_id, reported_tcb)`. Result is cached on disk so
/// only the first call per chip+tcb hits the network.
pub fn fetch_vcek(r: &Report<'_>) -> Result<Vec<u8>, String> {
    let dir = cache_dir();
    let _ = fs::create_dir_all(&dir);
    let cache = dir.join(format!(
        "vcek-{}-{:016x}.der",
        hex(&r.chip_id()[..8]),
        r.reported_tcb()
    ));
    if let Ok(b) = fs::read(&cache) {
        return Ok(b);
    }

    // KDS product name from report v3+'s cpuid (family, model). Mapping per
    // virtee/sev (Apache-2.0). v2 reports lack the field.
    let (fam, mdl) = (r.0[0x188], r.0[0x189]);
    let product = if r.version() >= 3 {
        match (fam, mdl) {
            (0x19, 0x00..=0x0f) => "Milan",
            (0x19, 0x10..=0x1f | 0xa0..=0xaf) => "Genoa",
            (0x1a, 0x00..=0x11) => "Turin",
            _ => {
                return Err(format!(
                    "unknown KDS product for cpuid fam={fam:#x} mdl={mdl:#x}"
                ))
            }
        }
        .to_string()
    } else {
        env::var("U2FE_KDS_PRODUCT").map_err(|_| {
            "report v<3 has no cpuid; set U2FE_KDS_PRODUCT (Milan/Genoa/Turin)".to_string()
        })?
    };
    // TCB byte layout is Milan/Genoa; Turin reshuffled it.
    let tcb = r.reported_tcb().to_le_bytes();
    let url = format!(
        "https://kdsintf.amd.com/vcek/v1/{product}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        hex(r.chip_id()),
        tcb[0],
        tcb[1],
        tcb[6],
        tcb[7],
    );
    eprintln!("verify: fetching {url}");
    let mut der = Vec::new();
    ureq::get(&url)
        .call()
        .map_err(|e| {
            format!(
                "KDS fetch failed ({e}); pre-seed {} to run offline",
                cache.display()
            )
        })?
        .into_reader()
        .read_to_end(&mut der)
        .map_err(|e| e.to_string())?;
    let _ = fs::write(&cache, &der);
    Ok(der)
}

fn cache_dir() -> PathBuf {
    env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(env::temp_dir)
        .join("u2f-enclave")
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `u2f-enclave verify [--vcek FILE]`: read a 1184-byte report on stdin,
/// check its VCEK signature and that its measurement matches this build.
/// The credential-binding check (`report_data == SHA-512(authData ‖ cdh)`)
/// stays with the caller — they have those bytes, we don't — so print
/// `report_data` for them.
pub fn cmd(vcek_path: Option<String>, expected_measurement: [u8; 48]) -> i32 {
    let mut buf = [0u8; REPORT_LEN];
    if let Err(e) = io::stdin().read_exact(&mut buf) {
        eprintln!("verify: stdin must be exactly {REPORT_LEN} bytes (raw SNP report): {e}");
        return 2;
    }
    let r = Report(&buf);

    let vcek = match vcek_path {
        Some(p) => fs::read(&p).map_err(|e| format!("read {p}: {e}")),
        None => fetch_vcek(&r),
    };
    let sig_ok = match vcek.and_then(|d| verify_signature(&r, &d)) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("verify: {e}");
            false
        }
    };
    let meas_ok = r.measurement() == expected_measurement;
    let pol_ok = r.policy() == crate::snp::SNP_POLICY;

    println!("report_data   {}", hex(r.report_data()));
    println!("measurement   {}  {}", hex(r.measurement()), ok(meas_ok));
    println!("policy        {:#x}  {}", r.policy(), ok(pol_ok));
    println!("chip_id       {}", hex(&r.chip_id()[..8]));
    println!("reported_tcb  {:#018x}", r.reported_tcb());
    println!("vcek_sig      {}", ok(sig_ok));
    eprintln!("verify: caller must also check report_data == SHA-512(authData || clientDataHash)");

    if sig_ok && meas_ok && pol_ok {
        0
    } else {
        1
    }
}

fn ok(b: bool) -> &'static str {
    if b {
        "ok"
    } else {
        "FAIL"
    }
}
