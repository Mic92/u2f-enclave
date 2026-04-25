//! Relying-party side: `verify`/`vcek-url` subcommands.  Report layout and
//! signature check live in `snp_report` (shared with the guest); this file
//! is the std-only I/O around it.  Host code, not in the TCB.

use std::path::PathBuf;
use std::{env, fs, io, io::Read};

use crate::snp_report::{cert_p384_pubkey, verify_sig};
pub use crate::snp_report::{Report, REPORT_LEN};

/// Verify the report against a VCEK leaf cert (DER).  ASK/ARK chain is not
/// checked: the HTTPS fetch already pins to AMD's endpoint.
pub fn verify_signature(r: &Report<'_>, vcek_der: &[u8]) -> Result<(), String> {
    let pk = cert_p384_pubkey(vcek_der).ok_or("no P-384 SEC1 point in VCEK cert")?;
    verify_sig(r, &pk).map_err(String::from)
}

/// VCEK is per `(chip_id, reported_tcb)`, so it can't be baked in. Look in
/// the cache; on miss, print the exact `curl` that populates it. Keeps an
/// HTTP+TLS stack out of the binary for what is a once-per-chip fetch.
pub fn find_vcek(r: &Report<'_>) -> Result<Vec<u8>, String> {
    let dir = cache_dir();
    let cache = dir.join(format!(
        "vcek-{}-{:016x}.der",
        hex(&r.chip_id()[..8]),
        r.reported_tcb()
    ));
    if let Ok(b) = fs::read(&cache) {
        return Ok(b);
    }
    let _ = fs::create_dir_all(&dir);
    Err(format!(
        "no VCEK for this chip/TCB. Fetch it once (or pass --vcek FILE):\n  \
         curl -fsSo {} '{}'",
        cache.display(),
        kds_url(r),
    ))
}

/// AMD KDS lookup URL. Product name from the report's cpuid (v3+); mapping
/// per virtee/sev (Apache-2.0). TCB byte layout is Milan/Genoa; Turin
/// reshuffled it.
pub fn kds_url(r: &Report<'_>) -> String {
    let (fam, mdl) = (r.0[0x188], r.0[0x189]);
    let product = match (fam, mdl) {
        (0x19, 0x00..=0x0f) => "Milan",
        (0x19, 0x10..=0x1f | 0xa0..=0xaf) => "Genoa",
        (0x1a, 0x00..=0x11) => "Turin",
        // v<3 reports have no cpuid here; let the user edit the URL.
        _ => "<Milan|Genoa|Turin>",
    };
    let tcb = r.reported_tcb().to_le_bytes();
    format!(
        "https://kdsintf.amd.com/vcek/v1/{product}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        hex(r.chip_id()),
        tcb[0],
        tcb[1],
        tcb[6],
        tcb[7],
    )
}

/// `u2f-enclave vcek-url`: stdin = report, stdout = bare URL (composes with
/// `curl -O "$(…)"`), stderr = where `verify` will look for it.
pub fn cmd_url() -> i32 {
    let mut buf = [0u8; REPORT_LEN];
    if let Err(e) = io::stdin().read_exact(&mut buf) {
        eprintln!("vcek-url: stdin must be a {REPORT_LEN}-byte SNP report: {e}");
        return 2;
    }
    let r = Report(&buf);
    println!("{}", kds_url(&r));
    eprintln!(
        "vcek-url: verify looks for this at {}/vcek-{}-{:016x}.der",
        cache_dir().display(),
        hex(&r.chip_id()[..8]),
        r.reported_tcb()
    );
    0
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
pub fn cmd(vcek_path: Option<String>, expected: [u8; 48]) -> i32 {
    let mut buf = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut buf) {
        eprintln!("verify: read stdin: {e}");
        return 2;
    }
    let buf: [u8; REPORT_LEN] = match buf.try_into() {
        Ok(b) => b,
        Err(b) => {
            eprintln!(
                "verify: stdin is {} bytes; expected {REPORT_LEN} (raw SNP report)",
                b.len()
            );
            return 2;
        }
    };
    let r = Report(&buf);
    let vcek = match vcek_path {
        Some(p) => fs::read(&p).map_err(|e| format!("read {p}: {e}")),
        None => find_vcek(&r),
    };
    let sig_ok = match vcek.and_then(|d| verify_signature(&r, &d)) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("verify: {e}");
            false
        }
    };
    // Compare against what *this binary* computes for its own guest image.
    // If the computation is wrong we reject good reports; we can't accept a
    // bad one because the PSP only signs what it actually measured.  The
    // author-key arm lets a verifier built from one release accept reports
    // from another, as long as the same operator key signed both.
    let meas_ok = r.measurement() == expected;
    let akd_ok = r.author_key_en() && r.author_key_digest() == crate::snp::AUTHOR_KEY_DIGEST;
    let pol_ok = r.policy() == crate::snp::SNP_POLICY;

    let tag = |b, s| if b { s } else { "" };
    println!("report_data   {}", hex(r.report_data()));
    println!(
        "measurement   {}  {}",
        hex(r.measurement()),
        tag(meas_ok, "= this build")
    );
    println!(
        "author_key    {}  {}",
        hex(r.author_key_digest()),
        tag(akd_ok, "= this build's signer")
    );
    println!("policy        {:#x}  {}", r.policy(), ok(pol_ok));
    println!("chip_id       {}", hex(&r.chip_id()[..8]));
    println!("reported_tcb  {:#018x}", r.reported_tcb());
    println!("vcek_sig      {}", ok(sig_ok));
    eprintln!("verify: caller must also check report_data == SHA-512(authData || clientDataHash)");

    let pass = sig_ok && (meas_ok || akd_ok) && pol_ok;
    if !meas_ok && !akd_ok {
        eprintln!("verify: neither measurement nor author_key_digest match this build");
    }
    if pass {
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
