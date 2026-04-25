//! Cross-build the bare-metal payloads, then **sign** the SGX one.
//!
//! SIGSTRUCT is computed here so the binary embeds only the signed blob and
//! never the RSA private key: the build machine is the signer, the host that
//! later runs `--sgx` is the adversary, and `EGETKEY(MRSIGNER)` binds the
//! enclave's seal key to this signer.  A separate `CARGO_TARGET_DIR` under
//! `OUT_DIR` keeps the inner cargo from contending on the outer build's lock.

use std::path::{Path, PathBuf};
use std::process::Command;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

#[path = "src/sgx_layout.rs"]
mod sgx_layout;
use sgx_layout::*;

const MOD: usize = 384; // RSA-3072
const SIGSTRUCT_LEN: usize = 1808;

fn cross(ws: &Path, out: &Path, krate: &str, rustflags: &str) -> PathBuf {
    let st = Command::new(std::env::var_os("CARGO").unwrap())
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", out.join(format!("{krate}-target")))
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("RUSTFLAGS", rustflags)
        .args([
            "build",
            "-p",
            krate,
            "--release",
            "--target",
            "x86_64-unknown-none",
        ])
        .status()
        .expect("spawn cargo");
    assert!(st.success(), "{krate} build failed");
    let elf = out.join(format!(
        "{krate}-target/x86_64-unknown-none/release/{krate}"
    ));
    let dst = out.join(krate);
    std::fs::copy(&elf, &dst).unwrap();
    println!("cargo:rerun-if-changed={}", ws.join(krate).display());
    dst
}

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let ws = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    // The guest runs at its link address; the enclave does not, so it is
    // built PIC + PIE and self-relocates.  RUSTFLAGS overrides the workspace
    // `[target.*.rustflags]` entirely, so each build sees only its own model.
    cross(&ws, &out, "guest", "-Crelocation-model=static");
    let sgx_elf = cross(
        &ws,
        &out,
        "sgx",
        "-Crelocation-model=pic -Clink-arg=-pie -Clink-arg=--apply-dynamic-relocs",
    );
    println!("cargo:rerun-if-changed={}", ws.join("ctap/src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ws.join("host/src/snp_report.rs").display()
    );
    println!("cargo:rerun-if-env-changed=U2FE_SGX_SIGN");
    println!("cargo:rerun-if-env-changed=U2FE_SGX_PUBKEY");

    let elf = std::fs::read(&sgx_elf).unwrap();
    let (segs, img) = layout(&elf);
    let mre = mrenclave(&segs, &img);
    let (tbs, mut ss) = sigstruct_body(&mre);

    // Signing always goes through an external command so this process never
    // touches the private key — the default just shells out to openssl with a
    // local file, an HSM/TPM build overrides U2FE_SGX_SIGN.  EINIT mandates
    // RSA-3072 e=3; the s³≡m check below rejects a wrong-exponent signer at
    // build time.
    let dflt = |f: &str| ws.join(f).to_string_lossy().into_owned();
    let sign_cmd = std::env::var("U2FE_SGX_SIGN").unwrap_or_else(|_| {
        format!(
            "openssl dgst -sha256 -sign {}",
            sh_quote(&dflt("sgx_key.pem"))
        )
    });
    let pubkey = std::env::var("U2FE_SGX_PUBKEY").unwrap_or_else(|_| dflt("sgx_pub.pem"));
    println!("cargo:rerun-if-changed={pubkey}");
    println!("cargo:rerun-if-changed={}", dflt("sgx_key.pem"));

    let n = pubkey_n(&std::fs::read(&pubkey).unwrap_or_else(|e| no_key(&pubkey, e)));
    let s = sign_external(&sign_cmd, &tbs);
    assert!(
        n.bits() >= 3071 && n.bits() <= 3072,
        "signer must be RSA-3072"
    );
    assert_eq!(
        s.modpow(&BigUint::from(3u8), &n),
        BigUint::from_bytes_be(&pkcs1v15_sha256(&tbs)),
        "signature does not verify with e=3 (EINIT requires exponent 3)"
    );
    eprintln!("  sgx mrenclave {}", hex(&mre));
    eprintln!("  sgx mrsigner  {}", hex(&Sha256::digest(le384(&n))));

    // q1 = ⌊s²/n⌋, q2 = ⌊s·(s² mod n)/n⌋ — precomputed so the CPU can do
    // s³ mod n with multiplies only during EINIT.
    let s2 = &s * &s;
    ss[128..128 + MOD].copy_from_slice(&le384(&n));
    ss[512..516].copy_from_slice(&3u32.to_le_bytes());
    ss[516..516 + MOD].copy_from_slice(&le384(&s));
    ss[1040..1040 + MOD].copy_from_slice(&le384(&(&s2 / &n)));
    ss[1424..1424 + MOD].copy_from_slice(&le384(&((&s * (&s2 % &n)) / &n)));
    std::fs::write(out.join("sgx.sigstruct"), ss).unwrap();
}

/// Pipe the 256-byte payload to a shell command that performs
/// RSASSA-PKCS1-v1_5-SHA256 and writes the raw 384-byte big-endian
/// signature to stdout, e.g. `openssl dgst -sha256 -sign key.pem` or
/// `pkcs11-tool --sign -m SHA256-RSA-PKCS …`.
fn sign_external(cmd: &str, tbs: &[u8; 256]) -> BigUint {
    use std::io::Write;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn U2FE_SGX_SIGN `{cmd}`: {e}"));
    child.stdin.take().unwrap().write_all(tbs).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "U2FE_SGX_SIGN `{cmd}` exited {}",
        out.status
    );
    assert_eq!(
        out.stdout.len(),
        MOD,
        "U2FE_SGX_SIGN must write a raw 384-byte big-endian signature to stdout"
    );
    BigUint::from_bytes_be(&out.stdout)
}

fn no_key(path: &str, e: std::io::Error) -> ! {
    panic!(
        "\n\nSGX signing public key not found at {path}: {e}.\n\
         The signer is the MRSIGNER identity EGETKEY binds the seal key to; it is\n\
         per-operator and not checked in.  For a local file key:\n\n  \
           openssl genrsa -3 3072 > sgx_key.pem\n  \
           openssl rsa -in sgx_key.pem -pubout > sgx_pub.pem\n\n\
         For a hardware token, set U2FE_SGX_SIGN to a command that reads the\n\
         256-byte payload on stdin and writes a raw 384-byte RSASSA-PKCS1-v1_5\n\
         SHA-256 signature to stdout, and U2FE_SGX_PUBKEY to its public key PEM.\n\
         The key must be RSA-3072 with public exponent 3 (EINIT requirement).\n"
    )
}

/// Reproduce the SHA-256 stream EINIT checks against MRENCLAVE: one 64-byte
/// record per ECREATE / EADD, plus per 256-byte chunk one EEXTEND record
/// followed by the chunk itself.  Mirrors `mrenclave_*` in the kernel
/// selftest's `sigstruct.c`.
fn mrenclave(segs: &[Seg], img: &[AlignedPage]) -> [u8; 32] {
    let bytes =
        unsafe { std::slice::from_raw_parts(img.as_ptr() as *const u8, img.len() * PAGE as usize) };
    let mut h = Sha256::new();
    let mut rec = |tag: u64, b: u64, c: u64, dlen, data: &[u8]| {
        let mut r = [0u8; 64];
        r[0..8].copy_from_slice(&tag.to_le_bytes());
        r[8..8 + dlen].copy_from_slice(&b.to_le_bytes()[..dlen]);
        r[8 + dlen..16 + dlen].copy_from_slice(&c.to_le_bytes());
        h.update(r);
        h.update(data);
    };
    // "ECREATE\0", ssaframesize=1 (u32), size (u64)
    rec(0x0045544145524345, 1, secs_size(segs), 4, &[]);
    for s in segs {
        for p in (s.off..s.off + s.len).step_by(PAGE as usize) {
            rec(0x0000000044444145, p, s.flags, 8, &[]); // "EADD"
            for c in (p..p + PAGE).step_by(256) {
                rec(0x00444E4554584545, c, 0, 8, &bytes[c as usize..][..256]); // "EEXTEND"
            }
        }
    }
    h.finalize().into()
}

/// Unsigned SIGSTRUCT and the 256-byte payload the signature covers.
fn sigstruct_body(mre: &[u8; 32]) -> ([u8; 256], [u8; SIGSTRUCT_LEN]) {
    let mut ss = [0u8; SIGSTRUCT_LEN];
    // header (SDM Table 38-19): magic constants, vendor=0, date=0.
    ss[0..16].copy_from_slice(&[6, 0, 0, 0, 0xe1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
    ss[24..40].copy_from_slice(&[1, 1, 0, 0, 0x60, 0, 0, 0, 0x60, 0, 0, 0, 1, 0, 0, 0]);
    // body @ 900: pin DEBUG=0 and MODE64BIT=1 — without the mask the host
    // could EINIT a DEBUG enclave under our MRSIGNER and EDBGRD the seal key.
    ss[928..936].copy_from_slice(&ATTR_MODE64BIT.to_le_bytes());
    ss[936..944].copy_from_slice(&XFRM_LEGACY.to_le_bytes());
    ss[944..952].copy_from_slice(&(ATTR_DEBUG | ATTR_MODE64BIT).to_le_bytes());
    ss[960..992].copy_from_slice(mre);
    // Signature is over header(128) ‖ body(128).
    let mut tbs = [0u8; 256];
    tbs[..128].copy_from_slice(&ss[0..128]);
    tbs[128..].copy_from_slice(&ss[900..1028]);
    (tbs, ss)
}

fn pkcs1v15_sha256(tbs: &[u8]) -> [u8; MOD] {
    let mut em = [0xffu8; MOD];
    em[0] = 0;
    em[1] = 1;
    const DI: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    em[MOD - 52] = 0;
    em[MOD - 51..MOD - 32].copy_from_slice(&DI);
    em[MOD - 32..].copy_from_slice(&Sha256::digest(tbs));
    em
}

fn le384(x: &BigUint) -> [u8; MOD] {
    let mut b = [0u8; MOD];
    let v = x.to_bytes_le();
    b[..v.len()].copy_from_slice(&v);
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// --- minimal SPKI / PKCS#1-public reader --------------------------------

fn pubkey_n(pem: &[u8]) -> BigUint {
    let s = std::str::from_utf8(pem).expect("PEM utf8");
    let body: String = s
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect();
    let der = b64(body.as_bytes());
    let mut p = &der[..];
    if s.contains("BEGIN PUBLIC KEY") {
        // SPKI: SEQUENCE { AlgId, BIT STRING { 0x00, RSAPublicKey } }
        p = der_tag(&mut p, 0x30);
        der_tag(&mut p, 0x30);
        p = &der_tag(&mut p, 0x03)[1..]; // skip unused-bits octet
    }
    // PKCS#1 RSAPublicKey ::= SEQUENCE { n, e }
    p = der_tag(&mut p, 0x30);
    BigUint::from_bytes_be(der_tag(&mut p, 0x02))
}

/// Read one DER TLV: assert tag, return value bytes, advance past it.
fn der_tag<'a>(p: &mut &'a [u8], tag: u8) -> &'a [u8] {
    assert_eq!(p[0], tag, "PEM: unexpected DER tag");
    let (len, hdr) = match p[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 => (p[2] as usize, 3),
        0x82 => (u16::from_be_bytes([p[2], p[3]]) as usize, 4),
        _ => panic!("PEM: DER length"),
    };
    let v = &p[hdr..hdr + len];
    *p = &p[hdr + len..];
    v
}

fn b64(s: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
    for &c in s.iter().filter(|&&c| c != b'=') {
        let v = lut[c as usize];
        assert_ne!(v, 255, "PEM: bad base64");
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
