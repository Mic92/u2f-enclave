//! Cross-build the bare-metal payloads and bake them into the host binary.
//!
//! A separate `CARGO_TARGET_DIR` under `OUT_DIR` keeps the inner cargo from
//! contending on the outer build's lock and makes the embedded artefacts
//! independent of whatever ad-hoc `cargo build -p ...` runs the user has done.

use std::path::{Path, PathBuf};
use std::process::Command;

fn cross(ws: &Path, out: &Path, krate: &str) {
    let st = Command::new(std::env::var_os("CARGO").unwrap())
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", out.join(format!("{krate}-target")))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
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
    std::fs::copy(&elf, out.join(krate)).unwrap();
    println!("cargo:rerun-if-changed={}", ws.join(krate).display());
}

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let ws = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    cross(&ws, &out, "guest");
    cross(&ws, &out, "sgx");
    println!("cargo:rerun-if-changed={}", ws.join("ctap/src").display());
}
