//! Cross-build the enclave unikernel and bake it into the host binary.
//!
//! A separate `CARGO_TARGET_DIR` under `OUT_DIR` keeps the inner cargo from
//! contending on the outer build's lock and makes the embedded artefact
//! independent of whatever `cargo build -p enclave` runs the user has done.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let ws = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    let st = Command::new(std::env::var_os("CARGO").unwrap())
        .current_dir(&ws)
        .env("CARGO_TARGET_DIR", out.join("guest-target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args([
            "build",
            "-p",
            "enclave",
            "--release",
            "--target",
            "x86_64-unknown-none",
        ])
        .status()
        .expect("spawn cargo");
    assert!(st.success(), "enclave build failed");

    let elf = out.join("guest-target/x86_64-unknown-none/release/enclave");
    std::fs::copy(&elf, out.join("enclave")).unwrap();

    println!("cargo:rerun-if-changed={}", ws.join("enclave").display());
    println!("cargo:rerun-if-changed={}", ws.join("ctap/src").display());
}
