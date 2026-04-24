use std::fs;
use std::process::{Command, Stdio};

use e2e::*;

/// PVH boot to 64-bit Rust on the plain `pc` machine. The only test that
/// needs no host devices, so it is the baseline CI sanity check.
#[test]
fn boot_pvh() {
    let elf = enclave_elf();
    let out = Command::new("qemu-system-x86_64")
        .arg("-kernel")
        .arg(&elf)
        .args(["-cpu", "max", "-m", "8M", "-nographic", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .output()
        .expect("spawn qemu");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("u2f-enclave: no vsock, halt"),
        "serial: {stdout}"
    );
    // isa-debug-exit: (code<<1)|1, qemu_exit(0) -> 1.
    assert_eq!(out.status.code(), Some(1), "qemu status");
}

#[test]
fn libfido2_sim() {
    let _g = serial_guard();
    if !need_writable("/dev/uhid") {
        return;
    }
    let be = sim_backend();
    fido2_roundtrip(&be.hidraw);
}

#[test]
fn libfido2_kernel() {
    let _g = serial_guard();
    if !need_writable("/dev/uhid") || !need_writable("/dev/vhost-vsock") {
        return;
    }
    let be = kernel_backend();
    fido2_roundtrip(&be.hidraw);
}

/// `ssh-keygen -t ecdsa-sk` drives makeCredential; the login drives
/// getAssertion and has sshd verify the signature — a second independent
/// client and verifier after libfido2.
#[test]
fn ssh_sim() {
    let _g = serial_guard();
    if !need_writable("/dev/uhid") {
        return;
    }
    let be = sim_backend();
    let tmp = Tmp::new("ssh");
    let port = "58022";

    run(Command::new("ssh-keygen")
        .args([
            "-t",
            "ecdsa-sk",
            "-N",
            "",
            "-O",
            "application=ssh:u2fe",
            "-f",
        ])
        .arg(tmp.join("id")));

    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(tmp.join("hostkey")));
    fs::copy(tmp.join("id.pub"), tmp.join("authorized_keys")).unwrap();
    fs::write(
        tmp.join("sshd_config"),
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\nPidFile {pid}\n\
             AuthorizedKeysFile {ak}\nPubkeyAuthentication yes\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             UsePAM no\nStrictModes no\n",
            hk = tmp.join("hostkey").display(),
            pid = tmp.join("sshd.pid").display(),
            ak = tmp.join("authorized_keys").display(),
        ),
    )
    .unwrap();

    // sshd refuses to run from a relative path.
    let mut sshd = Command::new(which("sshd"))
        .args(["-D", "-e", "-f"])
        .arg(tmp.join("sshd_config"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sshd");
    std::thread::sleep(std::time::Duration::from_millis(300));

    let user = std::env::var("USER").unwrap();
    let res = Command::new("ssh")
        .args(["-p", port, "-i"])
        .arg(tmp.join("id"))
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .arg(format!("{user}@127.0.0.1"))
        .arg("true")
        .output()
        .expect("spawn ssh");

    let _ = sshd.kill();
    let sshd_out = sshd.wait_with_output().unwrap();
    drop(be);

    assert!(
        res.status.success(),
        "ssh login failed: {}\nsshd: {}",
        String::from_utf8_lossy(&res.stderr),
        String::from_utf8_lossy(&sshd_out.stderr),
    );
}
