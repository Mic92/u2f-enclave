use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use e2e::*;

/// The actual deployable: single binary, embedded guest, own KVM launcher,
/// own vhost-vsock backend, own uhid bridge. No QEMU, no firmware.
#[test]
fn libfido2_vmm() {
    let _g = serial_guard();
    if !need_writable("/dev/uhid")
        || !need_writable("/dev/vhost-vsock")
        || !need_writable("/dev/kvm")
    {
        return;
    }
    let be = vmm_backend(false);
    fido2_roundtrip(&be.hidraw);
}

/// TDX encrypted launch: reset stub at 4 GiB-16, ram32_tdx, paravirt port
/// I/O via TDVMCALL. The guest halts after printing its banner.
#[test]
fn tdx_boot() {
    let _g = serial_guard();
    if !need_writable("/dev/kvm") || !have_tdx() {
        return;
    }
    let mut procs = Procs::default();
    let child = procs.push(
        Command::new(host_bin("u2f-enclave"))
            .arg("--tdx")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // The pipe read blocks; bound the test by killing the child if it
    // hasn't exited (the guest's debug_exit normally does).
    let pid = child.id();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    });
    let mut err = child.stderr.take().unwrap();
    let mut out = String::new();
    let mut buf = [0u8; 256];
    while let Ok(n @ 1..) = err.read(&mut buf) {
        out.push_str(&String::from_utf8_lossy(&buf[..n]));
        eprint!("{}", String::from_utf8_lossy(&buf[..n]));
        if out.contains("TDX active, paravirt up") {
            return;
        }
    }
    panic!("guest never printed TDX banner; output:\n{out}");
}

/// Full SEV-SNP path end to end: encrypted launch, GHCB up, virtio-mmio via
/// GHCB, virtqueue rings PSC'd shared, vhost-vsock data path, uhid bridge,
/// libfido2 register/assert/verify. No firmware, no `#VC` handler.
///
/// Then, acting as an SNP-aware relying party: pull the attestation report
/// out of attStmt and check its `report_data` binds the credential.
#[test]
fn libfido2_vmm_snp() {
    let _g = serial_guard();
    if !need_writable("/dev/uhid")
        || !need_writable("/dev/vhost-vsock")
        || !need_writable("/dev/kvm")
        || !have_snp()
    {
        return;
    }
    let be = vmm_backend(true);
    fido2_roundtrip(&be.hidraw);

    let cdh = [0x11u8; 32];
    let (ad, rep) = snp::make_credential(&be.hidraw, &cdh, "example.org");

    // Documented user flow: vcek-url → curl → verify --vcek.
    let url = pipe(Command::new(host_bin("u2f-enclave")).arg("vcek-url"), &rep);
    let url = String::from_utf8(url.stdout).unwrap().trim().to_string();
    let tmp = Tmp::new("snp");
    let vcek = tmp.join("vcek.der");
    if !Command::new("curl")
        .args(["-fsSo", vcek.to_str().unwrap(), &url])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: curl {url} failed (AMD KDS unreachable)");
        return;
    }

    // The relying-party check is `u2f-enclave verify` itself: VCEK signature,
    // and predictor==PSP for the measurement (a KVM VMSA change shows up as
    // exit 1 here, not silent drift). It prints report_data; we do the
    // binding check it leaves to the caller.
    let out = pipe(
        Command::new(host_bin("u2f-enclave"))
            .arg("verify")
            .arg("--vcek")
            .arg(&vcek)
            .stderr(std::process::Stdio::inherit()),
        &rep,
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    eprint!("{stdout}");
    assert!(out.status.success(), "u2f-enclave verify failed");

    let mut h = sha2::Sha512::default();
    use sha2::Digest;
    h.update(&ad);
    h.update(cdh);
    let want_rd: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        stdout.contains(&want_rd),
        "report_data does not bind authData||cdh"
    );

    // Second launch: launch-1's credId still resolves, i.e. the
    // PSP-derived master key is in fact stable.
    let m1 = rep[0x90..0xc0].to_vec();
    drop(be);
    let be = vmm_backend(true);
    let (_, rep2) = snp::make_credential(&be.hidraw, &cdh, "example.org");
    assert_eq!(
        &rep2[0x90..0xc0],
        m1,
        "measurement not stable across launches"
    );
    assert_eq!(
        snp::get_assertion(&be.hidraw, &cdh, "example.org", snp::cred_id(&ad)),
        0,
        "launch-1 credential did not resolve after relaunch"
    );
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
    let mut be = sim_backend();
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
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\n\
             PidFile {d}/sshd.pid\nAuthorizedKeysFile {d}/authorized_keys\n\
             PubkeyAuthentication yes\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\n",
            d = tmp.path().display(),
        ),
    )
    .unwrap();

    // sshd refuses to run from a relative path; reap via the backend so a
    // failing ssh-login panic does not leak it.
    be.procs.spawn(
        Command::new(which("sshd"))
            .args(["-D", "-f"])
            .arg(tmp.join("sshd_config")),
    );
    std::thread::sleep(std::time::Duration::from_millis(300));

    let user = std::env::var("USER").unwrap();
    run(Command::new("ssh")
        .args(["-p", port, "-i"])
        .arg(tmp.join("id"))
        .args(["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .arg(format!("{user}@127.0.0.1"))
        .arg("true"));
}
