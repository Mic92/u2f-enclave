use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use e2e::*;

/// SEV-SNP encrypted launch end-to-end: own VMM, no firmware. The guest
/// brings up a GHCB page (PVALIDATE + MSR-protocol PSC + GPA registration)
/// and prints to serial via paravirt IOIO — no `#VC` handler at all.
#[test]
fn snp_boot() {
    let _g = serial_guard();
    // `/dev/sev` existing isn't sufficient: SNP can be off in BIOS or via
    // module param while the PSP device is still there.
    if !need_writable("/dev/kvm")
        || !need_writable("/dev/sev")
        || fs::read_to_string("/sys/module/kvm_amd/parameters/sev_snp")
            .map(|s| s.trim() != "Y")
            .unwrap_or(true)
    {
        return;
    }
    // Bounded wait: a wedged guest would otherwise hang the whole suite.
    let mut procs = Procs::default();
    let child = procs.push(
        Command::new(host_bin("vmm"))
            .arg("--snp")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vmm"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(Instant::now() < deadline, "snp guest did not terminate");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    use std::io::Read;
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .ok();
    // 0x77 = sev::TERM_BOOT_OK; the banner is printed *from inside encrypted
    // memory* via GHCB IOIO and surfaces as plain KVM_EXIT_IO in the vmm.
    assert!(
        st.code() == Some(0x77)
            && stderr.contains("SEV-SNP launch ok")
            && stderr.contains("u2f-enclave: SEV-SNP active, GHCB up"),
        "status={st:?}\nstderr: {stderr}"
    );
}

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
    let be = vmm_backend();
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
