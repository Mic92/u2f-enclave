use std::fs;
use std::process::Command;

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
    let rep = snp::Report(&rep);
    snp::check_binding(&ad, &cdh, &rep);
    eprintln!(
        "snp: v{} measurement={} chip_id={} tcb={:#x}",
        rep.version(),
        hex(rep.measurement()),
        hex(&rep.chip_id()[..8]),
        rep.reported_tcb(),
    );

    let m1 = rep.measurement().to_vec();
    let vcek = snp::fetch_vcek(&rep, std::path::Path::new("target/vcek-cache"));
    if let Some(vcek) = &vcek {
        snp::verify_signature(&rep, vcek);
        eprintln!("snp: VCEK signature ok");
    }

    // Second launch: assert the measurement is byte-identical. That plus the
    // PSP's deterministic KDF is the credential-persistence guarantee, and it
    // sidesteps reproducing KVM's VMSA byte-for-byte.
    drop(be);
    let be = vmm_backend(true);
    let (_, rep2) = snp::make_credential(&be.hidraw, &cdh, "example.org");
    let rep2 = snp::Report(&rep2);
    assert_eq!(
        rep2.measurement(),
        m1,
        "measurement not stable across launches"
    );
    if let Some(vcek) = &vcek {
        snp::verify_signature(&rep2, vcek);
    }
    fido2_roundtrip(&be.hidraw);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
