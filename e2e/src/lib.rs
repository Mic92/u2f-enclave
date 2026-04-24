//! Shared harness for the end-to-end smoke tests.
//!
//! These tests drive real external programs (libfido2, OpenSSH) against
//! the workspace binaries, so they need `/dev/uhid` and `/dev/vhost-vsock`
//! and cannot run in a sandboxed builder. Each test takes [`serial_guard`]
//! because they all share one uhid device name and one vsock CID.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, Once};
use std::time::{Duration, Instant};

static LOCK: Mutex<()> = Mutex::new(());

/// Tests share `/dev/uhid` (single device name) and the vsock CID, so they
/// must not overlap. Poison is ignored: one failing test should not cascade.
pub fn serial_guard() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn target_dir() -> PathBuf {
    // Honour CARGO_TARGET_DIR so the harness finds the same artifacts cargo
    // produced, regardless of where the test binary itself was placed.
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"))
}

fn cargo(args: &[&str]) {
    let st = Command::new(env!("CARGO"))
        .args(args)
        .current_dir(workspace_root())
        .status()
        .expect("spawn cargo");
    assert!(st.success(), "cargo {args:?} failed");
}

pub fn host_bin(name: &str) -> PathBuf {
    static ONCE: Once = Once::new();
    // vmm's build.rs cross-builds and embeds the enclave ELF.
    ONCE.call_once(|| {
        cargo(&[
            "build",
            "--release",
            "-p",
            "sim",
            "-p",
            "bridge",
            "-p",
            "vmm",
        ])
    });
    target_dir().join("release").join(name)
}

/// Per-test scratch dir under `$XDG_RUNTIME_DIR`; removed on drop.
pub struct Tmp(PathBuf);
impl Tmp {
    pub fn new(tag: &str) -> Self {
        let base = std::env::var_os("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR");
        let p = PathBuf::from(base).join(format!("u2fe-e2e-{tag}"));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn join(&self, s: &str) -> PathBuf {
        self.0.join(s)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Return `true` if `path` is openable for writing, otherwise print a SKIP
/// line. Tests early-return on `false` so `cargo test` still passes on
/// machines without the device ACLs; grep output for `SKIP` to notice.
pub fn need_writable(path: &str) -> bool {
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("SKIP: {path} not writable ({e}); see README for setfacl");
            false
        }
    }
}

pub fn run(cmd: &mut Command) -> Output {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    if !out.status.success() {
        panic!(
            "{:?} failed ({}):\nstdout: {}\nstderr: {}",
            cmd,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

pub fn which(bin: &str) -> PathBuf {
    std::env::var_os("PATH")
        .expect("PATH")
        .to_string_lossy()
        .split(':')
        .map(|d| Path::new(d).join(bin))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("{bin} not in PATH"))
}

fn find_hidraw() -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        for entry in fs::read_dir("/sys/class/hidraw")
            .into_iter()
            .flatten()
            .flatten()
        {
            let uevent = entry.path().join("device/uevent");
            if fs::read_to_string(&uevent)
                .map(|s| s.contains("HID_NAME=u2f-enclave"))
                .unwrap_or(false)
            {
                // Present is not the same as ready: wait for whoever sets
                // permissions (udev rule, ad-hoc watcher) to catch up.
                let dev = PathBuf::from("/dev").join(entry.file_name());
                if fs::OpenOptions::new().write(true).open(&dev).is_ok() {
                    return dev;
                }
            }
        }
        if Instant::now() > deadline {
            panic!("hidraw device for u2f-enclave not found within 3s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Kill-on-drop child set. Constructors push as they spawn so a panic during
/// bring-up (e.g. `find_hidraw` timing out) does not leak the vmm holding the
/// vsock CID.
#[derive(Default)]
pub struct Procs(Vec<Child>);
impl Procs {
    pub fn push(&mut self, c: Child) -> &mut Child {
        self.0.push(c);
        self.0.last_mut().unwrap()
    }
    pub fn spawn(&mut self, cmd: &mut Command) -> &mut Child {
        self.push(
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}")),
        )
    }
}
impl Drop for Procs {
    fn drop(&mut self) {
        for c in self.0.iter_mut().rev() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Let udev tear the hidraw node down before the next test creates one.
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub struct Backend {
    pub procs: Procs,
    pub hidraw: PathBuf,
    _tmp: Tmp,
}

pub fn sim_backend() -> Backend {
    let tmp = Tmp::new("sim");
    let sock = tmp.join("ctap.sock");
    let mut procs = Procs::default();
    procs.spawn(Command::new(host_bin("sim")).arg(&sock));
    std::thread::sleep(Duration::from_millis(200));
    procs.spawn(Command::new(host_bin("bridge")).arg(&sock));
    Backend {
        hidraw: find_hidraw(),
        procs,
        _tmp: tmp,
    }
}

pub fn vmm_backend() -> Backend {
    let tmp = Tmp::new("vmm");
    let mut procs = Procs::default();
    procs.spawn(Command::new(host_bin("vmm")).arg("42"));
    Backend {
        hidraw: find_hidraw(),
        procs,
        _tmp: tmp,
    }
}

/// libfido2 register → verify-attestation → assert → verify-signature.
/// Passing means our CTAPHID, CBOR, credential derivation and DER encoding
/// are accepted by an independent implementation end to end.
pub fn fido2_roundtrip(hidraw: &Path) {
    let tmp = Tmp::new("fido2");
    // Fixed challenge/user-id keep the test deterministic; randomness adds
    // nothing here because the authenticator supplies its own nonces.
    let chal = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let uid = "AQIDBAUGBwgJCgsMDQ4PEA==";

    run(Command::new("fido2-token").arg("-I").arg(hidraw));

    let cred_in = tmp.join("cred-in");
    fs::write(&cred_in, format!("{chal}\nexample.org\nsmoke\n{uid}\n")).unwrap();
    let cred_out = tmp.join("cred-out");
    run(Command::new("fido2-cred")
        .args(["-M", "-i"])
        .arg(&cred_in)
        .arg("-o")
        .arg(&cred_out)
        .arg(hidraw));
    let cred_pk = tmp.join("cred-pk");
    run(Command::new("fido2-cred")
        .args(["-V", "-i"])
        .arg(&cred_out)
        .arg("-o")
        .arg(&cred_pk));

    let cred_out_s = fs::read_to_string(&cred_out).unwrap();
    let cred_id = cred_out_s.lines().nth(4).expect("cred-out line 5");

    let assert_in = tmp.join("assert-in");
    fs::write(&assert_in, format!("{chal}\nexample.org\n{cred_id}\n")).unwrap();
    let assert_out = tmp.join("assert-out");
    run(Command::new("fido2-assert")
        .args(["-G", "-i"])
        .arg(&assert_in)
        .arg("-o")
        .arg(&assert_out)
        .arg(hidraw));
    run(Command::new("fido2-assert")
        .args(["-V", "-i"])
        .arg(&assert_out)
        .arg(&cred_pk)
        .arg("es256"));
}
