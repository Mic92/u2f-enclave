//! Bridge: expose the remote authenticator as a local HID device.
//!
//! Runs in the *consumer* VM. Connects to the authenticator (Unix socket for
//! the simulator, AF_VSOCK for the real enclave — TODO) and registers a
//! virtual FIDO HID device via `/dev/uhid`. Browsers and `libfido2` then see
//! a regular `/dev/hidraw*` node.

#[cfg(target_os = "linux")]
mod uhid;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    const REPORT_SIZE: usize = 64;

    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let dir = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .expect("XDG_RUNTIME_DIR not set; pass an explicit socket path");
            dir.join("u2f-enclave.sock")
        });

    let sock = UnixStream::connect(&path)?;
    eprintln!("bridge: connected to {}", path.display());
    let dev = uhid::Uhid::create("u2f-enclave")?;
    eprintln!("bridge: /dev/uhid device created");

    // socket → uhid (device INPUT reports)
    let mut sock_r = sock.try_clone()?;
    let mut dev_w = dev.try_clone()?;
    std::thread::spawn(move || {
        let mut buf = [0u8; REPORT_SIZE];
        loop {
            if sock_r.read_exact(&mut buf).is_err() {
                eprintln!("bridge: authenticator disconnected");
                std::process::exit(1);
            }
            if let Err(e) = dev_w.write_input(&buf) {
                eprintln!("bridge: uhid write: {e}");
                std::process::exit(1);
            }
        }
    });

    // uhid OUTPUT → socket
    let mut sock_w = sock;
    let mut dev_r = dev;
    loop {
        let data = dev_r.read_output()?;
        // The FIDO descriptor has no report ID, so the kernel hands us the
        // raw 64-byte report. Normalise defensively in case a stack prepends
        // a zero ID byte.
        let report: [u8; REPORT_SIZE] = match data.len() {
            REPORT_SIZE => data.as_slice().try_into().unwrap(),
            n if n == REPORT_SIZE + 1 && data[0] == 0 => data[1..].try_into().unwrap(),
            n => {
                eprintln!("bridge: unexpected OUTPUT size {n}, dropping");
                continue;
            }
        };
        sock_w.write_all(&report)?;
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bridge: /dev/uhid is Linux-only");
    std::process::exit(1);
}
