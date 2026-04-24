//! Bridge: expose the remote authenticator as a local HID device.
//!
//! Runs in the *consumer* VM. Connects to the authenticator over a Unix
//! socket (simulator) or AF_VSOCK (`vsock:CID:PORT`, real enclave) and
//! registers a virtual FIDO HID device via `/dev/uhid`. Browsers and
//! `libfido2` then see a regular `/dev/hidraw*` node.

#[cfg(target_os = "linux")]
mod uhid;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use vsock::{VsockAddr, VsockStream};

    const REPORT_SIZE: usize = 64;

    let arg = std::env::args().nth(1);
    let (mut sock_r, mut sock_w): (Box<dyn Read + Send>, Box<dyn Write + Send>) =
        match arg.as_deref() {
            Some(a) if a.starts_with("vsock:") => {
                let rest = &a[6..];
                let (cid, port) = rest.split_once(':').expect("vsock:<cid>:<port>");
                let cid: u32 = cid.parse().expect("vsock cid");
                let port: u32 = port.parse().expect("vsock port");
                let s = VsockStream::connect(&VsockAddr::new(cid, port))?;
                eprintln!("bridge: connected to vsock:{cid}:{port}");
                (Box::new(s.try_clone()?), Box::new(s))
            }
            other => {
                let path = other.map(PathBuf::from).unwrap_or_else(|| {
                    let dir = std::env::var_os("XDG_RUNTIME_DIR")
                        .map(PathBuf::from)
                        .expect("XDG_RUNTIME_DIR not set; pass an explicit socket path");
                    dir.join("u2f-enclave.sock")
                });
                let s = UnixStream::connect(&path)?;
                eprintln!("bridge: connected to {}", path.display());
                (Box::new(s.try_clone()?), Box::new(s))
            }
        };

    let dev = uhid::Uhid::create("u2f-enclave")?;
    eprintln!("bridge: /dev/uhid device created");

    // socket → uhid (device INPUT reports)
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
    let mut dev_r = dev;
    loop {
        let data = dev_r.read_output()?;
        // Linux hidraw write() always carries the report-ID byte (0 here);
        // hidraw_send_report() forwards it verbatim to uhid, so the common
        // case is 65 bytes. Accept a bare 64 too for callers that bypass
        // hidraw.
        let report: [u8; REPORT_SIZE] = match data.len() {
            n if n == REPORT_SIZE + 1 && data[0] == 0 => data[1..].try_into().unwrap(),
            REPORT_SIZE => data.as_slice().try_into().unwrap(),
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
