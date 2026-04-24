//! Host-side stand-in for the SEV-SNP unikernel.
//!
//! Speaks raw 64-byte CTAPHID reports over either a Unix stream socket
//! (default, for local dev) or AF_VSOCK (`vsock:PORT`), which is the exact
//! transport the real guest uses. The wire format is identical so `bridge`
//! works against any of the three: this simulator, a loopback vsock, or the
//! guest.

use ctap::{Authenticator, Platform, Report, AAGUID, HID_REPORT_SIZE};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

struct Host {
    master: [u8; 32],
}
impl Platform for Host {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("getrandom");
    }
    fn master_secret(&self) -> [u8; 32] {
        self.master
    }
}

enum Endpoint {
    Unix(PathBuf),
    #[cfg(target_os = "linux")]
    Vsock(u32),
}

fn parse_endpoint() -> Endpoint {
    match std::env::args().nth(1) {
        #[cfg(target_os = "linux")]
        Some(a) if a.starts_with("vsock:") => {
            let port: u32 = a[6..].parse().expect("vsock:<port>");
            Endpoint::Vsock(port)
        }
        Some(a) => Endpoint::Unix(PathBuf::from(a)),
        None => {
            let dir = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .expect("XDG_RUNTIME_DIR not set; pass an explicit socket path");
            Endpoint::Unix(dir.join("u2f-enclave.sock"))
        }
    }
}

fn serve<S: Read + Write>(mut stream: S, master: [u8; 32]) {
    let mut auth = Authenticator::new(Host { master }, AAGUID);
    let mut buf: Report = [0u8; HID_REPORT_SIZE];
    loop {
        if let Err(e) = stream.read_exact(&mut buf) {
            eprintln!("sim: client gone: {e}");
            return;
        }
        for r in auth.process_report(&buf) {
            if let Err(e) = stream.write_all(&r) {
                eprintln!("sim: write failed: {e}");
                return;
            }
        }
    }
}

fn main() -> io::Result<()> {
    // Ephemeral per-process secret: registrations only survive as long as the
    // simulator does, which is exactly the isolation guarantee we want for a
    // host-side stand-in. The real guest provisions this via attestation.
    let mut master = [0u8; 32];
    getrandom::getrandom(&mut master).expect("getrandom");

    match parse_endpoint() {
        Endpoint::Unix(path) => {
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path)?;
            eprintln!("sim: listening on {}", path.display());
            for stream in listener.incoming() {
                eprintln!("sim: client connected");
                serve(stream?, master);
            }
        }
        #[cfg(target_os = "linux")]
        Endpoint::Vsock(port) => {
            let addr = vsock::VsockAddr::new(vsock::VMADDR_CID_ANY, port);
            let listener = vsock::VsockListener::bind(&addr)?;
            eprintln!("sim: listening on vsock:*:{port}");
            for stream in listener.incoming() {
                let stream = stream?;
                eprintln!("sim: client connected from {:?}", stream.peer_addr().ok());
                serve(stream, master);
            }
        }
    }
    Ok(())
}
