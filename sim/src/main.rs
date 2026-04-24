//! Host-side stand-in for the SEV-SNP unikernel.
//!
//! Listens on a Unix stream socket and speaks raw 64-byte CTAPHID reports.
//! The real enclave will listen on AF_VSOCK instead; the wire format is
//! identical so `bridge` works against either.

use ctap::{Authenticator, Platform, Report, AAGUID, HID_REPORT_SIZE};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

/// Per-user, mode-0700 socket location. Avoids the symlink/squatting races a
/// fixed `/tmp` path would invite.
fn default_socket() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .expect("XDG_RUNTIME_DIR not set; pass an explicit socket path");
    dir.join("u2f-enclave.sock")
}

struct OsRandom;
impl Platform for OsRandom {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("getrandom");
    }
}

fn main() -> std::io::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_socket);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    eprintln!("sim: listening on {}", path.display());

    for stream in listener.incoming() {
        let mut stream = stream?;
        eprintln!("sim: client connected");
        let mut auth = Authenticator::new(OsRandom, AAGUID);
        let mut buf: Report = [0u8; HID_REPORT_SIZE];
        loop {
            if let Err(e) = stream.read_exact(&mut buf) {
                eprintln!("sim: client gone: {e}");
                break;
            }
            for r in auth.process_report(&buf) {
                stream.write_all(&r)?;
            }
        }
    }
    Ok(())
}
