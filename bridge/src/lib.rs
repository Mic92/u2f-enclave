//! Expose a remote CTAP-HID stream as a local `/dev/hidraw*` via `/dev/uhid`.
//!
//! Shipped as a lib so the standalone `bridge` binary (consumer-VM use case)
//! and the all-in-one `vmm` (host use case) share the exact same loop.

#![cfg(target_os = "linux")]

use std::io::{self, Read, Write};

mod uhid;

const REPORT_SIZE: usize = 64;

/// Shuttle 64-byte reports between the authenticator stream and a freshly
/// created uhid device. Spawns one thread for the inbound direction; never
/// returns on success (call from a dedicated thread or as the main loop).
pub fn serve<R, W>(mut sock_r: R, mut sock_w: W) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write,
{
    let dev = uhid::Uhid::create("u2f-enclave")?;
    eprintln!("bridge: /dev/uhid device created");

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
