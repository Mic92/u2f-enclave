//! Standalone bridge: parse the endpoint, connect, hand the stream to
//! `bridge::serve`. Kept for the consumer-VM scenario where the VMM lives
//! on a different host.

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use vsock::{VsockAddr, VsockStream};

    let arg = std::env::args().nth(1);
    let (r, w): (Box<dyn Read + Send>, Box<dyn Write>) = match arg.as_deref() {
        Some(a) if a.starts_with("vsock:") => {
            let (cid, port) = a[6..].split_once(':').expect("vsock:<cid>:<port>");
            let s = VsockStream::connect(&VsockAddr::new(
                cid.parse().expect("cid"),
                port.parse().expect("port"),
            ))?;
            eprintln!("bridge: connected to {a}");
            (Box::new(s.try_clone()?), Box::new(s))
        }
        other => {
            let path = other.map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR"))
                    .join("u2f-enclave.sock")
            });
            let s = UnixStream::connect(&path)?;
            eprintln!("bridge: connected to {}", path.display());
            (Box::new(s.try_clone()?), Box::new(s))
        }
    };
    bridge::serve(r, w)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bridge: /dev/uhid is Linux-only");
    std::process::exit(1);
}
