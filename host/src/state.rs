//! `--snp` on-disk state: the sealed master plus everything a *future*
//! binary needs to relaunch *this* guest and recover that master.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const SEALED_LEN: usize = 60;
const MAGIC: &[u8; 4] = b"U2FE";
const VERSION: u32 = 1;

// Prelude reply byte 0; mirrored in `guest/src/seal.rs`.
pub const ST_FRESH: u8 = 0;
pub const ST_UNSEALED: u8 = 1;
pub const ST_UNSEAL_FAILED: u8 = 2;

pub fn path() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| ".".into())
        .join("u2f-enclave")
        .join("snp.state")
}

/// Only the sealed blob is read back here; the rest of the file is for the
/// upgrade path.
pub fn read_sealed(p: &Path) -> io::Result<Option<[u8; SEALED_LEN]>> {
    let mut f = match fs::File::open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut hdr = [0u8; 8 + SEALED_LEN];
    f.read_exact(&mut hdr)?;
    if &hdr[..4] != MAGIC || hdr[4..8] != VERSION.to_le_bytes() {
        return Err(io::Error::other(format!(
            "{}: bad magic/version (use --fresh to discard)",
            p.display()
        )));
    }
    Ok(Some(hdr[8..].try_into().unwrap()))
}

/// Atomic replace so a crash mid-write can't leave a half-file that the next
/// launch then tries to feed the guest.
pub fn write(p: &Path, sealed: &[u8; SEALED_LEN]) -> io::Result<()> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("state.tmp");
    // KEK is per chip+binary, not per uid, so file mode is the only per-user
    // boundary.  .mode = born 0600; O_NOFOLLOW refuses a planted symlink;
    // truncate reuses a crash-left tmp.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(MAGIC)?;
    f.write_all(&VERSION.to_le_bytes())?;
    f.write_all(sealed)?;
    f.write_all(&(crate::GUEST_ELF.len() as u32).to_le_bytes())?;
    f.write_all(crate::GUEST_ELF)?;
    f.write_all(crate::snp::ID_BLOCK)?;
    f.write_all(crate::snp::ID_AUTH)?;
    f.sync_all()?;
    fs::rename(&tmp, p)
}

/// Runs on the bridge thread once the vsock is up: hand the prior sealed
/// blob (if any) to the guest, take the freshly sealed one back, persist.
pub fn prelude(s: &mut (impl Read + Write)) -> io::Result<()> {
    let p = path();
    let prior = read_sealed(&p)?;
    let mut buf = [0u8; 64];
    if let Some(b) = prior {
        buf[0] = 1;
        buf[4..64].copy_from_slice(&b);
    }
    s.write_all(&buf)?;
    s.read_exact(&mut buf)?;
    match buf[0] {
        ST_UNSEALED => {}
        ST_FRESH => eprintln!("u2f-enclave: fresh SNP master key (no prior state)"),
        ST_UNSEAL_FAILED => eprintln!(
            "u2f-enclave: WARNING: could not unseal prior master — previously \
             registered credentials are lost; generated a fresh key"
        ),
        s => return Err(io::Error::other(format!("guest prelude status {s}"))),
    }
    write(&p, buf[4..64].try_into().unwrap())?;
    eprintln!("u2f-enclave: state → {}", p.display());
    Ok(())
}
