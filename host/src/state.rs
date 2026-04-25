//! `--snp` on-disk state: the sealed master plus everything a *future*
//! binary needs to relaunch *this* guest and recover that master.

use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::{env, fs};

use crate::snp_report::{cert_p384_pubkey, Report, REPORT_LEN};

pub const SEALED_LEN: usize = 60;
const MAGIC: &[u8; 4] = b"U2FE";
const VERSION: u32 = 1;

// Prelude byte 0; mirrored in `guest/src/seal.rs`.
pub const FL_UNSEAL: u8 = 1;
pub const FL_DONOR: u8 = 2;
pub const ST_FRESH: u8 = 0;
pub const ST_UNSEALED: u8 = 1;
pub const ST_UNSEAL_FAILED: u8 = 2;
pub const ST_HANDOFF_OK: u8 = 3;

const HELLO_LEN: usize = 65 + REPORT_LEN; // matches guest/src/handoff.rs
const HELLO_REPORTS: usize = HELLO_LEN.div_ceil(64);
const VCEK_REPORTS: usize = 97usize.div_ceil(64);

pub struct StateFile {
    pub sealed: [u8; SEALED_LEN],
    pub elf: Vec<u8>,
    pub idb: [u8; 96],
    pub ida: Box<[u8; 4096]>,
}

pub fn path() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| ".".into())
        .join("u2f-enclave")
        .join("snp.state")
}

pub fn read(p: &Path) -> io::Result<Option<StateFile>> {
    let buf = match fs::read(p) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bad = || {
        io::Error::other(format!(
            "{}: bad magic/version/layout (use --fresh to discard)",
            p.display()
        ))
    };
    if buf.len() < 72 || &buf[..4] != MAGIC || buf[4..8] != VERSION.to_le_bytes() {
        return Err(bad());
    }
    let sealed = buf[8..68].try_into().unwrap();
    let elen = u32::from_le_bytes(buf[68..72].try_into().unwrap()) as usize;
    let e = 72 + elen;
    if buf.len() != e + 96 + 4096 {
        return Err(bad());
    }
    Ok(Some(StateFile {
        sealed,
        elf: buf[72..e].to_vec(),
        idb: buf[e..e + 96].try_into().unwrap(),
        ida: Box::new(buf[e + 96..].try_into().unwrap()),
    }))
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
/// On `ST_UNSEAL_FAILED` (binary changed) drives the attested handover.
pub fn prelude(s: &mut (impl Read + Write)) -> io::Result<()> {
    let p = path();
    let prior = read(&p)?;
    let force = env::var_os("U2FE_FORCE_HANDOFF").is_some();
    let mut buf = [0u8; 64];
    if let Some(st) = &prior {
        buf[0] = FL_UNSEAL;
        // Garbage so unseal fails: tests the handover with one binary.
        buf[4..64].copy_from_slice(if force {
            &[0xff; SEALED_LEN]
        } else {
            &st.sealed
        });
    }
    s.write_all(&buf)?;
    s.read_exact(&mut buf)?;
    let had_prior = prior.is_some();
    if buf[0] == ST_UNSEAL_FAILED {
        // Do not touch snp.state until the handover concludes — a crash or
        // missing VCEK leaves the old file intact for retry.
        handoff(s)?;
        s.read_exact(&mut buf)?;
    }
    match buf[0] {
        ST_UNSEALED => {}
        ST_FRESH if !had_prior && !force => {
            eprintln!("u2f-enclave: fresh SNP master key (no prior state)")
        }
        ST_HANDOFF_OK => eprintln!("u2f-enclave: master key recovered via attested handover"),
        ST_FRESH => eprintln!(
            "u2f-enclave: WARNING: handover failed — previously registered \
             credentials are lost; generated a fresh key"
        ),
        s => return Err(io::Error::other(format!("guest prelude status {s}"))),
    }
    write(&p, buf[4..64].try_into().unwrap())?;
    eprintln!("u2f-enclave: state → {}", p.display());
    Ok(())
}

/// Guest's `read_report` resets the connection on `hdr.len != 64`, so every
/// write to the recipient's vsock must be exactly one 64-byte `write()`.
fn write_reports(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let mut buf = [0u8; 64];
    for c in data.chunks(64) {
        buf.fill(0);
        buf[..c.len()].copy_from_slice(c);
        w.write_all(&buf)?;
    }
    Ok(())
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Relay the mutual-attestation handshake between the recipient (`r`, our
/// own SNP guest) and a donor child process running the *previous* guest
/// from `snp.state`.  The host is a dumb pipe here — every check that
/// matters happens inside the two encrypted guests.
fn handoff(r: &mut (impl Read + Write)) -> io::Result<()> {
    // Recipient sends its hello first so we can look up the VCEK from the
    // report's chip_id/TCB without a /dev/sev round-trip.
    let mut hello_r = [0u8; HELLO_REPORTS * 64];
    r.read_exact(&mut hello_r)?;
    let rep_r: &[u8; REPORT_LEN] = hello_r[65..65 + REPORT_LEN].try_into().unwrap();
    let vcek = crate::verify::find_vcek(&Report(rep_r))
        .and_then(|d| cert_p384_pubkey(&d).ok_or_else(|| "VCEK has no P-384 key".into()));
    let vcek: [u8; 97] = match vcek {
        Ok(k) => k,
        // Exit nonzero, snp.state untouched: user can place the cert and retry.
        Err(e) => return Err(io::Error::other(format!("handover needs VCEK: {e}"))),
    };

    eprintln!("u2f-enclave: binary changed; launching previous guest as handover donor");
    let mut donor = KillOnDrop(
        Command::new(env::current_exe()?)
            .arg("--donor")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let mut din = donor.0.stdin.take().unwrap();
    let mut dout = donor.0.stdout.take().unwrap();

    let mut buf = [0u8; 64];
    let abort = |r: &mut dyn Write, why: &str| {
        eprintln!("u2f-enclave: handover aborted: {why}");
        r.write_all(&[0u8; 64]) // mode=0 → recipient goes fresh
    };

    // Donor child first emits the prelude status — did the old guest unseal?
    dout.read_exact(&mut buf)?;
    if buf[0] != ST_UNSEALED {
        return abort(r, "donor could not unseal (state file corrupt?)");
    }
    write_reports(&mut din, &vcek)?;
    din.write_all(&hello_r)?;
    din.flush()?;

    dout.read_exact(&mut buf)?;
    if buf[0] != 1 {
        return abort(r, "donor refused recipient (downgrade or signer mismatch)");
    }
    let mut hello_d = [0u8; HELLO_REPORTS * 64];
    dout.read_exact(&mut hello_d)?;
    let mut wrapped = [0u8; 64];
    dout.read_exact(&mut wrapped)?;

    r.write_all(&[1u8; 64])?; // mode=1
    write_reports(r, &vcek)?;
    write_reports(r, &hello_d[..HELLO_LEN])?;
    r.write_all(&wrapped)?;
    Ok(())
}

/// `--donor` (internal): vsock↔stdio relay so the parent process can speak
/// to the relaunched old guest without a second AF_VSOCK client.
pub fn donor_relay(s: &mut (impl Read + Write), sealed: &[u8; SEALED_LEN]) -> io::Result<()> {
    let mut buf = [0u8; 64];
    buf[0] = FL_DONOR;
    buf[4..64].copy_from_slice(sealed);
    s.write_all(&buf)?;
    s.read_exact(&mut buf)?;
    let mut out = io::stdout().lock();
    out.write_all(&buf)?;
    out.flush()?;
    if buf[0] != ST_UNSEALED {
        return Ok(());
    }
    // Fixed counts (host orchestrator knows the protocol): in = vcek + hello,
    // out = ok? + (hello + wrapped).  Sequential, so no relay threads.
    for _ in 0..VCEK_REPORTS + HELLO_REPORTS {
        io::stdin().read_exact(&mut buf)?;
        s.write_all(&buf)?;
    }
    s.read_exact(&mut buf)?;
    out.write_all(&buf)?;
    if buf[0] == 1 {
        for _ in 0..HELLO_REPORTS + 1 {
            s.read_exact(&mut buf)?;
            out.write_all(&buf)?;
        }
    }
    out.flush()
}
