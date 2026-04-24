//! `ctap::Platform` for the bare-metal target.

use alloc::vec::Vec;
use core::arch::x86_64::_rdrand64_step;

use crate::{greq, sev, tdx};

#[derive(Clone, Copy)]
enum Coco {
    Snp,
    Tdx,
}

pub struct BareMetal {
    master: [u8; 32],
    coco: Option<Coco>,
}

impl BareMetal {
    pub fn new() -> Self {
        if sev::active() {
            // Survives restarts; see `greq::derived_key`.
            if let Some(master) = greq::derived_key() {
                crate::serial::print("u2f-enclave: PSP-derived master key\n");
                return Self {
                    master,
                    coco: Some(Coco::Snp),
                };
            }
            crate::serial::print("u2f-enclave: MSG_KEY_REQ failed; ephemeral key\n");
        }
        // TDX has no firmware key-derive, so the master key is ephemeral
        // (same as a plain VM); registrations still get a TDREPORT.
        let mut master = [0u8; 32];
        fill_rdrand(&mut master);
        Self {
            master,
            coco: if sev::active() {
                Some(Coco::Snp)
            } else if tdx::active() {
                Some(Coco::Tdx)
            } else {
                None
            },
        }
    }
}

impl ctap::Platform for BareMetal {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        fill_rdrand(buf);
    }
    fn master_secret(&self) -> [u8; 32] {
        self.master
    }
    fn attestation(&mut self, rd: &[u8; 64]) -> Option<(&'static str, Vec<u8>)> {
        match self.coco? {
            Coco::Snp => greq::report(rd).map(|r| ("snp", r.to_vec())),
            Coco::Tdx => tdx::report(rd).map(|r| ("tdx", r.to_vec())),
        }
    }
}

/// RDRAND's DRNG is on-die and not hypervisor-mediated, so it is inside the
/// trust boundary on both SEV-SNP and TDX.
fn fill_rdrand(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut v = 0u64;
        // Retry on transient underflow; the SDM bounds this at a handful of
        // iterations in practice.
        while unsafe { _rdrand64_step(&mut v) } != 1 {}
        chunk.copy_from_slice(&v.to_ne_bytes()[..chunk.len()]);
    }
}
