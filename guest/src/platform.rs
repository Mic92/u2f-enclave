//! `ctap::Platform` for the bare-metal target.

use alloc::vec::Vec;
use core::arch::x86_64::_rdrand64_step;

use crate::{greq, sev};

pub struct BareMetal {
    master: [u8; 32],
    snp: bool,
}

impl BareMetal {
    pub fn new(master: [u8; 32]) -> Self {
        Self {
            master,
            snp: sev::active(),
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
        if self.snp {
            greq::report(rd).map(|r| ("snp", r.to_vec()))
        } else {
            None
        }
    }
}

/// RDRAND's DRNG is on-die and not hypervisor-mediated, so it is inside the
/// SEV-SNP trust boundary.
pub fn fill_rdrand(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut v = 0u64;
        // Retry on transient underflow; the SDM bounds this at a handful of
        // iterations in practice.
        while unsafe { _rdrand64_step(&mut v) } != 1 {}
        chunk.copy_from_slice(&v.to_ne_bytes()[..chunk.len()]);
    }
}
