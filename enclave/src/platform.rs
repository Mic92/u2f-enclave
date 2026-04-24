//! `ctap::Platform` for the bare-metal target.

use core::arch::x86_64::_rdrand64_step;

pub struct BareMetal {
    master: [u8; 32],
}

impl BareMetal {
    pub fn new() -> Self {
        // TODO(M2): the real master secret is released by the attestation
        // verifier after checking the SNP launch measurement. Until then,
        // derive an ephemeral one so the authenticator is functional.
        let mut master = [0u8; 32];
        fill_rdrand(&mut master);
        Self { master }
    }
}

impl ctap::Platform for BareMetal {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        fill_rdrand(buf);
    }
    fn master_secret(&self) -> [u8; 32] {
        self.master
    }
}

/// RDRAND is inside the SEV-SNP trust boundary (the DRNG is on-die and not
/// hypervisor-mediated), so it is an acceptable entropy source here.
fn fill_rdrand(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut v = 0u64;
        // Retry on transient underflow; the SDM bounds this at a handful of
        // iterations in practice.
        while unsafe { _rdrand64_step(&mut v) } != 1 {}
        chunk.copy_from_slice(&v.to_ne_bytes()[..chunk.len()]);
    }
}
