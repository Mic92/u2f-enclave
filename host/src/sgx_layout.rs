//! ELF→EPC layout, shared between `build.rs` (build-time MRENCLAVE/SIGSTRUCT)
//! and the runtime loader via `#[path]`-include.  Kept dependency-free so it
//! compiles in both crate roots; any drift would make EINIT reject.
#![allow(dead_code)]

pub const PAGE: u64 = 4096;

pub const SECINFO_R: u64 = 1;
pub const SECINFO_W: u64 = 2;
pub const SECINFO_X: u64 = 4;
pub const SECINFO_TCS: u64 = 1 << 8;
pub const SECINFO_REG: u64 = 2 << 8;

pub const ATTR_DEBUG: u64 = 1 << 1;
pub const ATTR_MODE64BIT: u64 = 1 << 2;
pub const XFRM_LEGACY: u64 = 0x3; // x87 + SSE; mandatory floor

#[repr(C, align(4096))]
pub struct AlignedPage(pub [u8; 4096]);

pub struct Seg {
    pub off: u64,
    pub len: u64,
    /// SECINFO flags. Low bits {R,W,X} share positions with `PROT_*`, so
    /// `(flags & 7) as c_int` is the mmap prot for REG segments.
    pub flags: u64,
}

/// Lay the ELF (linked at 0, p_vaddr == enclave offset) into a fresh
/// page-aligned image and derive per-segment SECINFO from p_flags.
pub fn layout(elf: &[u8]) -> (Vec<Seg>, Box<[AlignedPage]>) {
    let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    let phentsz = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;

    // Compute total span first so the image buffer can be sized once.
    let mut hi = 0u64;
    for i in 0..phnum {
        let ph = &elf[phoff + i * phentsz..];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 1 {
            continue; // PT_LOAD only
        }
        let va = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
        hi = hi.max((va + memsz).next_multiple_of(PAGE));
    }
    let mut img = (0..hi / PAGE)
        .map(|_| AlignedPage([0; 4096]))
        .collect::<Box<[_]>>();
    let bytes = unsafe { std::slice::from_raw_parts_mut(img.as_mut_ptr() as *mut u8, hi as usize) };

    let mut segs = Vec::new();
    for i in 0..phnum {
        let ph = &elf[phoff + i * phentsz..];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 1 {
            continue;
        }
        let pf = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        let foff = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let va = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        let filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());

        bytes[va as usize..va as usize + filesz].copy_from_slice(&elf[foff..foff + filesz]);

        // First segment is the TCS by linker-script convention.
        let flags = if segs.is_empty() {
            SECINFO_TCS
        } else {
            SECINFO_REG
                | (if pf & 4 != 0 { SECINFO_R } else { 0 })
                | (if pf & 2 != 0 { SECINFO_W } else { 0 })
                | (if pf & 1 != 0 { SECINFO_X } else { 0 })
        };
        let off = va & !(PAGE - 1);
        segs.push(Seg {
            off,
            len: (va + memsz).next_multiple_of(PAGE) - off,
            flags,
        });
    }
    (segs, img)
}

/// SECS.size must be a power of two ≥ span; same value goes into the
/// ECREATE record of the MRENCLAVE stream.
pub fn secs_size(segs: &[Seg]) -> u64 {
    segs.last()
        .map(|s| s.off + s.len)
        .unwrap()
        .next_power_of_two()
}
