//! PVH boot glue: ELF note, GDT and page-table storage that `ram32.s`
//! references by `#[no_mangle]` symbol name.
//!
//! Pattern lifted from `cloud-hypervisor/rust-hypervisor-firmware`
//! (Apache-2.0): keep the policy in Rust statics, keep the asm to a single
//! page-table fill and mode switch.

use core::arch::global_asm;
use core::mem::size_of;

global_asm!(include_str!("ram32.s"), options(att_syntax, raw));

extern "C" {
    fn ram32_start();
}

// --- PVH ELF note ---------------------------------------------------------

const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;
type Name = [u8; 4];
type Desc = unsafe extern "C" fn();

#[repr(C, packed(4))]
struct Note {
    name_size: u32,
    desc_size: u32,
    kind: u32,
    name: Name,
    desc: Desc,
}

// SAFETY: never read by us; only the ELF loader inspects PT_NOTE.
unsafe impl Sync for Note {}

#[link_section = ".note"]
#[used]
static PVH_NOTE: Note = Note {
    name_size: size_of::<Name>() as u32,
    desc_size: size_of::<Desc>() as u32,
    kind: XEN_ELFNOTE_PHYS32_ENTRY,
    name: *b"Xen\0",
    desc: ram32_start,
};

// --- 64-bit GDT -----------------------------------------------------------

// Long-mode descriptors ignore base/limit; only the access byte and L bit
// matter. Values match the rust-hypervisor-firmware GDT.
const CODE64: u64 = 0x0020_9B00_0000_0000;
const DATA64: u64 = 0x0020_9300_0000_0000;

static GDT64: [u64; 3] = [0, CODE64, DATA64];

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    // Reference, not u64, so the static can hold an address without a
    // pointer-to-integer cast (which Rust forbids in const context).
    base: &'static u64,
}
unsafe impl Sync for GdtPtr {}

#[no_mangle]
static GDT64_PTR: GdtPtr = GdtPtr {
    limit: (size_of::<[u64; 3]>() - 1) as u16,
    base: &GDT64[0],
};

// --- page tables ----------------------------------------------------------

use core::ptr::{addr_of, addr_of_mut, write_volatile};

#[repr(C, align(4096))]
pub struct PageTable(pub [u64; 512]);

#[no_mangle]
pub static mut PML4: PageTable = PageTable([0; 512]);
#[no_mangle]
pub static mut PDPT: PageTable = PageTable([0; 512]);

/// 4 KiB-granular tables for [0, 2 MiB) so individual pages can be flipped
/// to shared (C=0) while the rest stays private.
static mut PD0: PageTable = PageTable([0; 512]);
static mut PT0: PageTable = PageTable([0; 512]);

#[inline]
pub fn flush_tlb() {
    unsafe { core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack)) };
}

/// Replace the [0, 1 GiB) huge leaf with a PD whose first entry is a 4 KiB
/// PT. `leaf_or` (the C-bit) goes into every leaf. Safe to run while
/// executing out of this range: new leaves map the same PAs with the same
/// encryption disposition.
pub fn refine_low_2m(leaf_or: u64) {
    let pt0 = unsafe { &mut *addr_of_mut!(PT0) };
    let pd0 = unsafe { &mut *addr_of_mut!(PD0) };
    for i in 0..512u64 {
        pt0.0[i as usize] = (i << 12) | 0x03 | leaf_or;
        pd0.0[i as usize] = (i << 21) | 0x83 | leaf_or;
    }
    pd0.0[0] = (addr_of!(PT0) as u64) | 0x03;
    unsafe {
        write_volatile(addr_of_mut!(PDPT.0[0]), (addr_of!(PD0) as u64) | 0x03);
    }
    flush_tlb();
}

/// Pointer to the leaf PTE covering `gpa` in [0, 2 MiB).
pub fn pt0_entry(gpa: u64) -> *mut u64 {
    debug_assert!(gpa < 0x20_0000);
    unsafe { addr_of_mut!(PT0.0[(gpa >> 12) as usize]) }
}
