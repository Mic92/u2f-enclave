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

#[repr(C, align(4096))]
struct PageTable([u64; 512]);

#[no_mangle]
static mut PML4: PageTable = PageTable([0; 512]);
#[no_mangle]
static mut PDPT: PageTable = PageTable([0; 512]);
#[no_mangle]
static mut PD: PageTable = PageTable([0; 512]);
