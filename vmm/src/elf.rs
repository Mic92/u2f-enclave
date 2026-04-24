//! Load PT_LOAD segments into guest memory and find the PVH entry note.
//! Hand-rolled: we only ever load our own ELF64, so a full parser is overkill.

use std::io;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

fn rd<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    b[off..off + N].try_into().unwrap()
}
fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(rd(b, off))
}
fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(rd(b, off))
}
fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(rd(b, off))
}

pub struct Loaded {
    pub entry: u32,
    /// Page-aligned [lo, hi) extent covering every PT_LOAD; this is what the
    /// SNP launch must encrypt+measure so the guest finds its code, page
    /// tables, .bss heap and stack all pre-validated.
    pub lo: u64,
    pub hi: u64,
}

pub fn load(img: &[u8], mem: &mut [u8]) -> io::Result<Loaded> {
    if img.len() < 64 || &img[..4] != b"\x7fELF" || img[4] != 2 {
        return Err(io::Error::other("not ELF64"));
    }
    let phoff = u64le(img, 32) as usize;
    let phentsize = u16le(img, 54) as usize;
    let phnum = u16le(img, 56) as usize;
    let mut entry32 = None;
    let (mut lo, mut hi) = (u64::MAX, 0u64);

    for i in 0..phnum {
        let ph = &img[phoff + i * phentsize..];
        let p_type = u32le(ph, 0);
        let off = u64le(ph, 8) as usize;
        let paddr = u64le(ph, 24) as usize;
        let filesz = u64le(ph, 32) as usize;
        let memsz = u64le(ph, 40) as usize;

        match p_type {
            PT_LOAD => {
                mem.get_mut(paddr..paddr + memsz)
                    .ok_or_else(|| io::Error::other("PT_LOAD outside guest memory"))?
                    .fill(0);
                mem[paddr..paddr + filesz].copy_from_slice(&img[off..off + filesz]);
                lo = lo.min(paddr as u64);
                hi = hi.max((paddr + memsz) as u64);
            }
            PT_NOTE => {
                let mut p = off;
                while p + 12 <= off + filesz {
                    let nsz = u32le(img, p) as usize;
                    let dsz = u32le(img, p + 4) as usize;
                    let typ = u32le(img, p + 8);
                    let name = &img[p + 12..p + 12 + nsz];
                    let desc = p + 12 + nsz.next_multiple_of(4);
                    if typ == XEN_ELFNOTE_PHYS32_ENTRY && name == b"Xen\0" {
                        entry32 = Some(u32le(img, desc));
                    }
                    p = desc + dsz.next_multiple_of(4);
                }
            }
            _ => {}
        }
    }
    Ok(Loaded {
        entry: entry32.ok_or_else(|| io::Error::other("no PVH PHYS32_ENTRY note"))?,
        lo: lo & !0xfff,
        hi: hi.next_multiple_of(0x1000),
    })
}
