/* 32-bit PVH entry → long mode. Runs with paging off, flat 4 GiB segments,
 * %ebx = hvm_start_info (ignored for now). Identity-maps [0, 4 GiB) with four
 * 1 GiB pages so virtio-mmio at 0xfeb00000 is reachable, enables PAE+LME+PG,
 * loads a 64-bit GDT and far-jumps into Rust.
 *
 * Derived from cloud-hypervisor/rust-hypervisor-firmware (Apache-2.0). */

.section .text32, "ax"
.global ram32_start
.code32

ram32_start:
    cli

    /* PDPT[0..4] = 1 GiB identity pages; PML4[0] -> PDPT */
    movl $0x00000083, (PDPT)      /* P|RW|PS */
    movl $0x40000083, (PDPT+8)
    movl $0x80000083, (PDPT+16)
    movl $0xC0000083, (PDPT+24)
    movl $PDPT, %eax; orb $0b11, %al; movl %eax, (PML4)

    movl $PML4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orb  $0b00100000, %al        /* CR4.PAE */
    movl %eax, %cr4

    movl $0xC0000080, %ecx
    rdmsr
    orb  $0b00000001, %ah        /* EFER.LME */
    wrmsr

    movl %cr0, %eax
    orl  $(1 << 31), %eax        /* CR0.PG */
    movl %eax, %cr0

    lgdtl GDT64_PTR
    movl $stack_end, %esp
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    ljmpl $0x08, $rust64_start
