/* 32-bit PVH entry → long mode. Runs with paging off, flat 4 GiB segments,
 * %ebx = hvm_start_info (ignored), %esi = SEV C-bit position from the host
 * (0 = not SEV; the guest cannot safely probe this itself: rdmsr SEV_STATUS
 * #GPs on non-SEV silicon and CPUID #VCs under SEV-ES). A lying host just
 * crashes the guest either way — fail-closed.
 *
 * Identity-maps [0, 4 GiB) with four 1 GiB pages, enables PAE+LME+PG, loads
 * a 64-bit GDT and far-jumps into Rust. With SEV active the leaf PTEs get
 * the C-bit so code/data stay private; the page-table *walk* is always
 * encrypted regardless (APM Vol 2 §15.34.5).
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

    /* %esi = C-bit position (>= 32 on all SNP parts); set it in each leaf
     * PTE's high dword. Intermediate entries don't need it. */
    testl %esi, %esi
    jz   1f
    movl %esi, %ecx
    subl $32, %ecx
    movl $1, %eax
    shll %cl, %eax
    orl  %eax, (PDPT+4)
    orl  %eax, (PDPT+12)
    orl  %eax, (PDPT+20)
    orl  %eax, (PDPT+28)
1:

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
    movl %esi, %edi               /* SysV arg0: 0 = plain, >=32 = SEV C-bit */
    ljmpl $0x08, $rust64_start
