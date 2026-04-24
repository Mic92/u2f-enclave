/* 32-bit PVH entry → long mode. Runs with paging off, flat 4 GiB segments,
 * %ebx = hvm_start_info (ignored), %esi = SEV C-bit position from the vmm
 * (0 = not SEV; the guest cannot safely probe this itself: rdmsr SEV_STATUS
 * #GPs on non-SEV silicon and CPUID #VCs under SEV-ES). A lying vmm just
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

/* TDX entry, near-jumped to from the reset stub at 0xFFFFFFF0. The TDX
 * module has already loaded flat 4 GiB CS/DS (base 0, AR 0xC09B/0xC093),
 * CR0=PE|NE, CR4=MCE|VMXE and EFER.LME=1
 * (intel/tdx-module td_vmcs_init.c). So this is the same 32→64 dance
 * minus the C-bit OR and minus the EFER write — wrmsr to EFER is in the
 * module's #VE list. */
.global ram32_tdx
ram32_tdx:
    cli
    movl $0x00000083, (PDPT)
    movl $0x40000083, (PDPT+8)
    movl $0x80000083, (PDPT+16)
    movl $0xC0000083, (PDPT+24)
    movl $PDPT, %eax; orb $0b11, %al; movl %eax, (PML4)
    movl $PML4, %eax
    movl %eax, %cr3
    movl %cr4, %eax
    orb  $0b00100000, %al
    movl %eax, %cr4
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0
    lgdtl GDT64_PTR
    movl $stack_end, %esp
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $1, %edi                /* SysV arg0: 1 = TDX */
    ljmpl $0x08, $rust64_start

/* TDX hard-codes RIP=0xFFFFFFF0 with flat CS/DS (base 0, limit 4 GiB).
 * The vmm puts this 4 KiB page at GPA 0xFFFFF000 in its own memslot —
 * SEV/plain boots ignore the segment entirely. A direct `jmp ram32_tdx`
 * would need a rel32 across the 4 GiB wrap, which the ELF64 linker
 * refuses; instead store the absolute target as data and jump through
 * it (DS base is 0, so the moffs32 is a flat linear address). */
.section .reset, "ax"
.code32
.fill 0xfe8, 1, 0
.long ram32_tdx                  /* @ 0xFFFFFFE8 */
.long 0
tdx_reset_vec:                   /* @ 0xFFFFFFF0 = TDX initial RIP */
    nop
    nop
    jmpl *0xFFFFFFE8
.fill 0x10 - (. - tdx_reset_vec), 1, 0
