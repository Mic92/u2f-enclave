ENTRY(ram32_start)

PHDRS
{
  ram   PT_LOAD FILEHDR PHDRS ;
  reset PT_LOAD               ;
  note  PT_NOTE               ;
}

/* QEMU/CloudHypervisor PVH puts low memory to work; stay above 1 MiB. */
ram_min = 1M;

SECTIONS
{
  . = ram_min;
  . += SIZEOF_HEADERS;
  .note   : { *(.note .note.*) } :note :ram
  .text32 : { *(.text32) } :ram
  .text   : { *(.text .text.*) }
  .rodata : ALIGN(16) { *(.rodata .rodata.*) }
  .data   : ALIGN(16) { *(.data .data.*) *(.got .got.*) }
  .bss    : ALIGN(4096) { *(.bss .bss.*) *(COMMON) }

  /* In :ram (not NOLOAD) so PT_LOAD.memsz covers it and the SNP launch
     measures/validates these pages along with .bss. */
  .stack  : ALIGN(4096) { stack_start = .; . += 32K; stack_end = .; } :ram

  /* TDX reset vector. SEV/plain launches never map this segment. KEEP
     because nothing references it (RIP=0xFFFFFFF0 is set by hardware). */
  . = 0xFFFFF000;
  .reset  : { KEEP(*(.reset)) } :reset
  ASSERT(SIZEOF(.reset) == 4096, "reset stub must be one page")

  /DISCARD/ : { *(.eh_frame*) *(.comment) }
}
