/* SGX enclave layout: linked at 0, all addresses are offsets from the
 * enclave base (SECS.base, picked by the host loader at runtime).  Three
 * PT_LOADs become three ADD_PAGES segments with distinct SECINFO, so the
 * loader can derive page type/permissions from p_flags alone:
 *   #0 RW  -> PT_TCS         (hardware ignores SECINFO perms on TCS)
 *   #1 RX  -> PT_REG | R | X
 *   #2 RW  -> PT_REG | R | W
 */
ENTRY(encl_entry)
PHDRS {
  tcs  PT_LOAD;
  text PT_LOAD;
  data PT_LOAD;
}
SECTIONS {
  . = 0;
  /* No symbol roots these so KEEP them through --gc-sections. */
  .tcs : { KEEP(*(.tcs)) } :tcs

  . = ALIGN(4096);
  .text   : { *(.text .text.*)     } :text
  .rodata : { *(.rodata .rodata.*) } :text
  . = ALIGN(4096);

  .data   : { *(.data .data.*) } :data
  .bss    : { *(.bss .bss.*)   } :data
  . = ALIGN(4096);
  .ssa    : { KEEP(*(.ssa))   } :data
  .stack  : { KEEP(*(.stack)) } :data

  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.dyn*) *(.gnu.hash) }
}
ASSERT(!DEFINED(_GLOBAL_OFFSET_TABLE_), "GOT not supported in enclave")
