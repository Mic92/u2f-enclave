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
  /* Any address-in-data the linker can't make RIP-relative (vtables, GOT
   * slots) ends up as R_X86_64_RELATIVE here; the entry stub applies them. */
  .rela   : {
    __rela_start = .; *(.rela.*); __rela_end = .;
  } :text
  . = ALIGN(4096);

  .data   : { *(.data .data.*) *(.got*) } :data
  .bss    : { *(.bss .bss.*)   } :data
  . = ALIGN(4096);
  .ssa    : { KEEP(*(.ssa))   } :data
  .stack  : { KEEP(*(.stack)) } :data
  __encl_end = .;

  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.dynamic) *(.dynsym) *(.dynstr) *(.gnu.hash) *(.hash) *(.interp) }
}
