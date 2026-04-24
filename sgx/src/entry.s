/* TCS + entry/exit stubs.  All addresses are RIP-relative; the enclave is
 * linked at 0 and mapped at a runtime-chosen base, so absolute references
 * would be wrong.  Values stored in the TCS are *offsets* (hardware adds
 * SECS.base), and since we link at 0 the symbol VAs already are offsets.
 *
 * EENTER lands at encl_entry with: RBX = TCS linear addr, RCX = AEP/return,
 * RDI/RSI/RDX/R8/R9 = host-chosen arguments (vDSO passes them through).
 * RBP and the host stack are off-limits (vDSO anchors on them); everything
 * else is ours until EEXIT.
 */
.macro ENCLU
  .byte 0x0f, 0x01, 0xd7
.endm

.section .tcs, "aw"
.balign 4096
  .quad 0             /* state  (CPU)  */
  .quad 0             /* flags         */
  .quad encl_ssa      /* OSSA          */
  .long 0             /* CSSA   (CPU)  */
  .long 1             /* NSSA          */
  .quad encl_entry    /* OENTRY        */
  .quad 0             /* AEP    (CPU)  */
  .quad 0             /* OFSBASE       */
  .quad 0             /* OGSBASE       */
  .long 0xFFFFFFFF    /* FSLIMIT       */
  .long 0xFFFFFFFF    /* GSLIMIT       */
  .fill 4024, 1, 0

.section .text
.global encl_entry
encl_entry:
  /* Swap to the in-enclave stack; preserve host RSP and the return RIP
   * (RCX) so we can EEXIT cleanly even after Rust clobbers them.
   */
  lea  encl_stack(%rip), %rax
  xchg %rax, %rsp
  push %rax
  push %rcx
  call encl_main           /* (rdi, rsi) per SysV; rdi = host arg ptr */
  pop  %rbx                /* EEXIT target */
  pop  %rsp
  mov  $4, %rax            /* ENCLU.EEXIT */
  ENCLU
  ud2

.section .ssa, "aw", @nobits
.balign 4096
encl_ssa:
  .space 4096

.section .stack, "aw", @nobits
.balign 4096
  .space 8 * 4096
encl_stack:
