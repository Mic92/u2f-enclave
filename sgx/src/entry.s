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
  /* OSSA/OENTRY are PIE relocation targets, but --apply-dynamic-relocs
   * makes lld write the addend (= offset, since we link at 0) into the
   * field as well, which is exactly what the hardware wants. */
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

  /* Apply R_X86_64_RELATIVE (see link.ld).  RBX is the TCS linear address
   * and the TCS is at offset 0, so RBX is also the enclave base.  Done in
   * asm because `lea sym(%rip)` is a PC32 fixup, whereas a Rust
   * `extern static` would itself go through the not-yet-relocated GOT.
   * Idempotent, so no once-flag. */
  lea  __rela_start(%rip), %r8
  lea  __rela_end(%rip), %r9
1:cmp  %r9, %r8
  jae  2f
  mov  (%r8), %r10
  cmpl $8, 8(%r8)          /* ELF64_R_TYPE == R_X86_64_RELATIVE */
  jne  3f
  cmp  $4096, %r10         /* skip TCS (offsets, and #PF on write anyway) */
  jb   3f
  mov  16(%r8), %r11
  add  %rbx, %r11
  mov  %r11, (%rbx, %r10)
3:add  $24, %r8
  jmp  1b
2:
  mov  %rbx, %rsi
  lea  __encl_end(%rip), %rdx
  call encl_main           /* (rdi = host arg ptr, rsi = base, rdx = end) */

  /* Hardware does not clear GPRs on EEXIT, so scrub the caller-saved ones
   * lest p256/HMAC residue leak.  r12–r15 still hold host-owned entry
   * values (SysV); rax/rbx are set below; XMM is never written. */
  xor  %ecx, %ecx
  xor  %edx, %edx
  xor  %esi, %esi
  xor  %edi, %edi
  xor  %r8d, %r8d
  xor  %r9d, %r9d
  xor  %r10d, %r10d
  xor  %r11d, %r11d

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
  .space 16 * 4096
encl_stack:
