/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * AArch64 pre-stack, pre-write early-entry boundary for SM7435/dizi.
 *
 * x0: untrusted incoming FDT PA. No FDT dereference (unverified mapping),
 * no branch to QcomPkg/PrePi/_ModuleEntryPoint, no stack, no MMIO/SMC/HVC,
 * no x0 store to the unverified PcdDeviceTreeStore address, no atomics.
 *
 * An x0 range check would be merely structural, NOT exclusive Gunyah/XPU
 * ownership. Therefore ALL paths unconditionally park, including valid x0.
 * PrePi can be reached only by an entirely separate pre-SEC trusted proof
 * chain which does not yet exist and is not synthesized in this module.
 */
.section .text.DiziEarlyHandoffGuardEntry, "ax", %progbits
.p2align 4
.global DiziEarlyHandoffGuardEntry
.type DiziEarlyHandoffGuardEntry, %function
DiziEarlyHandoffGuardEntry:
  /* Check only REGISTERS; deliberately no load from an unverified x0. */
  cbz x0, .Ldizi_early_deny
  tst x0, #7
  b.ne .Ldizi_early_deny
  mrs x9, CurrentEL
  cmp x9, #4              /* EL1 */
  b.eq .Ldizi_early_deny
  cmp x9, #8              /* EL2 */
  b.ne .Ldizi_early_deny
.Ldizi_early_deny:
  wfe
  b .Ldizi_early_deny
.size DiziEarlyHandoffGuardEntry, .-DiziEarlyHandoffGuardEntry
.section .note.GNU-stack, "", %progbits
