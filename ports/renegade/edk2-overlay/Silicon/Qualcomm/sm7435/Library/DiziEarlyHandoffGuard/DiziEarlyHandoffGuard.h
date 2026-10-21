/** @file
  POCO Pad SM7435 Renegade PrePi early-handoff guard contract.

  DiziEarlyHandoffGuardEntry is an independent, default-DENY assembly entry,
  NOT the existing upstream _ModuleEntryPoint. It performs no memory loads,
  stores, firmware protocol calls or stack accesses. It NEVER jumps into
  upstream PrePi without independent current-runtime PA ownership evidence.

  DiziEarlyHandoffAuditFdt is a portable READ-ONLY offline structural parser.
  The caller MUST have ALREADY placed the entire blob in a validated,
  CPU-readable buffer; passing the live unverified x0 physical pointer
  directly is NOT permitted. The parser NEVER authorizes early writes.

  No Gunyah/XPU/EL2 allocation protocol is known for this handoff. Mere DTB
  membership and a synthetic trusted-check flag are not ownership proof.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef DIZI_EARLY_HANDOFF_GUARD_H
#define DIZI_EARLY_HANDOFF_GUARD_H

#include <stddef.h>
#include <stdint.h>

#define DIZI_EARLY_FDT_MAX_BYTES (2u * 1024u * 1024u)
#define DIZI_EARLY_FDT_MEMORY_BANKS 7u
#define DIZI_EARLY_FDT_FIXED_RESERVATIONS 35u
#define DIZI_EARLY_FDT_DYNAMIC_RESERVATIONS 10u
#define DIZI_EARLY_GUARD_ABI_VERSION 1u

typedef enum {
  DiziEarlyDenied = 0,
  DiziEarlyStructureOnly = 1, /* successful inspection, STILL NOT boot grant */
  DiziEarlyInvalidArgument = -1,
  DiziEarlyFdtBounds = -2,
  DiziEarlyWrongBoard = -3,
  DiziEarlyMemoryConflict = -4
} DIZI_EARLY_RESULT;

typedef struct {
  uint32_t AbiVersion;
  uint32_t ObservedFdtBytes;
  uint32_t MemoryBanks;
  uint32_t FixedReservations;
  uint32_t DynamicReservations;
  uint32_t FdtStructurallyConsistent;
  uint32_t FdtPhysicalAddressWasAttested; /* ALWAYS ZERO */
  uint32_t ExclusiveMemoryOwnershipVerified; /* ALWAYS ZERO */
  uint32_t CanEnterRenegadePrePi; /* ALWAYS ZERO until real trusted upstream ABI */
} DIZI_EARLY_FDT_REPORT;

/** Structural validation only. `ObservedPhysicalAddress` is numeric,
    NEVER dereferenced. `MappedCopy` MUST already be safe to read by caller.
    Report zeroed on all reject paths. No success grants PA write permission.
    The check does not assert complete boot FDT transaction provenance. */
DIZI_EARLY_RESULT DiziEarlyHandoffAuditFdt(
  const void *MappedCopy, size_t BufferBytes,
  uint64_t ObservedPhysicalAddress,
  DIZI_EARLY_FDT_REPORT *Report);

/** SAFE NO-STORE pre-SEC entry point. AArch64 x0 = incoming FDT physical
    pointer, x1-x7 unspecified. No ABI exists to prove exclusive ownership
    before upstream ModuleEntryPoint.S stores x0 and overwrites VBAR/stack.
    Hence it parks forever (WFE loop), NEVER calls `_ModuleEntryPoint`.
    To use a real owner verifier, future integrator MUST author a separately
    audited pre-SEC entry using an independently trusted loader/hypervisor
    protocol and prove transition ordering with a binary disassembly review.
    Merely changing a macro here must never enable unsafe execution. */
void DiziEarlyHandoffGuardEntry(void);

#endif
