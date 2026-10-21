/** @file
  POCO Pad dizi (Qualcomm SM7435/parrot): strict early UEFI RAM admission.

  This header intentionally has NO dependence on proprietary Qualcomm XBL
  protocols, guessed PCDs, donor ACPI, clocks, GIC/SMMU writes or MMC/UFS.
  The captured boot FDT is a SNAPSHOT, never live ownership evidence.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef DIZI_SM7435_MEMORY_H
#define DIZI_SM7435_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#define DIZI_SM7435_ABI_VERSION 1u
#define DIZI_SM7435_DDR_COUNT 7u
#define DIZI_SM7435_FIXED_COUNT 35u
#define DIZI_SM7435_DYNAMIC_COUNT 10u
/* Upstream QcomPkg/PrePi/Pi.c reads PcdUefiMemPoolBase as FixedPcdGet32.
   High 0x8c0000000 is physically real but CANNOT serve this unpatched
   32-bit Renegade pre-PEI allocator. 0x90000000 is only a CANDIDATE. */
#define DIZI_SM7435_GRANT_BASE UINT64_C(0x90000000)
#define DIZI_SM7435_GRANT_BYTES UINT64_C(0x01000000)

/* All of these MUST be independently verified at the ACTUAL UEFI handoff.
   A flag by itself is NOT attestation: trusted_check MUST reject forged flags. */
#define DIZI_SM7435_ATTEST_FDT       (1u << 0)
#define DIZI_SM7435_ATTEST_FIXED     (1u << 1)
#define DIZI_SM7435_ATTEST_DYNAMIC   (1u << 2)
#define DIZI_SM7435_ATTEST_EL1_MMU   (1u << 3)
#define DIZI_SM7435_ATTEST_EL2_XPU   (1u << 4)
#define DIZI_SM7435_ATTEST_EXCLUSIVE (1u << 5)
#define DIZI_SM7435_ATTEST_FIRMWARE  (1u << 6)
#define DIZI_SM7435_ALL_ATTESTATIONS ((1u << 7) - 1u)

typedef struct {
  uint64_t Base;
  uint64_t Bytes;
} DIZI_SM7435_RANGE;

typedef struct {
  uint32_t Version;
  uint32_t StructBytes;
  uint32_t Attestations;
  uint32_t DdrCount;
  uint32_t FixedCount;
  uint32_t DynamicCount;
  uint8_t  FdtSha256[32];
  DIZI_SM7435_RANGE Ddr[DIZI_SM7435_DDR_COUNT];
  DIZI_SM7435_RANGE Fixed[DIZI_SM7435_FIXED_COUNT];
  /* All TEN dynamic reserved-memory allocations must be resolved by the
     current trusted boot handoff, not guessed from the saved DTS. */
  DIZI_SM7435_RANGE Dynamic[DIZI_SM7435_DYNAMIC_COUNT];
  DIZI_SM7435_RANGE RequestedGrant;
} DIZI_SM7435_EVIDENCE;

typedef struct {
  DIZI_SM7435_RANGE OnlyGrantedRam;
  uint32_t SafeToPublishConventionalRam;
  uint32_t NoGicWrites;
  uint32_t NoUfsDma;
  uint32_t NoFirmwareDonor;
} DIZI_SM7435_PLAN;

typedef enum {
  DiziSm7435Denied = 0,
  DiziSm7435Malformed = -1,
  DiziSm7435WrongBoard = -2,
  DiziSm7435Overlap = -3,
  DiziSm7435MissingOwnership = -4,
  DiziSm7435ApprovedByExternalVerifier = 1
} DIZI_SM7435_RESULT;

typedef int (*DIZI_SM7435_TRUSTED_CHECK)(
  void *Context,
  const DIZI_SM7435_EVIDENCE *Observed);

/* Exact FDT snapshot baseline (not the running hardware). */
const DIZI_SM7435_RANGE *DiziSm7435ExpectedDdr(void);
const DIZI_SM7435_RANGE *DiziSm7435ExpectedFixed(void);
const uint8_t *DiziSm7435ExpectedFdtSha256(void);

/* No hardware writes or DRAM access. Result 1 means ONLY the independent
   verifier permitted a 16 MiB PEI candidate. Not native UEFI boot proof. */
DIZI_SM7435_RESULT DiziSm7435PlanMemory(
  const DIZI_SM7435_EVIDENCE *Observation,
  DIZI_SM7435_TRUSTED_CHECK TrustedCheck,
  void *Context,
  DIZI_SM7435_PLAN *Plan);

/* Renegade PlatformMemoryMapLib bridge: default false. The integrator must
   call BEFORE GetPlatformMemoryMap and before installing permanent PEI memory,
   using genuinely trusted, fresh handoff observations. */
int DiziSm7435InstallTrustedMemoryEvidence(
  const DIZI_SM7435_EVIDENCE *Observation,
  DIZI_SM7435_TRUSTED_CHECK TrustedCheck,
  void *Context);
int DiziSm7435PlatformMemoryAuthorized(void);

#endif
