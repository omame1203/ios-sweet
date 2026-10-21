/** @file
  Renegade edk2-msm PlatformMemoryMapLib ABI for SM7435/dizi.
  Unlike donor SM7325, no private TZ, firmware, framebuffer or DMA ranges
  are handed out as EfiConventionalMemory. Before a separately verified
  handoff, the returned MMU/HOB descriptor list is EMPTY (terminator only).

  No hardware reads/writes; physical RAM ownership MUST be verified outside
  this library by a trusted handoff implementation not yet present.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/PlatformMemoryMapLib.h>
#include <Library/DiziSm7435Memory.h>

static ARM_MEMORY_REGION_DESCRIPTOR_EX mDenied[] = {
  {"Terminator", 0, 0, NoHob, 0, 0, 0, 0}
};

/* These FOUR pairwise-disjoint subranges are exactly the dizi parent DSC
   PCD layout and total the existing (unmodified) 16-MiB attested grant:

   [90000000,90400000) 4 MiB FD/FV         -> reserved, NOT conventional
   [90400000,90410000) 64 KiB handoff     -> FDT slot + exception vectors
   [90410000,90fc0000) heap/HOB free      -> sole conventional RAM
   [90fc0000,91000000) 256 KiB SEC stack  -> reserved, NOT conventional

   QcomPkg/PrePi/ModuleEntryPoint.S writes x0 at PcdDeviceTreeStore and
   fills 0x800 bytes at PcdCpuVectorBaseAddress BEFORE PlatformInitialize;
   a TRUSTED WRAPPER must verify ownership BEFORE entering that assembly.
   QcomPkg/PrePi/Pi.c then initializes HobConstructor with pool base
   0x90410000 and StackBase 0x90fc0000. Its free HOB area must never include
   the handoff slot, exception vectors, FD or stack. No autonomous hardware
   attestation is provided by the static PCDs themselves. */
static ARM_MEMORY_REGION_DESCRIPTOR_EX mAuthorized[] = {
  {"Dizi FD/FV reserved", UINT64_C(0x90000000), UINT64_C(0x00400000),
   AddDev, MEM_RES, INITIALIZED, Reserv, WRITE_BACK},
  {"Dizi FDT + vectors", UINT64_C(0x90400000), UINT64_C(0x00010000),
   AddDev, MEM_RES, INITIALIZED, Reserv, WRITE_BACK},
  {"Dizi PEI heap", UINT64_C(0x90410000), UINT64_C(0x00bb0000),
   AddMem, SYS_MEM, SYS_MEM_CAP, Conv, WRITE_BACK},
  {"Dizi SEC stack", UINT64_C(0x90fc0000), UINT64_C(0x00040000),
   NoHob, MEM_RES, INITIALIZED, Reserv, WRITE_BACK},
  {"Terminator", 0, 0, NoHob, 0, 0, 0, 0}
};

static int mMemoryAuthorized;

int DiziSm7435PlatformMemoryAuthorized(void)
{
  return mMemoryAuthorized == 1;
}

int DiziSm7435InstallTrustedMemoryEvidence(
  const DIZI_SM7435_EVIDENCE *Observation,
  DIZI_SM7435_TRUSTED_CHECK TrustedCheck,
  void *Context)
{
  DIZI_SM7435_PLAN Plan;
  /* Never retain stale authorization on a subsequent failed handoff. */
  mMemoryAuthorized = 0;
  if (DiziSm7435PlanMemory(Observation, TrustedCheck, Context, &Plan) !=
        DiziSm7435ApprovedByExternalVerifier ||
      Plan.SafeToPublishConventionalRam != 1 ||
      Plan.OnlyGrantedRam.Base != DIZI_SM7435_GRANT_BASE ||
      Plan.OnlyGrantedRam.Bytes != DIZI_SM7435_GRANT_BYTES ||
      Plan.NoGicWrites != 1 || Plan.NoUfsDma != 1 ||
      Plan.NoFirmwareDonor != 1)
    return 0;
  mMemoryAuthorized = 1;
  return 1;
}

ARM_MEMORY_REGION_DESCRIPTOR_EX *GetPlatformMemoryMap(void)
{
  return mMemoryAuthorized ? mAuthorized : mDenied;
}
