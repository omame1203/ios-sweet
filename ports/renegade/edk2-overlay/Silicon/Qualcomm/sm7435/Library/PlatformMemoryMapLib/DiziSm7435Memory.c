/** @file
  Offline-captured dizi FDT DDR and 35 fixed carve-outs. Fail closed.

  Provenance: backup/dizi/fdt (SHA256 below), research/ipad5/dizi-live.dts,
  observed 2026-10-21. Dynamic reserved-memory allocations are intentionally
  not assigned fictitious addresses. No peripheral register read/write.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/DiziSm7435Memory.h>

/* These are NOT inherited from SM7325 or SM8550. Seven NONEMPTY banks. */
static const DIZI_SM7435_RANGE mDdr[DIZI_SM7435_DDR_COUNT] = {
  {UINT64_C(0x80000000), UINT64_C(0x68e00000)},
  {UINT64_C(0xea700000), UINT64_C(0x15900000)},
  {UINT64_C(0x800000000), UINT64_C(0x3fc00000)},
  {UINT64_C(0x880000000), UINT64_C(0x39b00000)},
  {UINT64_C(0x840000000), UINT64_C(0x40000000)},
  {UINT64_C(0x8c0000000), UINT64_C(0xc0000000)},
  {UINT64_C(0x8ba100000), UINT64_C(0x01e00000)}
};

/* FDT /reserved-memory node order; NEVER treat these as available RAM.
 * 10 additional dynamic reserved children without reg MUST be resolved at
 * actual handoff or this library denies ALL conventional memory. */
static const DIZI_SM7435_RANGE mFixed[DIZI_SM7435_FIXED_COUNT] = {
  {UINT64_C(0x80000000),  UINT64_C(0x00600000)}, /* hyp */
  {UINT64_C(0x80600000),  UINT64_C(0x00040000)}, /* XBL dtlog */
  {UINT64_C(0x80640000),  UINT64_C(0x001c0000)}, /* XBL ramdump */
  {UINT64_C(0x80800000),  UINT64_C(0x00060000)}, /* AOP */
  {UINT64_C(0x80860000),  UINT64_C(0x00020000)}, /* AOP cmd db */
  {UINT64_C(0x80880000),  UINT64_C(0x00020000)}, /* AOP config */
  {UINT64_C(0x808a0000),  UINT64_C(0x00040000)}, /* TME crash */
  {UINT64_C(0x808e0000),  UINT64_C(0x00004000)}, /* TME log */
  {UINT64_C(0x808e4000),  UINT64_C(0x00010000)}, /* UEFI log */
  {UINT64_C(0x80900000),  UINT64_C(0x00200000)}, /* SMEM */
  {UINT64_C(0x80b00000),  UINT64_C(0x00100000)}, /* CPUCP firmware */
  {UINT64_C(0x80c00000),  UINT64_C(0x00001000)}, /* chipinfo */
  {UINT64_C(0x82a00000),  UINT64_C(0x00c00000)}, /* WLAN firmware */
  {UINT64_C(0x84b00000),  UINT64_C(0x00800000)}, /* camera */
  {UINT64_C(0x85300000),  UINT64_C(0x01900000)}, /* WPSS */
  {UINT64_C(0x86c00000),  UINT64_C(0x00700000)}, /* video */
  {UINT64_C(0x9a200000),  UINT64_C(0x02900000)}, /* ADSP */
  {UINT64_C(0x89400000),  UINT64_C(0x00a00000)}, /* CDSP */
  {UINT64_C(0x89e00000),  UINT64_C(0x00010000)}, /* IPA */
  {UINT64_C(0x89e10000),  UINT64_C(0x0000a000)}, /* GSI */
  {UINT64_C(0x89e1a000),  UINT64_C(0x00002000)}, /* GPU microcode */
  {UINT64_C(0x8bc00000),  UINT64_C(0x02c00000)}, /* MPSS */
  {UINT64_C(0xa6e00000),  UINT64_C(0x00040000)}, /* XBL SC */
  {UINT64_C(0xa6f00000),  UINT64_C(0x00100000)}, /* global sync */
  {UINT64_C(0xe0600000),  UINT64_C(0x00400000)}, /* CPU sys VM */
  {UINT64_C(0xe0b00000),  UINT64_C(0x00100000)}, /* Trusted UI VM */
  {UINT64_C(0xe55f3000),  UINT64_C(0x00009000)}, /* Trusted UI QRTR */
  {UINT64_C(0xe55fc000),  UINT64_C(0x00004000)}, /* Trusted UI vblk ring */
  {UINT64_C(0xe5600000),  UINT64_C(0x00100000)}, /* Trusted UI SWIOTLB */
  {UINT64_C(0xe8800000),  UINT64_C(0x00100000)}, /* TZ stats */
  {UINT64_C(0xe8900000),  UINT64_C(0x00680000)}, /* TZ tags */
  {UINT64_C(0xe8f80000),  UINT64_C(0x00500000)}, /* QTEE */
  {UINT64_C(0xe9480000),  UINT64_C(0x01200000)}, /* Trusted apps */
  {UINT64_C(0x80d00000),  UINT64_C(0x00200000)}, /* ramoops */
  {UINT64_C(0xb8000000),  UINT64_C(0x02b00000)}  /* live splash fb */
};

static const uint8_t mDiziFdtHash[32] = {
  0x13,0x10,0x7f,0xc6,0x80,0xb5,0x15,0x39,
  0x98,0x9e,0xcd,0x86,0x12,0x7e,0xdd,0x9d,
  0x50,0xb7,0x7a,0xf2,0x2a,0xfe,0x38,0x4f,
  0xfc,0x79,0x56,0xc3,0x2f,0x8a,0x94,0x40
};

const DIZI_SM7435_RANGE *DiziSm7435ExpectedDdr(void) { return mDdr; }
const DIZI_SM7435_RANGE *DiziSm7435ExpectedFixed(void) { return mFixed; }
const uint8_t *DiziSm7435ExpectedFdtSha256(void) { return mDiziFdtHash; }

static int SameBytes(const uint8_t *A, const uint8_t *B, size_t Size)
{
  size_t Index;
  unsigned Diff = 0;
  for (Index = 0; Index < Size; ++Index) Diff |= A[Index] ^ B[Index];
  return Diff == 0;
}

static int Valid(const DIZI_SM7435_RANGE *R)
{
  return R->Bytes && !(R->Base & UINT64_C(0xfff)) &&
         !(R->Bytes & UINT64_C(0xfff)) &&
         R->Base <= UINT64_MAX - R->Bytes;
}

static int SameRange(const DIZI_SM7435_RANGE *A, const DIZI_SM7435_RANGE *B)
{
  return A->Base == B->Base && A->Bytes == B->Bytes;
}

static int Contains(const DIZI_SM7435_RANGE *Outer, const DIZI_SM7435_RANGE *Inner)
{
  return Valid(Outer) && Valid(Inner) && Inner->Base >= Outer->Base &&
         Inner->Base - Outer->Base <= Outer->Bytes &&
         Inner->Bytes <= Outer->Bytes - (Inner->Base - Outer->Base);
}

static int Intersects(const DIZI_SM7435_RANGE *A, const DIZI_SM7435_RANGE *B)
{
  return Valid(A) && Valid(B) &&
         A->Base < B->Base + B->Bytes && B->Base < A->Base + A->Bytes;
}

/* PCD-critical protected layout, matched by the parent SM7435 DSC and the
   edk2 PlatformMemoryMapLib. All FOUR portions require the same live grant
   ownership proof; no carveout can be accepted merely because a DTB says RAM.
   FD and FDT/vectors are not HobConstructor heap, and the stack is deducted
   by QcomPkg/PrePi/Pi.c before publishing its free HOB area. */
static const DIZI_SM7435_RANGE mProtectedLayout[4] = {
  {UINT64_C(0x90000000), UINT64_C(0x00400000)}, /* FD: NOT conventional */
  {UINT64_C(0x90400000), UINT64_C(0x00010000)}, /* FDT + vector: reserved */
  {UINT64_C(0x90410000), UINT64_C(0x00bb0000)}, /* free PEI heap */
  {UINT64_C(0x90fc0000), UINT64_C(0x00040000)}  /* SEC stack: NOT free */
};

static int ProtectedLayoutCoversGrant(const DIZI_SM7435_RANGE *Grant)
{
  unsigned Index;
  uint64_t End;
  if (!Valid(Grant) || Grant->Base != DIZI_SM7435_GRANT_BASE ||
      Grant->Bytes != DIZI_SM7435_GRANT_BYTES)
    return 0;
  End = Grant->Base;
  for (Index = 0; Index < 4; ++Index) {
    if (!Valid(&mProtectedLayout[Index]) ||
        mProtectedLayout[Index].Base != End ||
        !Contains(Grant, &mProtectedLayout[Index]))
      return 0;
    End += mProtectedLayout[Index].Bytes;
  }
  /* First page of region 1 is a FDT pointer write by ModuleEntryPoint.S;
     second page holds 0x800 bytes of early AArch64 exception vectors. */
  if (mProtectedLayout[1].Bytes < UINT64_C(0x1800) ||
      mProtectedLayout[2].Base != UINT64_C(0x90410000) ||
      mProtectedLayout[3].Base != UINT64_C(0x90fc0000))
    return 0;
  return End == Grant->Base + Grant->Bytes;
}

DIZI_SM7435_RESULT DiziSm7435PlanMemory(
  const DIZI_SM7435_EVIDENCE *O,
  DIZI_SM7435_TRUSTED_CHECK TrustedCheck,
  void *Context,
  DIZI_SM7435_PLAN *Plan)
{
  unsigned I, J;
  DIZI_SM7435_RANGE Grant = {DIZI_SM7435_GRANT_BASE, DIZI_SM7435_GRANT_BYTES};
  int Found;
  if (!Plan) return DiziSm7435Malformed;
  /* No partial publication on any failure. */
  {
    uint8_t *Raw = (uint8_t *)Plan;
    for (I = 0; I < sizeof(*Plan); ++I) Raw[I] = 0;
  }
  if (!O || O->Version != DIZI_SM7435_ABI_VERSION ||
      O->StructBytes != sizeof(*O) ||
      O->DdrCount != DIZI_SM7435_DDR_COUNT ||
      O->FixedCount != DIZI_SM7435_FIXED_COUNT ||
      O->DynamicCount != DIZI_SM7435_DYNAMIC_COUNT)
    return DiziSm7435Malformed;
  if (O->Attestations != DIZI_SM7435_ALL_ATTESTATIONS ||
      !TrustedCheck) return DiziSm7435MissingOwnership;
  if (!SameBytes(O->FdtSha256, mDiziFdtHash, sizeof(mDiziFdtHash)))
    return DiziSm7435WrongBoard;
  if (!SameRange(&O->RequestedGrant, &Grant))
    return DiziSm7435WrongBoard;

  /* This only checks the proposed PCD geometry. It is not an independent
     ownership attestation; that remains entirely with TrustedCheck. */
  if (!ProtectedLayoutCoversGrant(&Grant)) return DiziSm7435Malformed;

  /* Compare as sets, not order-dependent DTS node enumeration. */
  for (I = 0; I < O->DdrCount; ++I) {
    if (!Valid(&O->Ddr[I])) return DiziSm7435Malformed;
    Found = 0;
    for (J = 0; J < DIZI_SM7435_DDR_COUNT; ++J)
      Found += SameRange(&O->Ddr[I], &mDdr[J]);
    if (Found != 1) return DiziSm7435WrongBoard;
    for (J = 0; J < I; ++J)
      if (SameRange(&O->Ddr[I], &O->Ddr[J])) return DiziSm7435Overlap;
  }
  for (I = 0; I < O->FixedCount; ++I) {
    if (!Valid(&O->Fixed[I])) return DiziSm7435Malformed;
    Found = 0;
    for (J = 0; J < DIZI_SM7435_FIXED_COUNT; ++J)
      Found += SameRange(&O->Fixed[I], &mFixed[J]);
    if (Found != 1) return DiziSm7435WrongBoard;
    for (J = 0; J < I; ++J)
      if (SameRange(&O->Fixed[I], &O->Fixed[J])) return DiziSm7435Overlap;
    if (Intersects(&O->Fixed[I], &Grant)) return DiziSm7435Overlap;
  }
  Found = 0;
  for (I = 0; I < DIZI_SM7435_DDR_COUNT; ++I)
    Found += Contains(&O->Ddr[I], &Grant);
  if (Found != 1) return DiziSm7435WrongBoard;
  for (I = 0; I < O->DynamicCount; ++I) {
    if (!Valid(&O->Dynamic[I])) return DiziSm7435Malformed;
    Found = 0;
    for (J = 0; J < O->DdrCount; ++J)
      Found += Contains(&O->Ddr[J], &O->Dynamic[I]);
    if (Found != 1) return DiziSm7435WrongBoard;
    if (Intersects(&O->Dynamic[I], &Grant)) return DiziSm7435Overlap;
    for (J = 0; J < O->FixedCount; ++J)
      if (Intersects(&O->Dynamic[I], &O->Fixed[J]))
        return DiziSm7435Overlap;
    for (J = 0; J < I; ++J)
      if (Intersects(&O->Dynamic[I], &O->Dynamic[J]))
        return DiziSm7435Overlap;
  }
  /* NEVER accept an untrusted input boolean as physical ownership proof.
     Only a separately wired early-boot verifier may confirm the PRESENT
     EL1/EL2 maps, XPU ownership, ALL DMA reservations and executable rights.
     This callback is intentionally UNIMPLEMENTED in the overlay. */
  if (TrustedCheck(Context, O) != 1) return DiziSm7435MissingOwnership;
  Plan->OnlyGrantedRam = Grant;
  Plan->SafeToPublishConventionalRam = 1;
  Plan->NoGicWrites = 1;
  Plan->NoUfsDma = 1;
  Plan->NoFirmwareDonor = 1;
  return DiziSm7435ApprovedByExternalVerifier;
}
