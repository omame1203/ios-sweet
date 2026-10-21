/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Offline SM7435 silicon memory gate regression. No hardware MMIO/DMA.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <Library/DiziSm7435Memory.h>
#include <Library/PlatformMemoryMapLib.h>

static int approved(void *context, const DIZI_SM7435_EVIDENCE *observed)
{
  int *count = (int *)context;
  assert(observed && count);
  ++*count;
  return 1; /* SYNTHETIC ONLY, NOT real EL1/EL2 ownership attestation */
}

static int denied(void *context, const DIZI_SM7435_EVIDENCE *observed)
{
  (void)context;
  (void)observed;
  return 0;
}

static int zeroed(const void *buf, size_t len)
{
  const unsigned char *p = (const unsigned char *)buf;
  size_t i;
  for (i = 0; i < len; ++i)
    if (p[i] != 0) return 0;
  return 1;
}

static void make_evidence(DIZI_SM7435_EVIDENCE *evidence)
{
  unsigned i;
  memset(evidence, 0, sizeof(*evidence));
  evidence->Version = DIZI_SM7435_ABI_VERSION;
  evidence->StructBytes = sizeof(*evidence);
  evidence->Attestations = DIZI_SM7435_ALL_ATTESTATIONS;
  evidence->DdrCount = DIZI_SM7435_DDR_COUNT;
  evidence->FixedCount = DIZI_SM7435_FIXED_COUNT;
  evidence->DynamicCount = DIZI_SM7435_DYNAMIC_COUNT;
  memcpy(evidence->FdtSha256, DiziSm7435ExpectedFdtSha256(), 32);
  memcpy(evidence->Ddr, DiziSm7435ExpectedDdr(), sizeof(evidence->Ddr));
  memcpy(evidence->Fixed, DiziSm7435ExpectedFixed(), sizeof(evidence->Fixed));
  for (i = 0; i < evidence->DynamicCount; ++i) {
    evidence->Dynamic[i].Base = UINT64_C(0x8c1000000) + i * UINT64_C(0x400000);
    evidence->Dynamic[i].Bytes = UINT64_C(0x200000);
  }
  evidence->RequestedGrant.Base = DIZI_SM7435_GRANT_BASE;
  evidence->RequestedGrant.Bytes = DIZI_SM7435_GRANT_BYTES;
}

static void require_reject(DIZI_SM7435_EVIDENCE *observed,
                           DIZI_SM7435_RESULT reason)
{
  DIZI_SM7435_PLAN plan;
  int count = 0;
  memset(&plan, 0xA5, sizeof(plan));
  DIZI_SM7435_RESULT actual = DiziSm7435PlanMemory(observed, approved, &count, &plan);
  if (actual != reason)
    fprintf(stderr, "silicon reject mismatch expected=%d actual=%d\n", reason, actual);
  assert(actual == reason);
  assert(zeroed(&plan, sizeof(plan)));
  assert(count == 0); /* malformed FDT must not reach trust callback */
}

int main(void)
{
  DIZI_SM7435_EVIDENCE good, bad;
  DIZI_SM7435_PLAN plan;
  const DIZI_SM7435_RANGE *expected;
  ARM_MEMORY_REGION_DESCRIPTOR_EX *map;
  unsigned i, j;
  int count = 0;

  assert(!DiziSm7435PlatformMemoryAuthorized());
  map = GetPlatformMemoryMap();
  assert(map && map[0].Address == 0 && map[0].Length == 0);
  assert(map[0].HobOption == NoHob);
  assert(DiziSm7435PlanMemory(NULL, approved, NULL, &plan) == DiziSm7435Malformed);
  assert(DiziSm7435PlanMemory(NULL, approved, NULL, NULL) == DiziSm7435Malformed);

  make_evidence(&good);
  expected = DiziSm7435ExpectedDdr();
  for (i = 0; i < DIZI_SM7435_DDR_COUNT; ++i)
    for (j = i + 1; j < DIZI_SM7435_DDR_COUNT; ++j)
      assert(expected[i].Base + expected[i].Bytes <= expected[j].Base ||
             expected[j].Base + expected[j].Bytes <= expected[i].Base);
  expected = DiziSm7435ExpectedFixed();
  for (i = 0; i < DIZI_SM7435_FIXED_COUNT; ++i)
    for (j = i + 1; j < DIZI_SM7435_FIXED_COUNT; ++j)
      assert(expected[i].Base + expected[i].Bytes <= expected[j].Base ||
             expected[j].Base + expected[j].Bytes <= expected[i].Base);
  assert(DiziSm7435PlanMemory(&good, NULL, NULL, &plan) == DiziSm7435MissingOwnership);
  assert(zeroed(&plan, sizeof(plan)));
  assert(DiziSm7435PlanMemory(&good, denied, NULL, &plan) == DiziSm7435MissingOwnership);
  assert(zeroed(&plan, sizeof(plan)));
  assert(DiziSm7435PlanMemory(&good, approved, &count, &plan) ==
         DiziSm7435ApprovedByExternalVerifier);
  assert(count == 1);
  assert(plan.SafeToPublishConventionalRam == 1 && plan.NoGicWrites == 1 &&
         plan.NoUfsDma == 1 && plan.NoFirmwareDonor == 1);
  assert(plan.OnlyGrantedRam.Base == DIZI_SM7435_GRANT_BASE &&
         plan.OnlyGrantedRam.Bytes == DIZI_SM7435_GRANT_BYTES);
  assert(!DiziSm7435PlatformMemoryAuthorized()); /* pure plan cannot publish */

#define CHECK_REJECT(mutation, expected_status) do { \
    bad = good; mutation; require_reject(&bad, expected_status); \
  } while (0)
  CHECK_REJECT(bad.Version = 0, DiziSm7435Malformed);
  CHECK_REJECT(bad.StructBytes = 0, DiziSm7435Malformed);
  CHECK_REJECT(bad.DdrCount = 8, DiziSm7435Malformed);
  CHECK_REJECT(bad.FixedCount = 34, DiziSm7435Malformed);
  CHECK_REJECT(bad.DynamicCount = 9, DiziSm7435Malformed);
  CHECK_REJECT(bad.Attestations = 0, DiziSm7435MissingOwnership);
  CHECK_REJECT(bad.Attestations = DIZI_SM7435_ALL_ATTESTATIONS | 0x80,
               DiziSm7435MissingOwnership);
  CHECK_REJECT(bad.FdtSha256[0] ^= 1, DiziSm7435WrongBoard);
  CHECK_REJECT(bad.RequestedGrant.Base += 0x1000, DiziSm7435WrongBoard);
  CHECK_REJECT(bad.RequestedGrant.Bytes = 0, DiziSm7435WrongBoard);
  CHECK_REJECT(bad.Ddr[0].Base += 0x1000, DiziSm7435WrongBoard);
  CHECK_REJECT(bad.Ddr[0].Bytes = 0, DiziSm7435Malformed);
  CHECK_REJECT(bad.Ddr[1] = bad.Ddr[0], DiziSm7435Overlap);
  CHECK_REJECT(bad.Fixed[0].Base += 0x1000, DiziSm7435WrongBoard);
  CHECK_REJECT(bad.Fixed[0].Bytes = 0, DiziSm7435Malformed);
  CHECK_REJECT(bad.Fixed[1] = bad.Fixed[0], DiziSm7435Overlap);
  CHECK_REJECT(bad.Dynamic[0].Bytes = 0, DiziSm7435Malformed);
  CHECK_REJECT(bad.Dynamic[0].Bytes = UINT64_MAX, DiziSm7435Malformed);
  CHECK_REJECT(bad.Dynamic[0].Base = DIZI_SM7435_GRANT_BASE, DiziSm7435Overlap);
  CHECK_REJECT(bad.Dynamic[0] = bad.Fixed[0], DiziSm7435Overlap);
  CHECK_REJECT(bad.Dynamic[0] = bad.Dynamic[1], DiziSm7435Overlap);
  CHECK_REJECT(bad.Dynamic[0].Base = UINT64_C(0x200000000), DiziSm7435WrongBoard);
  CHECK_REJECT(bad.Dynamic[0].Base += 1, DiziSm7435Malformed);
#undef CHECK_REJECT
  /* Physically admitted 16 MiB grant is split into disjoint descriptors;
     the only EfiConventionalMemory is 0x90410000..0x90fc0000.
     The initial firmware, FDT/vector writes and stack are NEVER allocator RAM. */
  assert(DiziSm7435InstallTrustedMemoryEvidence(&good, approved, &count) == 1);
  assert(DiziSm7435PlatformMemoryAuthorized());
  map = GetPlatformMemoryMap();
  {
    const uint64_t begins[4] = {UINT64_C(0x90000000), UINT64_C(0x90400000),
                                 UINT64_C(0x90410000), UINT64_C(0x90fc0000)};
    const uint64_t sizes[4] = {UINT64_C(0x00400000), UINT64_C(0x00010000),
                                UINT64_C(0x00bb0000), UINT64_C(0x00040000)};
    unsigned conventional = 0;
    for (i = 0; i < 4; ++i) {
      assert(map[i].Address == begins[i]);
      assert(map[i].Length == sizes[i]);
      assert(map[i].ArmAttributes == WRITE_BACK);
      assert(map[i].Address + map[i].Length ==
             (i + 1 < 4 ? begins[i + 1] :
                            DIZI_SM7435_GRANT_BASE + DIZI_SM7435_GRANT_BYTES));
      for (j = 0; j < i; ++j)
        assert(map[j].Address + map[j].Length <= map[i].Address);
      if (map[i].MemoryType == Conv) {
        ++conventional;
        assert(i == 2 && map[i].HobOption == AddMem &&
               map[i].ResourceType == SYS_MEM);
      } else {
        assert(map[i].MemoryType == Reserv && map[i].ResourceType == MEM_RES);
        assert(map[i].HobOption == AddDev || map[i].HobOption == NoHob);
      }
    }
    assert(conventional == 1);
  }
  assert(map[4].Length == 0 && map[4].Address == 0);
  assert(map[4].HobOption == NoHob);
  /* Any later failed attestation revokes ALL exposed descriptors. */
  assert(DiziSm7435InstallTrustedMemoryEvidence(&good, denied, NULL) == 0);
  assert(!DiziSm7435PlatformMemoryAuthorized());
  assert(GetPlatformMemoryMap()[0].Length == 0);
  puts("PASS: dizi SM7435 silicon DDR/FDT ownership and EDK2 map ABI (synthetic only)");
  return 0;
}
