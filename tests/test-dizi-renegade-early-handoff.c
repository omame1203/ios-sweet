/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Host-only FDT parser smoke/negative tests with the saved real dizi FDT.
 * `0x93000000` is a synthetic address argument, not a device observation.
 * No hardware accesses, no native Renegade UEFI boot/attestation.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Library/DiziSm7435Memory.h>
#include "DiziEarlyHandoffGuard.h"

#define SAMPLE_FAKE_PA UINT64_C(0x93000000)

static int report_is_zero(const DIZI_EARLY_FDT_REPORT *r)
{
  const unsigned char *b = (const unsigned char *)r;
  size_t i;
  for (i = 0; i < sizeof(*r); ++i) if (b[i]) return 0;
  return 1;
}

static uint32_t getbe(const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static void putbe(unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)(v >> 24);
  p[1] = (unsigned char)(v >> 16);
  p[2] = (unsigned char)(v >> 8);
  p[3] = (unsigned char)v;
}

static DIZI_EARLY_RESULT inspect(const unsigned char *fdt, size_t len,
                                 uint64_t pa, DIZI_EARLY_FDT_REPORT *r)
{
  memset(r, 0xa5, sizeof(*r));
  return DiziEarlyHandoffAuditFdt(fdt, len, pa, r);
}

static void reject(const unsigned char *fdt, size_t len, uint64_t pa)
{
  DIZI_EARLY_FDT_REPORT r;
  DIZI_EARLY_RESULT status = inspect(fdt, len, pa, &r);
  if (status == DiziEarlyStructureOnly) {
    fprintf(stderr, "Unexpected FDT acceptance (len=%zu PA=%llx)\n",
            len, (unsigned long long)pa);
    abort();
  }
  assert(report_is_zero(&r));
}

int main(int argc, char **argv)
{
  FILE *input;
  size_t count, i;
  unsigned char *fdt;
  DIZI_EARLY_FDT_REPORT r;
  const size_t size_limit = DIZI_EARLY_FDT_MAX_BYTES;
  if (argc != 2) {
    fprintf(stderr, "usage: %s backup/dizi/fdt\n", argv[0]);
    return 2;
  }
  input = fopen(argv[1], "rb");
  assert(input);
  fdt = (unsigned char *)malloc(size_limit);
  assert(fdt);
  count = fread(fdt, 1, size_limit, input);
  assert(ferror(input) == 0);
  assert(fclose(input) == 0);
  assert(count == 851726);
  assert(getbe(fdt) == UINT32_C(0xd00dfeed));

  assert(DiziEarlyHandoffAuditFdt(fdt, count, SAMPLE_FAKE_PA, NULL)
         == DiziEarlyInvalidArgument);
  {
    DIZI_EARLY_RESULT rc = inspect(fdt, count, SAMPLE_FAKE_PA, &r);
    if (rc != DiziEarlyStructureOnly)
      fprintf(stderr, "Real FDT structural status %d\n", (int)rc);
    assert(rc == DiziEarlyStructureOnly);
  }
  assert(r.AbiVersion == DIZI_EARLY_GUARD_ABI_VERSION);
  assert(r.ObservedFdtBytes == count);
  assert(r.MemoryBanks == DIZI_EARLY_FDT_MEMORY_BANKS);
  assert(r.FixedReservations == DIZI_EARLY_FDT_FIXED_RESERVATIONS);
  assert(r.DynamicReservations == DIZI_EARLY_FDT_DYNAMIC_RESERVATIONS);
  assert(r.FdtStructurallyConsistent == 1);
  assert(r.FdtPhysicalAddressWasAttested == 0);
  assert(r.ExclusiveMemoryOwnershipVerified == 0);
  assert(r.CanEnterRenegadePrePi == 0);

  reject(NULL, count, SAMPLE_FAKE_PA);
  reject(fdt, 0, SAMPLE_FAKE_PA);
  reject(fdt, 39, SAMPLE_FAKE_PA);
  reject(fdt, count, 0);
  reject(fdt, count, SAMPLE_FAKE_PA + 1);
  reject(fdt, count, UINT64_MAX - 7);
  reject(fdt, count, UINT64_C(0x90000000)); /* unresolved FD overlap */
  reject(fdt, count, UINT64_C(0x90400000)); /* FDT/vector writable slot */
  reject(fdt, count, UINT64_C(0x90fc0000)); /* SEC stack */
  reject(fdt, count, UINT64_C(0xb8000000)); /* splash framebuffer carveout */
  reject(fdt, count, UINT64_C(0x80900000)); /* SMEM carveout */
  reject(fdt, count, UINT64_C(0x70000000)); /* no DDR */

  for (i = 0; i < 40; ++i) {
    unsigned char old = fdt[i];
    fdt[i] ^= 0xff;
    if (i == 0 || i == 4 || i == 5 || i == 8 || i == 12 || i == 16 ||
        i == 20 || i == 24 || i == 32 || i == 36)
      reject(fdt, count, SAMPLE_FAKE_PA);
    fdt[i] = old;
  }

  /* Require complete bounded blob and reject invalid reserve-map entry. */
  for (i = 40; i < count; i += 65537) {
    unsigned char old = fdt[i];
    fdt[i] = 0xff;
    DIZI_EARLY_RESULT rc = inspect(fdt, count, SAMPLE_FAKE_PA, &r);
    assert(rc != DiziEarlyStructureOnly ||
           (!r.FdtPhysicalAddressWasAttested &&
            !r.ExclusiveMemoryOwnershipVerified &&
            !r.CanEnterRenegadePrePi));
    fdt[i] = old;
  }

  /* Mutated FDT structure `BEGIN_NODE` must fail structurally. */
  {
    size_t off = (size_t)getbe(fdt + 8);
    uint32_t old = getbe(fdt + off);
    putbe(fdt + off, UINT32_C(0xf0000001));
    reject(fdt, count, SAMPLE_FAKE_PA);
    putbe(fdt + off, old);
  }
  /* Truncated FDT storage is refused even if header totalsize looks good. */
  reject(fdt, count - 1, SAMPLE_FAKE_PA);
  /* Original FDT unchanged in this process, structural outcome repeatable. */
  assert(inspect(fdt, count, SAMPLE_FAKE_PA, &r) == DiziEarlyStructureOnly);
  assert(r.CanEnterRenegadePrePi == 0);
  free(fdt);
  puts("PASS: real dizi FDT read-only structural audit; no attestation or early writes");
  return 0;
}
