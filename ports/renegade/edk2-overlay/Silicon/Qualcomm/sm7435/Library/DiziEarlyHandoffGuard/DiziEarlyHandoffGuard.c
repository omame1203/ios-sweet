/** @file
  Portable read-only FDT *structure* preflight; never used to authorize
  firmware writes without independent pre-entry Gunyah/XPU attestation.
  The caller may pass only an already-trusted readable copy of the FDT,
  NEVER a raw unverified physical pointer from ABL x0.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "DiziEarlyHandoffGuard.h"
#include <Library/DiziSm7435Memory.h>

#define FDT_MAGIC 0xd00dfeedu
#define FDT_BEGIN_NODE 1u
#define FDT_END_NODE 2u
#define FDT_PROP 3u
#define FDT_NOP 4u
#define FDT_END 9u
#define MAX_DEPTH 48u

static uint32_t be32(const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t be64(const unsigned char *p)
{
  return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static int span(size_t total, size_t start, size_t length)
{
  return start <= total && length <= total - start;
}

static int equal_cstr(const unsigned char *p, size_t size, const char *name)
{
  size_t i = 0;
  while (i < size && name[i] && p[i] && p[i] == (unsigned char)name[i]) ++i;
  return i < size && name[i] == 0 && p[i] == 0;
}

static int start_name(const unsigned char *p, size_t size, const char *name)
{
  size_t i = 0;
  while (i < size && name[i] && p[i] && p[i] == (unsigned char)name[i]) ++i;
  return !name[i] && i < size && (p[i] == 0 || p[i] == '@');
}

static int contains_literal(const unsigned char *p, size_t n, const char *text)
{
  size_t i, j;
  if (!text[0]) return 0;
  for (i = 0; i < n; ++i) {
    for (j = 0; text[j] && j < n - i; ++j)
      if (p[i + j] != (unsigned char)text[j]) break;
    if (!text[j]) return 1;
  }
  return 0;
}

static int within_ddr(uint64_t pa, size_t bytes)
{
  unsigned i;
  const DIZI_SM7435_RANGE *ram = DiziSm7435ExpectedDdr();
  if (!pa || !bytes || (pa & 7u) || bytes > DIZI_EARLY_FDT_MAX_BYTES) return 0;
  for (i = 0; i < DIZI_SM7435_DDR_COUNT; ++i) {
    if (pa >= ram[i].Base && pa - ram[i].Base <= ram[i].Bytes &&
        (uint64_t)bytes <= ram[i].Bytes - (pa - ram[i].Base)) return 1;
  }
  return 0;
}

/* This returns only the index in the captured, immutable FDT baseline.
   Equality of data does NOT imply hardware ownership. */
static int match_range(uint64_t base, uint64_t bytes,
                       const DIZI_SM7435_RANGE *values, unsigned count)
{
  unsigned i;
  if (!bytes || base > UINT64_MAX - bytes) return -1;
  for (i = 0; i < count; ++i)
    if (values[i].Base == base && values[i].Bytes == bytes) return (int)i;
  return -1;
}

typedef struct {
  uint8_t under_reserved;
  uint8_t is_memory;
  uint8_t is_soc;
  uint8_t is_psci;
  uint8_t has_reg;
  uint8_t has_size;
} Node;

DIZI_EARLY_RESULT DiziEarlyHandoffAuditFdt(
  const void *MappedCopy, size_t BufferBytes,
  uint64_t ObservedPhysicalAddress, DIZI_EARLY_FDT_REPORT *Report)
{
  const unsigned char *fdt = (const unsigned char *)MappedCopy;
  const unsigned char *strings;
  uint32_t total, begin, strings_begin, struct_len, strings_len;
  size_t pos, limit, name_end, reservations;
  uint32_t depth = 0, banks = 0, fixed = 0, dynamic = 0;
  uint64_t ddr_seen = 0, fixed_seen = 0;
  int model = 0, compatible = 0, psci_smc = 0, root_cells = 0;
  Node nodes[MAX_DEPTH];
  unsigned i;

  if (!Report) return DiziEarlyInvalidArgument;
  {
    unsigned char *dest = (unsigned char *)Report;
    for (i = 0; i < sizeof(*Report); ++i) dest[i] = 0;
  }
  if (!fdt || BufferBytes < 40 || BufferBytes > DIZI_EARLY_FDT_MAX_BYTES)
    return DiziEarlyInvalidArgument;

  if (be32(fdt) != FDT_MAGIC) return DiziEarlyFdtBounds;
  total = be32(fdt + 4);
  begin = be32(fdt + 8);
  strings_begin = be32(fdt + 12);
  struct_len = be32(fdt + 36);
  strings_len = be32(fdt + 32);
  if (total < 56 || total > BufferBytes || total > DIZI_EARLY_FDT_MAX_BYTES ||
      be32(fdt + 20) != 17 || be32(fdt + 24) != 16 ||
      !(begin % 4 == 0 && strings_begin % 4 == 0) ||
      begin < 40 || !span(total, begin, struct_len) ||
      !span(total, strings_begin, strings_len) ||
      begin + struct_len > strings_begin ||
      be32(fdt + 16) < 40 || be32(fdt + 16) >= begin)
    return DiziEarlyFdtBounds;
  /* Terminator for the 64-bit big-endian memory reserve table must be
     found before the structure section without accessing beyond the blob. */
  reservations = be32(fdt + 16);
  while (1) {
    uint64_t start, len;
    if (!span(begin, reservations, 16)) return DiziEarlyFdtBounds;
    start = be64(fdt + reservations);
    len = be64(fdt + reservations + 8);
    reservations += 16;
    if (!start && !len) break;
    if (!len || start > UINT64_MAX - len) return DiziEarlyFdtBounds;
  }

  if (!within_ddr(ObservedPhysicalAddress, total)) return DiziEarlyMemoryConflict;
  if (ObservedPhysicalAddress < DIZI_SM7435_GRANT_BASE + DIZI_SM7435_GRANT_BYTES &&
      ObservedPhysicalAddress + total > DIZI_SM7435_GRANT_BASE)
    return DiziEarlyMemoryConflict;
  /* The FDT itself must not overlap any of the 35 fixed carve-outs, even
     when those carve-outs are present in the FDT. It is a source of facts,
     never an exclusive ownership lease. */
  {
    const DIZI_SM7435_RANGE *protected_ranges = DiziSm7435ExpectedFixed();
    for (i = 0; i < DIZI_SM7435_FIXED_COUNT; ++i)
      if (ObservedPhysicalAddress < protected_ranges[i].Base + protected_ranges[i].Bytes &&
          protected_ranges[i].Base < ObservedPhysicalAddress + total)
        return DiziEarlyMemoryConflict;
  }

  strings = fdt + strings_begin;
  pos = begin;
  limit = (size_t)begin + struct_len;
  while (pos < limit) {
    uint32_t token;
    if (!span(limit, pos, 4)) return DiziEarlyFdtBounds;
    token = be32(fdt + pos);
    pos += 4;
    switch (token) {
    case FDT_BEGIN_NODE: {
      Node newnode = {0,0,0,0,0,0};
      size_t n = pos;
      if (depth == MAX_DEPTH) return DiziEarlyFdtBounds;
      while (n < limit && fdt[n]) ++n;
      if (n >= limit || n - pos >= 256) return DiziEarlyFdtBounds;
      name_end = n - pos + 1;
      if (depth == 1) {
        newnode.is_memory = start_name(fdt + pos, name_end, "memory");
        newnode.is_soc = start_name(fdt + pos, name_end, "soc");
        newnode.under_reserved = start_name(fdt + pos, name_end, "reserved-memory");
      } else if (depth == 2) {
        newnode.under_reserved = nodes[1].under_reserved;
        newnode.is_psci = nodes[1].is_soc &&
                          start_name(fdt + pos, name_end, "psci");
      }
      if (depth == 0 && name_end != 1) return DiziEarlyFdtBounds;
      nodes[depth++] = newnode;
      pos = (n + 4) & ~(size_t)3;
      if (pos > limit) return DiziEarlyFdtBounds;
      break;
    }
    case FDT_END_NODE:
      if (depth == 0) return DiziEarlyFdtBounds;
      if (depth == 3 && nodes[2].under_reserved) {
        if (nodes[2].has_reg == nodes[2].has_size) return DiziEarlyWrongBoard;
        if (nodes[2].has_size) ++dynamic;
      }
      --depth;
      break;
    case FDT_PROP: {
      uint32_t bytes, nameoff;
      const unsigned char *value, *key;
      size_t keylen = 0;
      Node *here;
      if (depth == 0 || !span(limit, pos, 8)) return DiziEarlyFdtBounds;
      bytes = be32(fdt + pos);
      nameoff = be32(fdt + pos + 4);
      pos += 8;
      if (!span(limit, pos, bytes) || nameoff >= strings_len)
        return DiziEarlyFdtBounds;
      key = strings + nameoff;
      while (nameoff + keylen < strings_len && key[keylen]) ++keylen;
      if (nameoff + keylen >= strings_len) return DiziEarlyFdtBounds;
      value = fdt + pos;
      here = &nodes[depth - 1];
      if (depth == 1 && equal_cstr(key, keylen + 1, "model"))
        model = contains_literal(value, bytes, "DIZI");
      if (depth == 1 && equal_cstr(key, keylen + 1, "compatible"))
        compatible = contains_literal(value, bytes, "qcom,parrot-qrd");
      if (depth == 1 && equal_cstr(key, keylen + 1, "#address-cells"))
        root_cells |= bytes == 4 && be32(value) == 2 ? 1 : 0;
      if (depth == 1 && equal_cstr(key, keylen + 1, "#size-cells"))
        root_cells |= bytes == 4 && be32(value) == 2 ? 2 : 0;
      if (depth == 3 && here->is_psci && equal_cstr(key, keylen + 1, "method"))
        psci_smc = equal_cstr(value, bytes, "smc");
      if (depth == 2 && here->is_memory && equal_cstr(key, keylen + 1, "reg")) {
        /* Captured dizi /memory.reg contains 8 tuples: seven real banks
           AND one 0-byte placeholder [0xe9500000,0); this is not RAM. */
        if (here->has_reg || bytes != 8u * 16u) return DiziEarlyWrongBoard;
        here->has_reg = 1;
        for (i = 0; i < 8; ++i) {
          uint64_t bytes_in_bank = be64(value + 16u * i + 8);
          if (!bytes_in_bank) {
            if (be64(value + 16u * i) != UINT64_C(0xe9500000))
              return DiziEarlyWrongBoard;
            continue;
          }
          int index = match_range(be64(value + 16u * i),
                                  bytes_in_bank,
                                  DiziSm7435ExpectedDdr(), DIZI_SM7435_DDR_COUNT);
          if (index < 0 || (ddr_seen & (UINT64_C(1) << index)))
            return DiziEarlyWrongBoard;
          ddr_seen |= UINT64_C(1) << index;
          ++banks;
        }
      }
      if (depth == 3 && here->under_reserved &&
          equal_cstr(key, keylen + 1, "reg")) {
        int index;
        if (here->has_reg || bytes != 16) return DiziEarlyWrongBoard;
        here->has_reg = 1;
        index = match_range(be64(value), be64(value + 8),
                            DiziSm7435ExpectedFixed(), DIZI_SM7435_FIXED_COUNT);
        if (index < 0 || fixed_seen & (UINT64_C(1) << index))
          return DiziEarlyWrongBoard;
        fixed_seen |= UINT64_C(1) << index;
        ++fixed;
      }
      if (depth == 3 && here->under_reserved &&
          equal_cstr(key, keylen + 1, "size")) {
        if (here->has_size || bytes != 8 || !be64(value)) return DiziEarlyWrongBoard;
        here->has_size = 1;
      }
      pos += bytes;
      pos = (pos + 3u) & ~(size_t)3;
      if (pos > limit) return DiziEarlyFdtBounds;
      break;
    }
    case FDT_NOP:
      break;
    case FDT_END:
      if (depth || !model || !compatible || !psci_smc || root_cells != 3 ||
          banks != DIZI_EARLY_FDT_MEMORY_BANKS ||
          fixed != DIZI_EARLY_FDT_FIXED_RESERVATIONS ||
          dynamic != DIZI_EARLY_FDT_DYNAMIC_RESERVATIONS ||
          ddr_seen != ((UINT64_C(1) << DIZI_EARLY_FDT_MEMORY_BANKS) - 1) ||
          fixed_seen != ((UINT64_C(1) << DIZI_EARLY_FDT_FIXED_RESERVATIONS) - 1))
        return DiziEarlyWrongBoard;
      Report->AbiVersion = DIZI_EARLY_GUARD_ABI_VERSION;
      Report->ObservedFdtBytes = total;
      Report->MemoryBanks = banks;
      Report->FixedReservations = fixed;
      Report->DynamicReservations = dynamic;
      Report->FdtStructurallyConsistent = 1;
      /* NEVER set report's attestation or CanEnterPrePi fields to TRUE. */
      return DiziEarlyStructureOnly;
    default:
      return DiziEarlyFdtBounds;
    }
  }
  return DiziEarlyFdtBounds;
}
