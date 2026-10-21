/** @file
  Strictly bounded, READ-ONLY Android GKI-v4 -> EDK2 FD source planning.

  The caller supplies an already accessible FDT/initrd buffer and an
  independently pinned exact SHA256 digest. This does not verify physical
  memory ownership or perform an executable SEC handoff. A VALID_LAYOUT
  result is intentionally NOT an authorization or an entry point address.

  QcomPkg/PrePi/ModuleEntryPoint.S writes PcdDeviceTreeStore (0x90400000)
  before its PlatformInitialize ownership gate. DO NOT transfer to SEC until
  those writes, ARMv8 EL1 MMU/cache and Gunyah stage-2 permissions have
  been independently verified on live dizi hardware.
**/
#ifndef DIZI_GKI_HANDOFF_H
#define DIZI_GKI_HANDOFF_H

#include <stddef.h>
#include <stdint.h>

#define DIZI_FD_BASE UINT64_C(0x90000000)
#define DIZI_FD_SIZE UINT64_C(0x00400000)
#define DIZI_FD_STAGING_END (DIZI_FD_BASE + DIZI_FD_SIZE)
#define DIZI_FDT_STORE UINT64_C(0x90400000)
#define DIZI_VECTOR_BASE UINT64_C(0x90401000)
#define DIZI_STACK_BASE UINT64_C(0x90fc0000)
#define DIZI_EARLY_REGION_END UINT64_C(0x91000000)
#define DIZI_GKI_MAX_DTB (2u * 1024u * 1024u)
#define DIZI_GKI_MAX_INITRD (128u * 1024u * 1024u)

enum dizi_gki_result {
  DIZI_GKI_BAD_REQUEST = -1,
  DIZI_GKI_BAD_FDT = -2,
  DIZI_GKI_WRONG_BOARD = -3,
  DIZI_GKI_INITRD_MISMATCH = -4,
  DIZI_GKI_FD_MISSING = -5,
  DIZI_GKI_FD_INVALID = -6,
  DIZI_GKI_FD_HASH = -7,
  DIZI_GKI_FD_AMBIGUOUS = -8,
  DIZI_GKI_MEMORY_CONFLICT = -9,
  DIZI_GKI_LAYOUT_UNAUTHORIZED = 1
};

typedef struct {
  const uint8_t *fdt;
  size_t fdt_capacity;
  const uint8_t *initrd;
  size_t initrd_bytes;
  uint64_t initrd_physical;
  uint8_t exact_fd_sha256[32];   /* Source-pinned hash, never inferred from FD */
} DIZI_GKI_REQUEST;

typedef struct {
  size_t source_offset;
  size_t fd_bytes;
  uint64_t fd_destination_pa;    /* Candidate only, NOT runtime ownership */
  uint32_t sec_branch_word;
  uint32_t sec_branch_target_offset; /* Not independently verified executable */
  uint32_t dynamic_reservation_count;
  uint8_t actual_sha256[32];
  uint8_t authorized_to_copy_or_execute; /* ALWAYS ZERO */
} DIZI_GKI_PLAN;

/* Returns DIZI_GKI_LAYOUT_UNAUTHORIZED for structurally sound candidates. */
int dizi_gki_fd_plan(const DIZI_GKI_REQUEST *request, DIZI_GKI_PLAN *plan);

/* Inert host/isolated RAM transport only: no live physical mapping/BR.
   Copies only into explicit, nonaliasing, already owned software buffer. */
int dizi_gki_copy_to_private(const DIZI_GKI_REQUEST *request,
                             const DIZI_GKI_PLAN *plan,
                             uint8_t *private_copy, size_t capacity);

#endif
