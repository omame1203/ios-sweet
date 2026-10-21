/** @file
  Post-trusted-owner, real AArch64 EDK2 FV copy/cache/SEC transfer contract.

  This is NOT a claim that the current POCO Pad loader grants ownership:
  DiziSecGetTrustedRuntimeGrant has NO implementation in this project.
  The production path cannot link without its independent, reviewed firmware
  provider. No FDT RAM, initrd, or destination is touched before that call.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef DIZI_SEC_TRANSFER_H
#define DIZI_SEC_TRANSFER_H

#include <stddef.h>
#include <stdint.h>

#define DIZI_SEC_TRANSFER_ABI 1u
#define DIZI_SEC_LOW_FV_PA UINT64_C(0x90000000)
#define DIZI_SEC_LOW_FV_SIZE UINT64_C(0x00400000)
#define DIZI_SEC_EARLY_END UINT64_C(0x91000000)

enum {
  DIZI_SEC_REFUSED = -1,
  DIZI_SEC_BAD_REQUEST = -2,
  DIZI_SEC_NO_OWNER = -3,
  DIZI_SEC_OWNER_MISMATCH = -4,
  DIZI_SEC_FDT_OR_FV_INVALID = -5,
  DIZI_SEC_COPY_INVALID = -6,
  DIZI_SEC_STAGED_NOT_EXECUTED = 1
};

typedef struct {
  uint64_t incoming_fdt_pa;   /* Linux Image x0; NOT dereferenced initially */
  uint64_t initrd_pa;         /* /chosen physical initrd */
  uint64_t initrd_bytes;
  uint64_t kernel_image_base;
  uint64_t kernel_image_bytes;
  uint8_t expected_fd_sha256[32];
} DIZI_SEC_INPUT;

typedef struct {
  uint32_t abi_version;
  uint32_t _reserved;
  const uint8_t *fdt_readable;
  size_t fdt_capacity;
  const uint8_t *initrd_readable;
  uint64_t initrd_bytes;
  uint8_t *fd_writable;
  uint64_t fd_pa;
  uint64_t fd_bytes;
} DIZI_SEC_GRANTED_MAPPING;

/* Must be provided by a DIFFERENT, independently audited ABL/EL2/XPU owner
 * that proves the complete [0x90000000,0x91000000) region is exclusive,
 * all overlapping dynamic reservations and live loaders are absent, the
 * source FDT/initrd are readable, CPU at EL1 with MMU off and DAIF masked,
 * all affected mappings/cache maintenance allowed, and DMA quiesced.
 *
 * Never implement this by trusting an unverified DTB, a boolean field,
 * fastboot's OKAY reply or bootloader-unlock status. This symbol is
 * intentionally UNSATISFIED; source-only opt-in builds must fail at link.
 */
extern int DiziSecGetTrustedRuntimeGrant(
    const DIZI_SEC_INPUT *request, DIZI_SEC_GRANTED_MAPPING *result);

/* Stages the real FD (including exact SHA256) under an independently
 * verified mapping and performs architectural cache maintenance. It does
 * NOT jump merely because parsing succeeded. Default build always refuses.
 */
int DiziSecStageFirmware(const DIZI_SEC_INPUT *request);

/* The actual handoff: stage exact FV + architectural PoC/PoU cache sync,
 * then branch into GenFv's AArch64 SEC vector. Returns a denial if the
 * independent owner provider is not compiled and linked; NEVER invents
 * success for a merely valid FV/FDT. A successful BR does not return. */
int DiziSecTryBoot(const DIZI_SEC_INPUT *request);

/* The caller is a separately audited first-PC wrapper with a trusted stack.
 * After DiziSecStageFirmware returns DIZI_SEC_STAGED_NOT_EXECUTED, branch
 * through GenFv's AArch64 B SEC vector with x0=original physical FDT.
 * NO active branch is emitted unless both owner compile gates are set.
 */
void DiziSecEnterPrePi(uint64_t fdt_pa, uint64_t fv_pa)
    __attribute__((noreturn));

#endif
