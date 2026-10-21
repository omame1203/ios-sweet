/** @file
  Register-only first-PC contract for a dizi GKI v4 native ARM64 Linux Image.

  These constants describe *why* the real AArch64 entry parks. They are
  observable in x16 on a halted PE by an independent debugger; they are NOT
  runtime evidence of successful firmware boot or permission to enter SEC.
  No physical RAM is read or written by this entry.

  See kernel.org Documentation/arch/arm64/booting.rst (Image header/x0..x3);
  real dizi boot_a.img, vendor_boot_a.img and Qualcomm QcomPkg/PrePi sources.
**/
#ifndef DIZI_NATIVE_ENTRY_H
#define DIZI_NATIVE_ENTRY_H

#define DIZI_NATIVE_IMAGE_FLAGS          0xA
#define DIZI_NATIVE_PAGE_BYTES           4096
#define DIZI_NATIVE_IMAGE_HEADER_BYTES   64

#define DIZI_NATIVE_REASON_BAD_FDT_X0     1
#define DIZI_NATIVE_REASON_FDT_ALIGNMENT  2
#define DIZI_NATIVE_REASON_NONZERO_X1     3
#define DIZI_NATIVE_REASON_NONZERO_X2     4
#define DIZI_NATIVE_REASON_NONZERO_X3     5
#define DIZI_NATIVE_REASON_WRONG_EL       6
#define DIZI_NATIVE_REASON_IRQ_UNMASKED   7
#define DIZI_NATIVE_REASON_FIQ_UNMASKED   8
#define DIZI_NATIVE_REASON_EL1_MMU_ON     9
#define DIZI_NATIVE_REASON_EL1_DCACHE_ON  10
#define DIZI_NATIVE_REASON_EL1_ICACHE_ON  11
/* The default success-to-here reason is a HARD STOP, not an owner grant. */
#define DIZI_NATIVE_REASON_NO_OWNER      12

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
/* Offline inspection of built ARM64 Image metadata only; not boot approval. */
int dizi_native_image_header_valid(const uint8_t *image, size_t count,
                                   uint32_t *first_pc_offset);
#endif

#endif
