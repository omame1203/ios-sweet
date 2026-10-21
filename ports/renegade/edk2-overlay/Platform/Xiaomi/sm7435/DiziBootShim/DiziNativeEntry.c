/** @file
  Host-side/freestanding metadata validator for the genuine dizi Linux Image
  produced by DiziNativeEntry.S and DiziNativeEntry.ld.

  This is intentionally NOT linked or called at native first PC: a C ABI
  normally needs a usable stack, and no memory/stack region is independently
  known to be writable on dizi before QcomPkg PrePi first writes 0x90400000.
  Success here means only "correct initial Linux Image shape", NOT proof of
  runtime RAM or permission to enter EDK2.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "DiziNativeEntry.h"

static uint32_t get_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_le64(const uint8_t *p) {
  return (uint64_t)get_le32(p) |
         ((uint64_t)get_le32(p + 4) << 32);
}

int dizi_native_image_header_valid(const uint8_t *image, size_t count,
                                   uint32_t *first_pc_offset) {
  uint32_t first;
  size_t i;
  if (first_pc_offset) *first_pc_offset=0;
  if (!image || !first_pc_offset || count!=DIZI_NATIVE_PAGE_BYTES)
    return 0;
  first=get_le32(image);
  if ((first >> 26)!=5)    /* AArch64 B immediate, NOT a fake NOP/MZ stub */
    return 0;
  /* This exact source always enters at +64 and never jumps into FV RAM.
     A bootloader might load the image at any supported address. */
  if ((first & 0x03ffffffu)!=DIZI_NATIVE_IMAGE_HEADER_BYTES / 4u)
    return 0;
  if (get_le32(image+4)!=0 ||
      get_le64(image+8)!=0 ||
      get_le64(image+16)!=count ||
      get_le64(image+24)!=DIZI_NATIVE_IMAGE_FLAGS ||
      get_le32(image+56)!=UINT32_C(0x644d5241) ||
      get_le32(image+60)!=0)
    return 0;
  for (i=32;i<56;i++)
    if (image[i])return 0;
  if (!get_le32(image+DIZI_NATIVE_IMAGE_HEADER_BYTES))
    return 0;  /* The +64 first instruction must not be empty. */
  *first_pc_offset=DIZI_NATIVE_IMAGE_HEADER_BYTES;
  return 1;
}
