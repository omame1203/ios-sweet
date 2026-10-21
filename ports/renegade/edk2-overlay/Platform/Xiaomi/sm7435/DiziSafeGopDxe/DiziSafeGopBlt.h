/** @file
  Bounded, freestanding CPU-side BGRA8888 GOP operations.
  No MMIO setup, cache maintenance, full reservation clear or device I/O.
  The caller MUST obtain an independently validated and pinned CPU mapping.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef DIZI_SAFE_GOP_BLT_H
#define DIZI_SAFE_GOP_BLT_H

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

#define DIZI_GOP_FB_PA             0xB8000000ULL
#define DIZI_GOP_RESERVED_BYTES    0x02B00000ULL
#define DIZI_GOP_WIDTH             1600U
#define DIZI_GOP_HEIGHT            2560U
#define DIZI_GOP_STRIDE_PIXELS     1600U
#define DIZI_GOP_VISIBLE_BYTES     0x00FA0000ULL
#define DIZI_GOP_BYTES_PER_PIXEL   4U

EFI_STATUS
DiziSafeBlt (
  IN volatile UINT8                         *CpuVisible,
  IN UINTN                                  MappedBytes,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL          *BltBuffer OPTIONAL,
  IN EFI_GRAPHICS_OUTPUT_BLT_OPERATION      Operation,
  IN UINTN                                  SourceX,
  IN UINTN                                  SourceY,
  IN UINTN                                  DestinationX,
  IN UINTN                                  DestinationY,
  IN UINTN                                  Width,
  IN UINTN                                  Height,
  IN UINTN                                  Delta
  );

#endif
