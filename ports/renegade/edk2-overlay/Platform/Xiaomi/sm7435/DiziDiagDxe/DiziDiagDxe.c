/** @file
  Genuine EDK2 DXE driver, no kernel-mode stand-in and no firmware writes.

  Only accepts the already observed dizi ABL-initialized framebuffer exposed
  through EFI_GRAPHICS_OUTPUT_PROTOCOL. The DXE dispatcher invokes this after
  a GOP provider is installed. It does NOT invent a GOP, initialize DSI,
  authorize DRAM, enumerate UFS or touch SMMU/PMIC/GIC device registers.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

#define DIZI_FB_PHYSICAL_ADDRESS  0xB8000000ULL
#define DIZI_FB_WIDTH             1600U
#define DIZI_FB_HEIGHT            2560U
#define DIZI_FB_STRIDE_PIXELS     1600U
#define DIZI_FB_MIN_BYTES         0x00FA0000ULL
#define DIZI_FB_RESERVED_BYTES    0x02B00000ULL

EFI_STATUS EFIAPI
DiziDiagEntry (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
  EFI_STATUS Status;

  (VOID)ImageHandle;
  if (SystemTable == NULL || SystemTable->BootServices == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Gop = NULL;
  Status = SystemTable->BootServices->LocateProtocol(
                                   &gEfiGraphicsOutputProtocolGuid,
                                   NULL,
                                   (VOID **)&Gop);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (Gop == NULL || Gop->Mode == NULL || Gop->Mode->Info == NULL) {
    return EFI_NOT_READY;
  }
  Info = Gop->Mode->Info;
  if (Gop->Mode->FrameBufferBase != DIZI_FB_PHYSICAL_ADDRESS ||
      Gop->Mode->FrameBufferSize < DIZI_FB_MIN_BYTES ||
      Gop->Mode->FrameBufferSize > DIZI_FB_RESERVED_BYTES ||
      Info->HorizontalResolution != DIZI_FB_WIDTH ||
      Info->VerticalResolution != DIZI_FB_HEIGHT ||
      Info->PixelsPerScanLine != DIZI_FB_STRIDE_PIXELS ||
      Info->PixelFormat != PixelBlueGreenRedReserved8BitPerColor) {
    return EFI_UNSUPPORTED;
  }

  /* ConOut is optional at the moment GOP appears. A validated GOP provider
   * is already responsible for the hardware state; only use UEFI text IO. */
  if (SystemTable->ConOut != NULL &&
      SystemTable->ConOut->OutputString != NULL) {
    (VOID)SystemTable->ConOut->OutputString(
                         SystemTable->ConOut,
                         L"Renegade EDK2: POCO Pad dizi GOP verified\r\n");
  }
  return EFI_SUCCESS;
}
