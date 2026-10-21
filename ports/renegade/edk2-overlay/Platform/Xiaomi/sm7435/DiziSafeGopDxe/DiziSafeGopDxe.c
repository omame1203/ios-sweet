/** @file
  EDK2 DXE Graphics Output Protocol for verified *inherited* dizi scanout.
  No automatic ZeroMem, panel power, GIC or clock changes.

  FAIL CLOSED twice: DSC/FDF exclude this driver by default, and even a
  separately compiled module returns EFI_UNSUPPORTED until BOTH source
  integration switches and an independent current-boot ownership grant exist.
  The in-tree sources deliberately implement NO ownership grant provider.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>
#include <Library/UefiBootServicesTableLib.h>
#include "DiziSafeGopDxe.h"

#if defined(DIZI_SAFE_GOP_ENABLE) && DIZI_SAFE_GOP_ENABLE == 1 && \
    defined(DIZI_SAFE_GOP_GRANT_INTEGRATED) && \
    DIZI_SAFE_GOP_GRANT_INTEGRATED == 1
#define DIZI_SAFE_GOP_ACTIVE 1
#else
#define DIZI_SAFE_GOP_ACTIVE 0
#endif

#if DIZI_SAFE_GOP_ACTIVE
static EFI_GUID mGrantGuid = DIZI_SAFE_GOP_GRANT_GUID;
static EFI_GRAPHICS_OUTPUT_MODE_INFORMATION mInfo = {
  0, DIZI_GOP_WIDTH, DIZI_GOP_HEIGHT,
  PixelBlueGreenRedReserved8BitPerColor, { 0, 0, 0, 0 },
  DIZI_GOP_STRIDE_PIXELS
};
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE mMode = {
  1, 0, &mInfo, sizeof(mInfo), DIZI_GOP_FB_PA, DIZI_GOP_VISIBLE_BYTES
};
static EFI_GRAPHICS_OUTPUT_PROTOCOL mGop;
static EFI_HANDLE mHandle;
static DIZI_SAFE_GOP_GRANT *mGrant;

static EFI_STATUS
CurrentMapping (UINT32 Request, DIZI_SAFE_GOP_MAPPING *Out)
{
  EFI_STATUS Status;
  if (mGrant == NULL || mGrant->Validate == NULL || Out == NULL ||
      mGrant->Version != DIZI_SAFE_GOP_GRANT_VERSION ||
      mGrant->Size != sizeof(*mGrant) ||
      (Request != DIZI_SAFE_GOP_GRANT_READ &&
       Request != DIZI_SAFE_GOP_GRANT_WRITE &&
       Request != DIZI_SAFE_GOP_GRANT_CLEAR)) {
    return EFI_ACCESS_DENIED;
  }
  Out->CpuIdentityAddress = NULL;
  Out->OwnershipAccess = 0;
  Status = mGrant->Validate(mGrant, Request, Out);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (Out->FrameBufferPa != DIZI_GOP_FB_PA ||
      Out->CpuIdentityAddress != (volatile UINT8 *)(UINTN)DIZI_GOP_FB_PA ||
      Out->MappedBytes < DIZI_GOP_VISIBLE_BYTES ||
      Out->MappedBytes > DIZI_GOP_RESERVED_BYTES ||
      Out->Width != DIZI_GOP_WIDTH || Out->Height != DIZI_GOP_HEIGHT ||
      Out->PixelsPerScanLine != DIZI_GOP_STRIDE_PIXELS ||
      Out->BitsPerPixel != 32 ||
      Out->OwnershipAccess != DIZI_SAFE_GOP_REQUIRED_ACCESS) {
    return EFI_ACCESS_DENIED;
  }
  /* This function checks contract shape, NOT the identity or veracity of
   * the provider. A trusted protocol *installation path* is a prerequisite.
   * Further, Validate must pin the mapping throughout the entire GOP call.
   * Revocation, cache coherency and EL2 changes cannot be proven here. */
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
QueryMode (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
  IN UINT32 ModeNumber,
  OUT UINTN *SizeOfInfo,
  OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info
  )
{
  EFI_STATUS Status;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Allocated;
  if (This != &mGop || ModeNumber != 0 || SizeOfInfo == NULL ||
      Info == NULL || gBS == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Info = NULL;
  *SizeOfInfo = 0;
  Allocated = NULL;
  Status = gBS->AllocatePool(EfiBootServicesData, sizeof(mInfo),
                             (VOID **)&Allocated);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (Allocated == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  Allocated->Version = mInfo.Version;
  Allocated->HorizontalResolution = mInfo.HorizontalResolution;
  Allocated->VerticalResolution = mInfo.VerticalResolution;
  Allocated->PixelFormat = mInfo.PixelFormat;
  Allocated->PixelInformation.RedMask = 0;
  Allocated->PixelInformation.GreenMask = 0;
  Allocated->PixelInformation.BlueMask = 0;
  Allocated->PixelInformation.ReservedMask = 0;
  Allocated->PixelsPerScanLine = mInfo.PixelsPerScanLine;
  *Info = Allocated;
  *SizeOfInfo = sizeof(mInfo);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
SetMode (IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This, IN UINT32 ModeNumber)
{
  DIZI_SAFE_GOP_MAPPING Mapping;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL Black = { 0, 0, 0, 0 };
  EFI_STATUS Status;
  if (This != &mGop || ModeNumber != 0) {
    return EFI_UNSUPPORTED;
  }
  /* UEFI GOP SetMode must clear the visible scanout. This is NEVER done
   * at driver entry. An independent owner must grant explicit CLEAR before
   * calling the bounded Fill primitive; the RESERVED TAIL is untouched. */
  Status = CurrentMapping(DIZI_SAFE_GOP_GRANT_CLEAR, &Mapping);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  return DiziSafeBlt(Mapping.CpuIdentityAddress, Mapping.MappedBytes,
                     &Black, EfiBltVideoFill, 0, 0, 0, 0,
                     DIZI_GOP_WIDTH, DIZI_GOP_HEIGHT, 0);
}

static EFI_STATUS EFIAPI
GopBlt (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer OPTIONAL,
  IN EFI_GRAPHICS_OUTPUT_BLT_OPERATION Operation,
  IN UINTN SourceX, IN UINTN SourceY, IN UINTN DestinationX,
  IN UINTN DestinationY, IN UINTN Width, IN UINTN Height, IN UINTN Delta
  )
{
  DIZI_SAFE_GOP_MAPPING Mapping;
  UINT32 Access;
  EFI_STATUS Status;
  if (This != &mGop) {
    return EFI_INVALID_PARAMETER;
  }
  if (Operation >= EfiGraphicsOutputBltOperationMax) {
    return EFI_INVALID_PARAMETER;
  }
  Access = Operation == EfiBltVideoToBltBuffer
           ? DIZI_SAFE_GOP_GRANT_READ : DIZI_SAFE_GOP_GRANT_WRITE;
  Status = CurrentMapping(Access, &Mapping);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  return DiziSafeBlt(Mapping.CpuIdentityAddress, Mapping.MappedBytes,
                     BltBuffer, Operation, SourceX, SourceY,
                     DestinationX, DestinationY, Width, Height, Delta);
}
#endif

EFI_STATUS EFIAPI
DiziSafeGopEntry (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  (VOID)ImageHandle;
  if (SystemTable == NULL || SystemTable->BootServices == NULL) {
    return EFI_INVALID_PARAMETER;
  }
#if DIZI_SAFE_GOP_ACTIVE
  EFI_STATUS Status;
  DIZI_SAFE_GOP_MAPPING Mapping;
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Existing;
  if (gBS == NULL || gBS != SystemTable->BootServices) {
    return EFI_ACCESS_DENIED;
  }
  Existing = NULL;
  Status = gBS->LocateProtocol(&gEfiGraphicsOutputProtocolGuid, NULL,
                                (VOID **)&Existing);
  if (!EFI_ERROR(Status) || Status != EFI_NOT_FOUND) {
    /* Never replace, race, or mask another GOP implementation. */
    return EFI_ACCESS_DENIED;
  }
  mGrant = NULL;
  Status = gBS->LocateProtocol(&mGrantGuid, NULL, (VOID **)&mGrant);
  if (EFI_ERROR(Status) || mGrant == NULL) {
    return EFI_ACCESS_DENIED;
  }
  Status = CurrentMapping(DIZI_SAFE_GOP_GRANT_READ, &Mapping);
  if (EFI_ERROR(Status)) {
    mGrant = NULL;
    return Status;
  }
  mGop.QueryMode = QueryMode;
  mGop.SetMode = SetMode;
  mGop.Blt = GopBlt;
  mGop.Mode = &mMode;
  mHandle = NULL;
  /* Installation leaves inherited frame bytes untouched. */
  Status = gBS->InstallMultipleProtocolInterfaces(
                   &mHandle, &gEfiGraphicsOutputProtocolGuid, &mGop, NULL);
  if (EFI_ERROR(Status)) {
    mGrant = NULL;
  }
  return Status;
#else
  /* Independent ownership-verifier is ABSENT in the present overlay. */
  return EFI_UNSUPPORTED;
#endif
}
