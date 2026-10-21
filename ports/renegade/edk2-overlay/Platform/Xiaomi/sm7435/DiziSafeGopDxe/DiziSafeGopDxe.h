/** @file
  Independent, externally-provided scanout ownership contract.

  NO PRODUCER is bundled with this experimental board overlay. A GUID and
  self-reported flags are NOT hardware proof. A separate reviewed ABL/EL2/XPU
  owner must implement and register Validate for the current boot handoff,
  including live reserved-memory, stage-1 and stage-2 access, cache attributes,
  scanout lifetime, and exclusive display ownership. A fabricated protocol
  must NEVER be accepted as an attestation.

  No built-in grant fallback, no GPIO/DSI/PLL init, no SMMU/UFS writes.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef DIZI_SAFE_GOP_DXE_H
#define DIZI_SAFE_GOP_DXE_H

#include <Uefi.h>
#include "DiziSafeGopBlt.h"

#define DIZI_SAFE_GOP_GRANT_GUID \
  { 0x0fd8641e, 0x85ca, 0x4c30, { 0x96, 0xa5, 0x13, 0xcd, 0x8e, 0x3b, 0xe9, 0x74 } }

#define DIZI_SAFE_GOP_GRANT_VERSION  1U
#define DIZI_SAFE_GOP_GRANT_READ     1U
#define DIZI_SAFE_GOP_GRANT_WRITE    2U
#define DIZI_SAFE_GOP_GRANT_CLEAR    4U

/* Independent owner must have already verified every one of these.
 * The driver does not discover or assert them from a saved Android FDT.
 */
#define DIZI_SAFE_GOP_ACCESS_EL1_IDENTITY       0x01U
#define DIZI_SAFE_GOP_ACCESS_EL2_STAGE2         0x02U
#define DIZI_SAFE_GOP_ACCESS_XPU_DISPLAY        0x04U
#define DIZI_SAFE_GOP_ACCESS_MEMORY_ATTRIBUTES  0x08U
#define DIZI_SAFE_GOP_ACCESS_EXCLUSIVE_OWNER    0x10U
#define DIZI_SAFE_GOP_ACCESS_SCANOUT_LIFETIME   0x20U
#define DIZI_SAFE_GOP_REQUIRED_ACCESS           0x3fU

typedef struct _DIZI_SAFE_GOP_GRANT DIZI_SAFE_GOP_GRANT;

typedef struct {
  EFI_PHYSICAL_ADDRESS  FrameBufferPa;
  volatile UINT8        *CpuIdentityAddress;
  UINTN                 MappedBytes;
  UINT32                Width;
  UINT32                Height;
  UINT32                PixelsPerScanLine;
  UINT32                BitsPerPixel;
  UINT32                OwnershipAccess;
} DIZI_SAFE_GOP_MAPPING;

typedef EFI_STATUS (EFIAPI *DIZI_SAFE_GOP_VALIDATE) (
  IN DIZI_SAFE_GOP_GRANT *Grant,
  IN UINT32 Operation,
  OUT DIZI_SAFE_GOP_MAPPING *Mapping
  );

struct _DIZI_SAFE_GOP_GRANT {
  UINT32                  Version;
  UINT32                  Size;
  DIZI_SAFE_GOP_VALIDATE  Validate; /* provider pins verified mapping for call */
};

EFI_STATUS EFIAPI DiziSafeGopEntry (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  );

#endif
