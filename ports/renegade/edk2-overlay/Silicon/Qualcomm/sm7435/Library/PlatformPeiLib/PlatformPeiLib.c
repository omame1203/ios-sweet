/** @file
  Renegade PlatformPeiLib entry for dizi: firmware-volume HOB only.
  No inherited SM7325 SHIM_LIBRARY_INFO_BLOCK GUIDs: their 0x9FFFF000
  and 0x9FC403D0 addresses are unverified on SM7435.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <PiPei.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/DiziSm7435Memory.h>

EFI_STATUS EFIAPI PlatformPeim(VOID)
{
  UINT64 FvBase;
  UINT64 FvLength;

  if (!DiziSm7435PlatformMemoryAuthorized())
    return EFI_NOT_READY;

  FvBase   = PcdGet64(PcdFvBaseAddress);
  FvLength = PcdGet32(PcdFvSize);
  if (FvBase < DIZI_SM7435_GRANT_BASE ||
      !FvLength || (FvBase & 0xFFF) || (FvLength & 0xFFF) ||
      FvBase - DIZI_SM7435_GRANT_BASE > DIZI_SM7435_GRANT_BYTES ||
      FvLength > DIZI_SM7435_GRANT_BYTES -
                     (FvBase - DIZI_SM7435_GRANT_BASE))
    return EFI_UNSUPPORTED;

  /* The HOB points ONLY at an FV already in independently owned DRAM.
     A valid FV signature, checksums and DXE trust remain another duty. */
  BuildFvHob(FvBase, FvLength);
  return EFI_SUCCESS;
}
