/** @file
  SM7435 dizi pre-PEI platform entry. No donor GICR_WAKER writes.
  No undocumented framebuffer console-tail writes, no blind serial clock
  enable and NO automatic USB/UFS/GPI/SMMU DMA. Default: CpuDeadLoop().

  The early Renegade integration must first build true boot-handoff evidence
  (physical RAM/XPU/EL1/EL2/current FDT, all reservations), authorize the
  memory library, and only then call PlatformInitialize(). Merely copying
  saved /backup/dizi/fdt to RAM cannot satisfy that contract.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/BaseLib.h>
#include <Library/DiziSm7435Memory.h>

/* Optional isolated first-instruction EDK2 proof. This block is completely
   absent in the default production build. The framebuffer was exercised by
   the already running dizi GKI shim at PA 0xb8000000; no donor UART/GIC.
   Requires MANUAL independent approval of identity mapping and ownership.
   It DOES change up to 64 display bytes, but no persistent storage or MMIO. */
#if defined(DIZI_EDK2_PREPI_DIAGNOSTIC) && DIZI_EDK2_PREPI_DIAGNOSTIC == 1
#if !defined(__aarch64__) || !defined(DIZI_EDK2_PREPI_FB_REVIEWED) || \
    DIZI_EDK2_PREPI_FB_REVIEWED != 1
#error EDK2 diagnostic requires AArch64 plus explicit framebuffer review opt-in
#endif
static VOID DiziSm7435DiagnosticPixelRow(VOID)
{
  UINT64 El;
  UINT64 Sctlr;
  volatile UINT32 *Fb;
  UINTN Index;

  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ volatile ("mrs %0, SCTLR_EL1" : "=r" (Sctlr));
  /* Only EL1 physical identity addressing while MMU disabled can use the
     previously observed physical splash address without guessed page tables.
     No attempt to remap GPU/display registers, enable interrupts or clocks. */
  if (El != 4 || (Sctlr & 1) != 0)
    CpuDeadLoop();

  /* First line, pixels 0..15 of the known 1600x2560 RGBA framebuffer;
     0xb8000000 and 0x2b00000 reservation come from captured dizi FDT.
     Display bytes may still be inaccessible under Gunyah/XPU; this is NOT
     asserted safe or tested on hardware, even when manually enabled. */
  Fb = (volatile UINT32 *)(UINTN)UINT64_C(0xb8000000);
  for (Index = 0; Index < 16; ++Index)
    Fb[Index] = UINT32_C(0xffff00ff);
  __asm__ volatile ("dsb sy" ::: "memory");
  CpuDeadLoop(); /* Never advance into unverified PEI or DXE. */
}
#endif

VOID PlatformInitialize(VOID)
{
#if defined(DIZI_EDK2_PREPI_DIAGNOSTIC) && DIZI_EDK2_PREPI_DIAGNOSTIC == 1
  DiziSm7435DiagnosticPixelRow();
#endif
  if (!DiziSm7435PlatformMemoryAuthorized()) {
    /* Never let EDK2 enter PEI with zero verified allocator bytes. */
    CpuDeadLoop();
  }
  /* The Qualcomm ABL handoff has already initialized the primary CPU.
     GIC WAKER, SMP enable, PLLs, clocks, TLMM and serial remain unchanged.
     Board-level console needs a separate verified 1600x2560 GOP driver. */
}
