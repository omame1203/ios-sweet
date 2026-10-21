/** @file
  dizi-specific, single-core GICv3 Group1 virtual PPI27 timer DXE.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  DEFAULT: entry returns EFI_UNSUPPORTED without reading or writing ANY GIC,
  GICR, timer, CPU interrupt or MMIO register, and publishes NO protocols.

  Opt-in requires BOTH DIZI_GIC_TIMER_ENABLE=1 and
  DIZI_GIC_TIMER_OWNER_IMPL_PRESENT=1 plus an independently authored,
  trusted DiziGicTimerGetTrustedGrant() implementation. An opt-in compile
  without that external object fails at LINK TIME. Arbitrary flags or a
  saved FDT can never impersonate the missing firmware ownership proof.

  The owner implementation must have independent ABL/Gunyah/EL2/XPU
  evidence for: GICD + CPU0 GICR access, PPI27 Group1 exclusive ownership,
  ICC_* EL1 sysreg and CNTV_* access without traps, IRQ vector takeover,
  and identity mappings while boot services live. This driver never
  traverses unknown GICR windows, writes WAKER, changes GICD_CTLR, changes
  routing/other PPIs, or enables the physical timer PPI30.
**/
#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include "DiziGicTimerPlan.h"

#if defined(DIZI_GIC_TIMER_ENABLE) && DIZI_GIC_TIMER_ENABLE == 1 && \
    defined(DIZI_GIC_TIMER_OWNER_IMPL_PRESENT) && DIZI_GIC_TIMER_OWNER_IMPL_PRESENT == 1
#define DIZI_GT_NATIVE 1
#else
#define DIZI_GT_NATIVE 0
#endif

#if DIZI_GT_NATIVE
#include <Library/ArmLib.h>
#include <Library/ArmGicLib.h>
#include <Library/ArmGenericTimerCounterLib.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Protocol/Cpu.h>
#include <Protocol/HardwareInterrupt.h>
#include <Protocol/Timer.h>

#define GICR_WAKER             0x0014
#define GICR_TYPER             0x0008
#define GICR_SGI_BASE          0x10000
#define GICR_IGROUPR0          (GICR_SGI_BASE + 0x0080)
#define GICR_ISENABLER0        (GICR_SGI_BASE + 0x0100)
#define GICR_ICENABLER0        (GICR_SGI_BASE + 0x0180)
#define GICR_IPRIORITYR27     (GICR_SGI_BASE + 0x0400 + DIZI_GT_VTIMER_PPI)
#define GICR_ICFGR1           (GICR_SGI_BASE + 0x0c04)
#define GICD_CTLR             0x0000
#define DIZI_TIMER_DEFAULT_PERIOD UINT64_C(100000) /* 10 ms in 100ns */

/* Implemented only by independent trusted platform owner with hardware
 * proof. Do not add a library returning success from unverified DTS data.
 * The external implementation MUST refuse grants after platform handoff
 * is invalid, otherwise runtime can be unsafe despite this driver. */
extern EFI_STATUS EFIAPI
DiziGicTimerGetTrustedGrant(struct DiziGicTimerGrant *grant);

static EFI_CPU_ARCH_PROTOCOL *mCpu;
static EFI_HANDLE mHandle;
static EFI_EVENT mExitEvent;
static EFI_TIMER_NOTIFY mNotify;
static HARDWARE_INTERRUPT_HANDLER mPpiHandler;
static UINT64 mPeriod;
static UINT64 mTicks;
static UINT64 mNextCompare;
static BOOLEAN mTimerArmed;
static BOOLEAN mInstalled;

static EFI_STATUS EFIAPI
GtEnable(EFI_HARDWARE_INTERRUPT_PROTOCOL *This, HARDWARE_INTERRUPT_SOURCE source)
{
  (void)This;
  if (!mInstalled || source != DIZI_GT_VTIMER_PPI) return EFI_UNSUPPORTED;
  MmioWrite32(DIZI_GT_GICR_BASE + GICR_ISENABLER0, DIZI_GT_PPI_BIT);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtDisable(EFI_HARDWARE_INTERRUPT_PROTOCOL *This, HARDWARE_INTERRUPT_SOURCE source)
{
  (void)This;
  if (!mInstalled || source != DIZI_GT_VTIMER_PPI) return EFI_UNSUPPORTED;
  MmioWrite32(DIZI_GT_GICR_BASE + GICR_ICENABLER0, DIZI_GT_PPI_BIT);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtState(EFI_HARDWARE_INTERRUPT_PROTOCOL *This, HARDWARE_INTERRUPT_SOURCE source,
        BOOLEAN *state)
{
  (void)This;
  if (state == NULL) return EFI_INVALID_PARAMETER;
  if (!mInstalled || source != DIZI_GT_VTIMER_PPI) return EFI_UNSUPPORTED;
  *state = (MmioRead32(DIZI_GT_GICR_BASE + GICR_ISENABLER0) & DIZI_GT_PPI_BIT) != 0;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtEoi(EFI_HARDWARE_INTERRUPT_PROTOCOL *This, HARDWARE_INTERRUPT_SOURCE source)
{
  (void)This;
  if (!mInstalled || source != DIZI_GT_VTIMER_PPI) return EFI_UNSUPPORTED;
  ArmGicV3EndOfInterrupt((UINT32)source);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtRegister(EFI_HARDWARE_INTERRUPT_PROTOCOL *This, HARDWARE_INTERRUPT_SOURCE source,
           HARDWARE_INTERRUPT_HANDLER handler)
{
  (void)This;
  (void)handler;
  if (!mInstalled || source != DIZI_GT_VTIMER_PPI) return EFI_UNSUPPORTED;
  /* The DXE architectural timer irrevocably owns PPI27. Allowing an
   * unrelated driver to unregister/replace its callback could leave the
   * virtual timer enabled with no forward progress. */
  return EFI_ACCESS_DENIED;
}

static EFI_HARDWARE_INTERRUPT_PROTOCOL mInterrupt = {
  GtRegister, GtEnable, GtDisable, GtState, GtEoi
};

static EFI_STATUS EFIAPI
GtTimerRegister(EFI_TIMER_ARCH_PROTOCOL *This, EFI_TIMER_NOTIFY notify)
{
  (void)This;
  if (!mInstalled) return EFI_NOT_READY;
  if (notify == NULL && mNotify == NULL) return EFI_INVALID_PARAMETER;
  if (notify != NULL && mNotify != NULL) return EFI_ALREADY_STARTED;
  mNotify = notify;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtTimerSetPeriod(EFI_TIMER_ARCH_PROTOCOL *This, UINT64 period)
{
  uint64_t ticks;
  EFI_TPL oldTpl;
  (void)This;
  if (!mInstalled) return EFI_NOT_READY;
  if (!DiziGicTimerPlanTicks(period, DIZI_GT_TIMER_HZ, &ticks))
    return EFI_UNSUPPORTED;
  oldTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
  ArmGenericTimerDisableTimer();
  mTimerArmed = FALSE;
  mPeriod = period;
  mTicks = ticks;
  if (ticks != 0) {
    mNextCompare = ArmGenericTimerGetSystemCount() + ticks;
    ArmGenericTimerSetCompareVal(mNextCompare);
    ArmGenericTimerEnableTimer();
    mTimerArmed = TRUE;
  }
  gBS->RestoreTPL(oldTpl);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtTimerGetPeriod(EFI_TIMER_ARCH_PROTOCOL *This, UINT64 *period)
{
  (void)This;
  if (period == NULL) return EFI_INVALID_PARAMETER;
  if (!mInstalled) return EFI_NOT_READY;
  *period = mPeriod;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GtTimerSoftInterrupt(EFI_TIMER_ARCH_PROTOCOL *This)
{
  (void)This;
  return EFI_UNSUPPORTED; /* allowed by EFI_TIMER_ARCH_PROTOCOL */
}

static EFI_TIMER_ARCH_PROTOCOL mTimer = {
  GtTimerRegister, GtTimerSetPeriod, GtTimerGetPeriod, GtTimerSoftInterrupt
};

static VOID EFIAPI
GtOnPpi(HARDWARE_INTERRUPT_SOURCE source, EFI_SYSTEM_CONTEXT context)
{
  UINT64 now, elapsed, next;
  EFI_TPL oldTpl;
  (void)context;
  if (source != DIZI_GT_VTIMER_PPI) return;
  oldTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
  if (mTimerArmed && (ArmGenericTimerGetTimerCtrlReg() & ARM_ARCH_TIMER_ISTATUS)) {
    now = ArmGenericTimerGetSystemCount();
    /* Compensate for missed periods without an unbounded interrupt loop. */
    elapsed = now >= mNextCompare ? 1 + (now - mNextCompare) / mTicks : 1;
    if (elapsed > UINT64_MAX / mTicks || mNextCompare > UINT64_MAX - elapsed * mTicks)
      next = now + mTicks;
    else
      next = mNextCompare + elapsed * mTicks;
    mNextCompare = next;
    ArmGenericTimerSetCompareVal(next);
    if (mNotify != NULL && elapsed <= UINT64_MAX / mPeriod)
      mNotify(mPeriod * elapsed);
  }
  ArmGicV3EndOfInterrupt((UINT32)source);
  gBS->RestoreTPL(oldTpl);
}

static VOID EFIAPI
GtIrq(EFI_EXCEPTION_TYPE type, EFI_SYSTEM_CONTEXT context)
{
  UINT32 id;
  (void)type;
  id = ArmGicV3AcknowledgeInterrupt();
  if (id >= 1020) return; /* GICv3 special/spurious, no EOI */
  if (id == DIZI_GT_VTIMER_PPI && mPpiHandler != NULL)
    mPpiHandler(id, context);
  else
    ArmGicV3EndOfInterrupt(id); /* exclusive Group1 IRQ grant only */
}

static VOID EFIAPI
GtExit(EFI_EVENT event, VOID *context)
{
  (void)event;
  (void)context;
  ArmGenericTimerDisableTimer();
  mTimerArmed = FALSE;
  MmioWrite32(DIZI_GT_GICR_BASE + GICR_ICENABLER0, DIZI_GT_PPI_BIT);
  mInstalled = FALSE;
  /* Leave GICD and all other IRQs untouched. Handoff owns ICC state. */
}

static EFI_STATUS
GtLiveSnapshot(struct DiziGicTimerSnapshot *snapshot)
{
  UINT64 currentEl = ArmReadCurrentEL();
  /* Trusted provider has already attested that these MMIO reads, CPU EL1
   * sysregs and GICR frame are mapped and cannot trap. */
  snapshot->current_el = (UINT32)(currentEl >> 2);
  if (snapshot->current_el != 1) return EFI_UNSUPPORTED;
  snapshot->current_mpidr = ArmReadMpidr();
  snapshot->cntfrq = ArmGenericTimerGetTimerFreq();
  snapshot->gicd_ctlr = MmioRead32(DIZI_GT_GICD_BASE + GICD_CTLR);
  snapshot->gicr_waker = MmioRead32(DIZI_GT_GICR_BASE + GICR_WAKER);
  snapshot->gicr_typer = MmioRead64(DIZI_GT_GICR_BASE + GICR_TYPER);
  snapshot->gicr_igroupr0 = MmioRead32(DIZI_GT_GICR_BASE + GICR_IGROUPR0);
  snapshot->gicr_icfgr1 = MmioRead32(DIZI_GT_GICR_BASE + GICR_ICFGR1);
  return EFI_SUCCESS;
}

static EFI_STATUS
GtInitialize(EFI_HANDLE imageHandle)
{
  EFI_STATUS status;
  struct DiziGicTimerGrant grant;
  struct DiziGicTimerSnapshot snapshot;
  VOID *already;
  (void)imageHandle;
  /* Grant is obtained from a separately reviewed real firmware/EL2 owner,
   * not a boolean in FDT/DSC; no implementation means opt-in LINK FAILURE. */
  status = DiziGicTimerGetTrustedGrant(&grant);
  if (EFI_ERROR(status)) return status;
  status = gBS->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);
  if (EFI_ERROR(status) || mCpu == NULL) return EFI_NOT_READY;
  if (!EFI_ERROR(gBS->LocateProtocol(&gHardwareInterruptProtocolGuid, NULL, &already)) ||
      !EFI_ERROR(gBS->LocateProtocol(&gEfiTimerArchProtocolGuid, NULL, &already)))
    return EFI_ALREADY_STARTED;
  status = GtLiveSnapshot(&snapshot);
  if (EFI_ERROR(status) || !DiziGicTimerPlanValidate(&grant, &snapshot))
    return EFI_ACCESS_DENIED;

  status = gBS->CreateEvent(EVT_SIGNAL_EXIT_BOOT_SERVICES, TPL_NOTIFY,
                            GtExit, NULL, &mExitEvent);
  if (EFI_ERROR(status)) return status;
  /* We require EXCLUSIVE CPU0 IRQ-vectored ownership: no coexistence with
   * an untrusted GIC owner. We deliberately refuse to overwrite an existing
   * non-default registered handler, if CpuDxe cannot remove it. */
  status = mCpu->RegisterInterruptHandler(mCpu, ARM_ARCH_EXCEPTION_IRQ, NULL);
  if (EFI_ERROR(status)) goto fail_event;
  status = mCpu->RegisterInterruptHandler(mCpu, ARM_ARCH_EXCEPTION_IRQ, GtIrq);
  if (EFI_ERROR(status)) goto fail_event;
  ArmGenericTimerDisableTimer();
  MmioWrite8(DIZI_GT_GICR_BASE + GICR_IPRIORITYR27, 0x80);
  ArmGicV3SetPriorityMask(0xff);
  ArmGicV3EnableInterruptInterface();
  mPpiHandler = GtOnPpi;
  mInstalled = TRUE;
  MmioWrite32(DIZI_GT_GICR_BASE + GICR_ISENABLER0, DIZI_GT_PPI_BIT);
  status = gBS->InstallMultipleProtocolInterfaces(&mHandle,
                            &gHardwareInterruptProtocolGuid, &mInterrupt,
                            &gEfiTimerArchProtocolGuid, &mTimer, NULL);
  if (EFI_ERROR(status)) goto fail_active;
  status = GtTimerSetPeriod(&mTimer, DIZI_TIMER_DEFAULT_PERIOD);
  if (!EFI_ERROR(status)) return EFI_SUCCESS;
  gBS->UninstallMultipleProtocolInterfaces(mHandle,
                            &gHardwareInterruptProtocolGuid, &mInterrupt,
                            &gEfiTimerArchProtocolGuid, &mTimer, NULL);
fail_active:
  ArmGenericTimerDisableTimer();
  MmioWrite32(DIZI_GT_GICR_BASE + GICR_ICENABLER0, DIZI_GT_PPI_BIT);
  mInstalled = FALSE;
  mCpu->RegisterInterruptHandler(mCpu, ARM_ARCH_EXCEPTION_IRQ, NULL);
fail_event:
  gBS->CloseEvent(mExitEvent);
  return status;
}
#endif

EFI_STATUS EFIAPI
DiziGicTimerDxeEntry(EFI_HANDLE imageHandle, EFI_SYSTEM_TABLE *systemTable)
{
  (void)imageHandle;
  (void)systemTable;
#if DIZI_GT_NATIVE
  return GtInitialize(imageHandle);
#else
  /* Safe in a normal build even if this INF is accidentally packed in FV:
   * absolutely NO MMIO reads/writes, timer sysregs or protocol publication. */
  return EFI_UNSUPPORTED;
#endif
}
