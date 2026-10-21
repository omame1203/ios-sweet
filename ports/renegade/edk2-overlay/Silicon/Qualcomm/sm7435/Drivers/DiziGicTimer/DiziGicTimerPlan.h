/** @file
  Source-only dizi GICv3 + EL1 virtual timer ownership and register plan.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  The captured dizi DTB describes GICD 0x17200000, GICR 0x17260000,
  virtual timer PPI 27, physical timer PPI 30, generic counter 19.2 MHz.
  It does NOT prove that the ABL/Gunyah-owned interrupt controller can be
  reprogrammed. These POD structures are pure data; flag fields are NOT a
  hardware attestation. Only a separate, independently reviewed firmware
  owner can implement DiziGicTimerGetTrustedGrant().
**/
#ifndef DIZI_GIC_TIMER_PLAN_H
#define DIZI_GIC_TIMER_PLAN_H

#include <stdint.h>

#define DIZI_GT_GICD_BASE UINT64_C(0x17200000)
#define DIZI_GT_GICD_SIZE UINT64_C(0x00010000)
#define DIZI_GT_GICR_BASE UINT64_C(0x17260000)
#define DIZI_GT_GICR_SIZE UINT64_C(0x00020000)
#define DIZI_GT_VTIMER_PPI UINT32_C(27)
#define DIZI_GT_PHYS_PPI UINT32_C(30)
#define DIZI_GT_TIMER_HZ UINT32_C(19200000)
#define DIZI_GT_PPI_BIT (UINT32_C(1) << DIZI_GT_VTIMER_PPI)

/* All permissions must be attested by trusted EL2/ABL/Gunyah and firmware
 * handoff, not inferred from the device tree. All bits are required. */
#define DIZI_GT_OWN_GICD UINT32_C(0x0001)
#define DIZI_GT_OWN_GICR UINT32_C(0x0002)
#define DIZI_GT_OWN_EL1_ICC UINT32_C(0x0004)
#define DIZI_GT_OWN_EL1_CNTV UINT32_C(0x0008)
#define DIZI_GT_OWN_EXCLUSIVE_IRQ UINT32_C(0x0010)
#define DIZI_GT_OWN_HYPERVISOR UINT32_C(0x0020)
#define DIZI_GT_OWN_MMIO_MAPPING UINT32_C(0x0040)
#define DIZI_GT_ALL_PERMISSIONS UINT32_C(0x007f)

struct DiziGicTimerGrant {
  uint64_t gicd_base;
  uint64_t gicd_size;
  uint64_t gicr_base;
  uint64_t gicr_size;
  uint32_t timer_frequency;
  uint32_t timer_ppi;
  uint32_t core_count;
  uint32_t verified_permissions;
  uint64_t primary_mpidr_affinity;
};

/* Hardware register snapshot acquired only AFTER the trusted ownership
 * provider has granted safe reads. This routine itself does no I/O. */
struct DiziGicTimerSnapshot {
  uint32_t gicd_ctlr;
  uint32_t gicr_waker;
  uint32_t gicr_igroupr0;
  uint32_t gicr_icfgr1;
  uint64_t gicr_typer;
  uint64_t current_mpidr;
  uint32_t current_el;
  uint32_t cntfrq;
};

/* Error instead of guessing any ownership or CPU mapping. */
enum DiziGicTimerVerdict {
  DIZI_GT_REJECT = 0,
  DIZI_GT_ADMIT = 1
};

int DiziGicTimerPlanValidate(const struct DiziGicTimerGrant *grant,
                             const struct DiziGicTimerSnapshot *snapshot);

/* 100ns UEFI period -> future virtual counter ticks, rounding UP. 0
 * period indicates timer disabled. No overflow, no fractional tick 0. */
int DiziGicTimerPlanTicks(uint64_t period_100ns, uint32_t frequency,
                          uint64_t *ticks);

#endif
