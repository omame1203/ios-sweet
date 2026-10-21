/** @file  No MMIO, system-register, UEFI or hypervisor side effects.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "DiziGicTimerPlan.h"

int
DiziGicTimerPlanValidate(const struct DiziGicTimerGrant *g,
                         const struct DiziGicTimerSnapshot *s)
{
  uint64_t affinity;
  if (!g || !s || g->gicd_base != DIZI_GT_GICD_BASE ||
      g->gicd_size < DIZI_GT_GICD_SIZE ||
      g->gicd_size > UINT64_MAX - g->gicd_base ||
      g->gicr_base != DIZI_GT_GICR_BASE ||
      g->gicr_size < DIZI_GT_GICR_SIZE ||
      g->gicr_size > UINT64_MAX - g->gicr_base ||
      g->timer_frequency != DIZI_GT_TIMER_HZ ||
      g->timer_ppi != DIZI_GT_VTIMER_PPI || g->core_count != 1 ||
      g->verified_permissions != DIZI_GT_ALL_PERMISSIONS ||
      g->primary_mpidr_affinity != 0 ||
      s->current_el != 1 || s->cntfrq != DIZI_GT_TIMER_HZ)
    return DIZI_GT_REJECT;

  /* The first redistributor belongs to cpu0. GICR_TYPER affinity is the
   * upper 32 bits in Aff3,Aff2,Aff1,Aff0 order. Raw MPIDR has Aff3 in
   * bits [39:32], Aff2 in [23:16], Aff1 in [15:8], Aff0 in [7:0]. */
  affinity = ((s->current_mpidr >> 32) & 0xff) << 24 |
             ((s->current_mpidr >> 16) & 0xff) << 16 |
             ((s->current_mpidr >> 8) & 0xff) << 8 |
             (s->current_mpidr & 0xff);
  if (affinity != 0 || ((s->gicr_typer >> 32) & UINT64_C(0xffffffff)) != affinity)
    return DIZI_GT_REJECT;

  /* GICR WAKER ProcessorSleep/ChildrenAsleep must both be clear. The
   * driver never writes WAKER. Group1NS must already be enabled in GICD
   * and virtual PPI must already be configured as Group1 level-high.
   * GICR_ICFGR1 has two bits per PPI; PPI27 uses bits 23:22. */
  if ((s->gicr_waker & UINT32_C(0x6)) != 0 ||
      (s->gicd_ctlr & UINT32_C(0x2)) == 0 ||
      (s->gicr_igroupr0 & DIZI_GT_PPI_BIT) == 0 ||
      (s->gicr_icfgr1 & (UINT32_C(2) << (2 * (DIZI_GT_VTIMER_PPI - 16)))) != 0)
    return DIZI_GT_REJECT;
  return DIZI_GT_ADMIT;
}

int
DiziGicTimerPlanTicks(uint64_t period, uint32_t frequency, uint64_t *ticks)
{
  uint64_t whole, rest, result;
  if (!ticks || frequency != DIZI_GT_TIMER_HZ)
    return 0;
  if (period == 0) {
    *ticks = 0;
    return 1;
  }
  whole = period / UINT64_C(10000000);
  rest = period % UINT64_C(10000000);
  /* Limit to 2^31-1 ticks, avoiding compare wrap in the timer path. */
  if (whole > UINT64_C(0x7fffffff) / frequency)
    return 0;
  result = whole * frequency +
           ((rest * frequency + UINT64_C(9999999)) / UINT64_C(10000000));
  if (result == 0 || result > UINT64_C(0x7fffffff))
    return 0;
  *ticks = result;
  return 1;
}
