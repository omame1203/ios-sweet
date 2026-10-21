/* Host tests for the exact GICv3 CPU0 redistributor and 19.2MHz vtimer
 * contract. These tests execute NO MMIO, privileged AArch64 or EDK2 code. */
#include "../ports/renegade/edk2-overlay/Silicon/Qualcomm/sm7435/Drivers/DiziGicTimer/DiziGicTimerPlan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct DiziGicTimerGrant grant(void)
{
  struct DiziGicTimerGrant g;
  memset(&g, 0, sizeof(g));
  g.gicd_base = DIZI_GT_GICD_BASE;
  g.gicd_size = DIZI_GT_GICD_SIZE;
  g.gicr_base = DIZI_GT_GICR_BASE;
  g.gicr_size = DIZI_GT_GICR_SIZE;
  g.timer_frequency = DIZI_GT_TIMER_HZ;
  g.timer_ppi = DIZI_GT_VTIMER_PPI;
  g.core_count = 1;
  g.verified_permissions = DIZI_GT_ALL_PERMISSIONS;
  return g;
}

static struct DiziGicTimerSnapshot snapshot(void)
{
  struct DiziGicTimerSnapshot s;
  memset(&s, 0, sizeof(s));
  s.gicd_ctlr = 0x2;           /* Group1NS enabled externally */
  s.gicr_waker = 0;           /* no WAKER writes in our DXE */
  s.gicr_igroupr0 = DIZI_GT_PPI_BIT;
  s.gicr_icfgr1 = 0;          /* level-high PPI27 */
  s.gicr_typer = 0;           /* affinity 0 for core0 */
  s.current_mpidr = 0;
  s.current_el = 1;
  s.cntfrq = DIZI_GT_TIMER_HZ;
  return s;
}

static void test_grants(void)
{
  struct DiziGicTimerGrant g = grant(), t;
  struct DiziGicTimerSnapshot s = snapshot(), u;
  assert(DIZI_GT_PHYS_PPI == 30 && DIZI_GT_VTIMER_PPI == 27);
  assert(DIZI_GT_PPI_BIT == (1U << 27));
  assert(DiziGicTimerPlanValidate(NULL, &s) == DIZI_GT_REJECT);
  assert(DiziGicTimerPlanValidate(&g, NULL) == DIZI_GT_REJECT);
  /* All permissions are sourced from an independent real handoff grant.
   * A memory snapshot alone cannot authenticate them. */
  assert(DiziGicTimerPlanValidate(&g, &s) == DIZI_GT_ADMIT);
  for (unsigned bit = 0; bit < 7; ++bit) {
    t = g;
    t.verified_permissions &= ~(1U << bit);
    assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  }
  t = g; t.verified_permissions |= 0x100;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.gicd_base++;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.gicr_base += 0x20000;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.gicr_size--;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.gicd_size--;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.gicd_size = UINT64_MAX;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.gicr_size = UINT64_MAX;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.timer_ppi = DIZI_GT_PHYS_PPI;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.timer_frequency--;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.core_count = 8;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);
  t = g; t.primary_mpidr_affinity = 1;
  assert(DiziGicTimerPlanValidate(&t, &s) == DIZI_GT_REJECT);

  u = s; u.current_el = 2;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.cntfrq = 24000000;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.current_mpidr = 0x100;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.gicr_typer = UINT64_C(1) << 32;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.gicr_waker = 2;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.gicr_waker = 4;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.gicr_igroupr0 = 0;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.gicd_ctlr = 0;
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
  u = s; u.gicr_icfgr1 = 2U << (2 * (27-16));
  assert(DiziGicTimerPlanValidate(&g, &u) == DIZI_GT_REJECT);
}

static void test_timer(void)
{
  uint64_t ticks = UINT64_MAX;
  assert(!DiziGicTimerPlanTicks(1, DIZI_GT_TIMER_HZ, NULL));
  assert(!DiziGicTimerPlanTicks(1, 25000000, &ticks));
  assert(DiziGicTimerPlanTicks(0, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == 0);
  assert(DiziGicTimerPlanTicks(1, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == 2); /* ceil(1 * 19.2 MHz / 10 MHz) */
  assert(DiziGicTimerPlanTicks(100000, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == 192000); /* 10 ms */
  assert(DiziGicTimerPlanTicks(10000000, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == 19200000); /* 1 second */
  assert(DiziGicTimerPlanTicks(10000001, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == 19200002); /* fractional remainder is rounded UP */
  ticks = UINT64_C(12345);
  assert(!DiziGicTimerPlanTicks(UINT64_MAX, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == UINT64_C(12345)); /* no output corruption on failure */
  assert(!DiziGicTimerPlanTicks(1200000000, DIZI_GT_TIMER_HZ, &ticks));
  assert(DiziGicTimerPlanTicks(100000000, DIZI_GT_TIMER_HZ, &ticks));
  assert(ticks == 192000000); /* 10 seconds */
}

int main(void)
{
  test_grants();
  test_timer();
  puts("PASS dizi GICv3 CPU0 virtual PPI27 ownership filter / timer ticks; host-only; no MMIO");
  return 0;
}
