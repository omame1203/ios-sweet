/* SPDX-License-Identifier: MIT
 * Offline-only SE9 root clock + TLMM 10..13 / IRQ54 register plan.
 * This API NEVER performs MMIO writes; ownership must be proven separately.
 */
#ifndef DIZI_SE9_CLOCK_H
#define DIZI_SE9_CLOCK_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SE9_GCC_BASE        UINT64_C(0x00100000)
#define SE9_TLMM_BASE       UINT64_C(0x0f000000)
#define SE9_GPIO_BASE       (SE9_TLMM_BASE + UINT64_C(0x100000))
#define SE9_GCC_VOTE        (SE9_GCC_BASE + UINT64_C(0x62008))
#define SE9_GCC_RCG_CMD     (SE9_GCC_BASE + UINT64_C(0x283b0))
#define SE9_GCC_RCG_CFG     (SE9_GCC_RCG_CMD + 4u)
#define SE9_GCC_SE_CBCR     (SE9_GCC_BASE + UINT64_C(0x283a8))
#define SE9_GCC_M_AHB_CBCR  (SE9_GCC_BASE + UINT64_C(0x28004))
#define SE9_GCC_S_AHB_CBCR  (SE9_GCC_BASE + UINT64_C(0x28008))
#define SE9_GPIO_CTL(n)     (SE9_GPIO_BASE + (uint64_t)(n) * 0x1000u)
#define SE9_GPIO_IO(n)      (SE9_GPIO_CTL(n) + 4u)
#define SE9_GPIO_INTR(n)    (SE9_GPIO_CTL(n) + 8u)
#define SE9_GPIO_INTR_ST(n) (SE9_GPIO_CTL(n) + 12u)
#define SE9_IO_MAX 16u
#define SE9_PLAN_MAX 18u
#define SE9_XO_HZ 19200000u
#define SE9_NVT_MAX_HZ 9600000u
#define SE9_ID_GPIO54 54u

enum se9_result {
    SE9_OK = 0, SE9_BAD_ARG = -1, SE9_NO_OWNER = -2,
    SE9_BAD_STATE = -3, SE9_STALE = -4, SE9_INCOMPLETE = -5
};
/* These are independent EXTERNAL ATTESTATIONS, not inferred from register
 * values, probe logs, FDT, a boot argument, or another device's consent. */
struct se9_ownership {
    bool gcc_exclusive;
    bool rcg_exclusive;
    bool wrap1_m_ahb_vote;
    bool wrap1_s_ahb_vote;
    bool se9_branch_vote;
    bool tlmm_pins10_13_exclusive;
    bool gpio54_exclusive;
    bool irq54_route_exclusive;
    bool spi_controller_idle;
    bool chip_select_idle;
    bool xo_19200000_verified;
    bool voltage_corners_approved;
    bool interrupt_handler_ready;
    bool no_concurrent_clients;
};
struct se9_reg {
    uint64_t pa;
    uint32_t value;
};
struct se9_snapshot {
    struct se9_reg regs[SE9_IO_MAX];
    unsigned count;
};
/* Operation plan is DATA ONLY: never writes or invokes a write callback.
 * RMW must compare expected masked read before any hypothetical update;
 * WAIT is a bounded hardware status poll to be implemented by a future
 * audited backend. Values are absolute physical addresses, not pointers. */
enum se9_op_kind { SE9_RMW = 1, SE9_WAIT_BITS = 2 };
struct se9_op {
    enum se9_op_kind kind;
    uint64_t pa;
    uint32_t mask;
    uint32_t value;
    uint32_t expect_mask; /* checked just before this operation */
    uint32_t expect_value;
    uint32_t max_polls; /* only WAIT_BITS, NEVER unbounded */
};
struct se9_plan {
    struct se9_snapshot source;
    struct se9_op ops[SE9_PLAN_MAX];
    unsigned count;
    uint32_t source_hz;
    uint32_t spi_hz_max;
    bool irq_armed_in_plan;
};
typedef int (*se9_read32)(void *ctx, uint64_t pa, uint32_t *value);

/* RO snapshot probes only this fixed GCC/TLMM allowlist. */
int se9_take_snapshot(se9_read32 read32, void *ctx, struct se9_snapshot *out);
/* Requires independent ALL-resource attestation; no registry writes. */
int se9_make_plan(const struct se9_snapshot *snap,
                  const struct se9_ownership *auth, bool arm_irq54,
                  struct se9_plan *out);
/* Check that all source registers are unchanged since the plan was made.
 * Does NOT itself grant ownership or perform any hardware actions. */
int se9_verify_unchanged(const struct se9_plan *plan,
                         se9_read32 read32, void *ctx);
/* Model of plan RMW/WAIT on a caller-owned fake in-memory register table;
 * has NO hardware callback, MMIO pointer, or device address dereference. */
int se9_simulate(const struct se9_plan *plan, struct se9_snapshot *fake,
                 unsigned *step_completed);
#endif
