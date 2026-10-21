/* Deterministic HOST ONLY test of the EL1 sysreg trap planner. No MRS run. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../shim/macos27_pac_recovery.h"

static unsigned nchecks;
#define CHECK(x) do { nchecks++; assert(x); } while (0)

static const struct mac27_pac_recovery_sites sites = {
    UINT64_C(0x1000), UINT64_C(0x2000)
};

static struct mac27_pac_recovery_state active_stage(unsigned stage)
{
    struct mac27_pac_recovery_state p = {0};
    p.armed = 1;
    p.stage = stage;
    return p;
}

static int plan(struct mac27_pac_recovery_state *p,
                const struct mac27_pac_recovery_sites *s,
                uint64_t slot, uint64_t esr, uint64_t pc)
{
    uint64_t resume = UINT64_C(0xdeadbeef);
    int handled = mac27_pac_recovery_plan(p, s, slot, esr, pc, &resume);
    if (handled) CHECK(resume == pc + 4);
    else CHECK(resume == UINT64_C(0xdeadbeef));
    return handled;
}

static void abi_and_disabled(void)
{
    struct mac27_pac_recovery_state p;
    CHECK(offsetof(struct mac27_pac_recovery_state, isar1) == 0);
    CHECK(offsetof(struct mac27_pac_recovery_state, isar2) == 8);
    CHECK(offsetof(struct mac27_pac_recovery_state, armed) == 16);
    CHECK(offsetof(struct mac27_pac_recovery_state, stage) == 20);
    CHECK(offsetof(struct mac27_pac_recovery_state, trap_mask) == 24);
    CHECK(offsetof(struct mac27_pac_recovery_state, observed_mask) == 28);
    CHECK(mac27_pac_recovery_expected_esr(0) == 0);
    CHECK(mac27_pac_recovery_expected_esr(3) == 0);
    CHECK(mac27_pac_recovery_expected_esr(1) !=
          mac27_pac_recovery_expected_esr(2));
    CHECK((mac27_pac_recovery_expected_esr(1) >> 26) == 0x18);
    CHECK(mac27_pac_recovery_expected_esr(1) & MAC27_PAC_RECOVERY_ESR_IL);
    p = active_stage(1);
    CHECK(mac27_pac_recovery_exc_handler(4, (uint64_t *)&p) == 0);
    CHECK(mac27_pac_recovery_exc_handler(5, NULL) == 0);
    CHECK(mac27_pac_recovery_sample(NULL, 1) == MAC27_PAC_RECOVERY_BAD_ARGUMENT);
    p.isar1 = p.isar2 = ~UINT64_C(0);
    p.trap_mask = p.observed_mask = ~UINT32_C(0);
    CHECK(mac27_pac_recovery_sample(&p, 0) == MAC27_PAC_RECOVERY_DISABLED);
    CHECK(p.isar1 == 0 && p.isar2 == 0);
    CHECK(p.armed == 0 && p.stage == 0 && p.trap_mask == 0);
    CHECK(p.observed_mask == 0 && p.native_boot_ready == 0);
#if !defined(__aarch64__)
    CHECK(mac27_pac_recovery_sample(&p, 1) == MAC27_PAC_RECOVERY_DISABLED);
#endif
}

static void permitted_faults_only(void)
{
    struct mac27_pac_recovery_state p = active_stage(1);
    const uint64_t esr1 = mac27_pac_recovery_expected_esr(1);
    const uint64_t esr2 = mac27_pac_recovery_expected_esr(2);
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 1);
    CHECK(p.trap_mask == MAC27_PAC_RECOVERY_TRAP_ISAR1);
    CHECK(p.observed_mask == 0 && p.isar1 == 0 && p.isar2 == 0);
    /* One-and-only-one recovery per stage; never retry the same fault. */
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.stage = 2;
    CHECK(plan(&p, &sites, 4, esr2, sites.isar2_mrs_pc) == 1);
    CHECK(p.trap_mask == MAC27_PAC_RECOVERY_COMPLETE);
    CHECK(plan(&p, &sites, 4, esr2, sites.isar2_mrs_pc) == 0);
    CHECK(p.native_boot_ready == 0);
}

static void wrong_slot_never_swallowed(void)
{
    const uint64_t esr1 = mac27_pac_recovery_expected_esr(1);
    for (uint64_t slot = 0; slot < 16; slot++) {
        struct mac27_pac_recovery_state p = active_stage(1);
        if (slot == 4) continue;
        CHECK(plan(&p, &sites, slot, esr1, sites.isar1_mrs_pc) == 0);
        CHECK(p.trap_mask == 0);
    }
}

static void wrong_pc_never_swallowed(void)
{
    struct mac27_pac_recovery_state p;
    const uint64_t esr1 = mac27_pac_recovery_expected_esr(1);
    for (uint64_t offset = 0; offset <= 32; offset += 4) {
        if (offset == 0) continue;
        p = active_stage(1);
        CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc + offset) == 0);
        CHECK(p.trap_mask == 0);
    }
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, esr1, sites.isar2_mrs_pc) == 0);
    p = active_stage(2);
    CHECK(plan(&p, &sites, 4, mac27_pac_recovery_expected_esr(2),
               sites.isar1_mrs_pc) == 0);
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc - 4) == 0);
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, esr1, UINT64_MAX) == 0);
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc + 1) == 0);
}

static void wrong_esr_never_swallowed(void)
{
    struct mac27_pac_recovery_state p;
    const uint64_t esr1 = mac27_pac_recovery_expected_esr(1);
    for (unsigned bit = 0; bit < 32; bit++) {
        p = active_stage(1);
        CHECK(plan(&p, &sites, 4, esr1 ^ (UINT64_C(1) << bit),
                   sites.isar1_mrs_pc) == 0);
        CHECK(p.trap_mask == 0);
    }
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, mac27_pac_recovery_expected_esr(2),
               sites.isar1_mrs_pc) == 0);
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, 0, sites.isar1_mrs_pc) == 0);
    p = active_stage(1);
    CHECK(plan(&p, &sites, 4, esr1 | (UINT64_C(1) << 32),
               sites.isar1_mrs_pc) == 0);
}

static void state_invalid_never_swallowed(void)
{
    const uint64_t esr1 = mac27_pac_recovery_expected_esr(1);
    struct mac27_pac_recovery_state p = active_stage(1);
    struct mac27_pac_recovery_sites bad = sites;
    uint64_t resume = 0x4321;
    CHECK(mac27_pac_recovery_plan(NULL, &sites, 4, esr1,
                                  sites.isar1_mrs_pc, &resume) == 0);
    CHECK(mac27_pac_recovery_plan(&p, NULL, 4, esr1,
                                  sites.isar1_mrs_pc, &resume) == 0);
    CHECK(mac27_pac_recovery_plan(&p, &sites, 4, esr1,
                                  sites.isar1_mrs_pc, NULL) == 0);
    CHECK(resume == 0x4321);
    p.armed = 0;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.armed = 2;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.armed = 1; p.stage = 3;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.stage = 1; p.observed_mask = 1;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.observed_mask = 4;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.observed_mask = 0; p.trap_mask = 4;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.trap_mask = 0; p.native_boot_ready = 1;
    CHECK(plan(&p, &sites, 4, esr1, sites.isar1_mrs_pc) == 0);
    p.native_boot_ready = 0;
    bad.isar1_mrs_pc = 0;
    CHECK(plan(&p, &bad, 4, esr1, sites.isar1_mrs_pc) == 0);
    bad = sites; bad.isar1_mrs_pc = 0x1001;
    CHECK(plan(&p, &bad, 4, esr1, sites.isar1_mrs_pc) == 0);
    bad = sites; bad.isar2_mrs_pc = sites.isar1_mrs_pc;
    CHECK(plan(&p, &bad, 4, esr1, sites.isar1_mrs_pc) == 0);
}

int main(void)
{
    abi_and_disabled();
    permitted_faults_only();
    wrong_slot_never_swallowed();
    wrong_pc_never_swallowed();
    wrong_esr_never_swallowed();
    state_invalid_never_swallowed();
    printf("PASS %u PAC EL1 exception-planner assertions; native_boot_ready=0, no hardware\n",
           nchecks);
    return 0;
}
