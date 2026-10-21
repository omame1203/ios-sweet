/* All tests are HOST MOCKS, no privileged CPU accesses. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../shim/macos27_pac_probe.h"

static unsigned checks;
#define CHECK(x) do { ++checks; assert(x); } while (0)
#define ISAR1(apa, api, gpa, gpi) (  ((uint64_t)(apa) << 4) | \
    ((uint64_t)(api) << 8) | ((uint64_t)(gpa) << 24) | ((uint64_t)(gpi) << 28))

struct fixture {
    uint64_t values[4];
    enum mac27_pac_probe_reg fail_at;
    unsigned called;
    unsigned bad_order;
};

static int fake_read(void *ctx, enum mac27_pac_probe_reg reg, uint64_t *out)
{
    struct fixture *f = ctx;
    if ((unsigned)reg != f->called) f->bad_order++;
    f->called++;
    if (reg == f->fail_at) return -1;
    *out = f->values[reg];
    return 0;
}

static void poison(struct mac27_pac_probe_observation *o)
{
    o->current_el = ~(uint64_t)0;
    o->mpidr_el1 = ~(uint64_t)0;
    o->id_aa64isar1_el1 = ~(uint64_t)0;
    o->id_aa64isar2_el1 = ~(uint64_t)0;
    o->complete_mask = ~(uint32_t)0;
    o->source = MAC27_PAC_SOURCE_DIRECT_EL1;
    o->native_boot_ready = ~(uint32_t)0;
}

static void assert_empty(const struct mac27_pac_probe_observation *o)
{
    CHECK(o->current_el == 0);
    CHECK(o->mpidr_el1 == 0);
    CHECK(o->id_aa64isar1_el1 == 0);
    CHECK(o->id_aa64isar2_el1 == 0);
    CHECK(o->complete_mask == 0);
    CHECK(o->source == MAC27_PAC_SOURCE_NONE);
    CHECK(o->native_boot_ready == 0);
}

static void assert_empty_sample(const struct mac27_cpu_sample *o)
{
    CHECK(o->mpidr_el1 == 0);
    CHECK(o->id_aa64isar1_el1 == 0);
    CHECK(o->id_aa64isar2_el1 == 0);
    CHECK(o->origin == MAC27_CPU_ORIGIN_NONE);
    CHECK(o->isar1_observed == 0);
    CHECK(o->isar2_observed == 0);
    CHECK(o->reserved[0] == 0 && o->reserved[1] == 0);
}

static void disabled_is_transactional(void)
{
    struct mac27_pac_probe_observation o;
    struct mac27_pac_probe_reader empty = {0};
    poison(&o);
    CHECK(mac27_pac_probe_el1(&o, 0) == MAC27_PAC_PROBE_DISABLED);
    assert_empty(&o);
    poison(&o);
#if !defined(__aarch64__)
    CHECK(mac27_pac_probe_el1(&o, 1) == MAC27_PAC_PROBE_DISABLED);
    assert_empty(&o);
#endif
    poison(&o);
    CHECK(mac27_pac_probe_el1(NULL, 1) == MAC27_PAC_PROBE_BAD_ARGUMENT);
    CHECK(mac27_pac_probe_mock(NULL, &o) == MAC27_PAC_PROBE_BAD_ARGUMENT);
    assert_empty(&o);
    poison(&o);
    CHECK(mac27_pac_probe_mock(&empty, &o) == MAC27_PAC_PROBE_BAD_ARGUMENT);
    assert_empty(&o);
    CHECK(mac27_pac_probe_mock(&empty, NULL) == MAC27_PAC_PROBE_BAD_ARGUMENT);
}

static void mock_never_attests(void)
{
    struct fixture f = {0};
    struct mac27_pac_probe_reader reader = {fake_read, &f};
    struct mac27_pac_probe_observation o;
    struct mac27_cpu_sample sample;
    f.fail_at = (enum mac27_pac_probe_reg)77;
    f.values[0] = MAC27_PAC_PROBE_EL1;
    f.values[1] = UINT64_C(0x300);
    f.values[2] = ISAR1(1, 0, 1, 0); /* synthetic positive PAC */
    f.values[3] = 0;
    poison(&o);
    CHECK(mac27_pac_probe_mock(&reader, &o) == MAC27_PAC_PROBE_OK);
    CHECK(o.source == MAC27_PAC_SOURCE_MOCK);
    CHECK(o.complete_mask == MAC27_PAC_PROBE_ALL_READS);
    CHECK(o.current_el == MAC27_PAC_PROBE_EL1);
    CHECK(o.mpidr_el1 == f.values[1]);
    CHECK(o.id_aa64isar1_el1 == f.values[2]);
    CHECK(o.id_aa64isar2_el1 == 0);
    CHECK(o.native_boot_ready == 0);
    CHECK(f.called == 4 && f.bad_order == 0);
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &sample) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&sample);
    /* Even zero-feature synthetic values remain observations, not PAC. */
    f.called = 0;
    f.values[2] = 0;
    f.values[3] = 0;
    CHECK(mac27_pac_probe_mock(&reader, &o) == MAC27_PAC_PROBE_OK);
    CHECK(o.id_aa64isar1_el1 == 0);
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &sample) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&sample);
}

static void failure_and_early_stop(void)
{
    struct fixture f = {0};
    struct mac27_pac_probe_reader reader = {fake_read, &f};
    struct mac27_pac_probe_observation o;
    unsigned pos;
    f.values[0] = MAC27_PAC_PROBE_EL1;
    f.values[1] = 0;
    f.values[2] = ~(uint64_t)0;
    f.values[3] = ~(uint64_t)0;
    for (pos = 0; pos < 4; ++pos) {
        f.called = f.bad_order = 0;
        f.fail_at = (enum mac27_pac_probe_reg)pos;
        poison(&o);
        CHECK(mac27_pac_probe_mock(&reader, &o) == MAC27_PAC_PROBE_READ_FAILED);
        CHECK(f.called == pos + 1 && f.bad_order == 0);
        assert_empty(&o);
    }
    f.fail_at = (enum mac27_pac_probe_reg)77;
    for (pos = 0; pos < 4; ++pos) {
        f.values[0] = (uint64_t)pos * 4;
        f.called = f.bad_order = 0;
        poison(&o);
        int outcome = mac27_pac_probe_mock(&reader, &o);
        if (pos == 1) {
            CHECK(outcome == MAC27_PAC_PROBE_OK);
            CHECK(f.called == 4);
        } else {
            CHECK(outcome == MAC27_PAC_PROBE_WRONG_EL);
            CHECK(f.called == 1 && f.bad_order == 0);
            assert_empty(&o);
        }
    }
}

static void conversion_gate(void)
{
    struct mac27_pac_probe_observation o = {0};
    struct mac27_cpu_sample cpu = {0};
    CHECK(mac27_pac_probe_to_cpu_sample(NULL, NULL) == MAC27_PAC_PROBE_BAD_ARGUMENT);
    CHECK(mac27_pac_probe_to_cpu_sample(NULL, &cpu) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&cpu);
    o.current_el = 4;
    o.mpidr_el1 = UINT64_C(0x700);
    o.id_aa64isar1_el1 = ISAR1(1, 0, 1, 0);
    o.id_aa64isar2_el1 = 0;
    o.complete_mask = MAC27_PAC_PROBE_ALL_READS;
    o.source = MAC27_PAC_SOURCE_DIRECT_EL1;
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &cpu) == MAC27_PAC_PROBE_OK);
    CHECK(cpu.origin == MAC27_CPU_ORIGIN_DIRECT_EL1);
    CHECK(cpu.mpidr_el1 == 0x700);
    CHECK(cpu.id_aa64isar1_el1 == o.id_aa64isar1_el1);
    CHECK(cpu.isar1_observed == 1 && cpu.isar2_observed == 1);
    /* Crafted structure is NOT an actual EL1 attestation; test only ABI. */
    o.native_boot_ready = 1;
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &cpu) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&cpu);
    o.native_boot_ready = 0;
    o.complete_mask = 7;
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &cpu) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&cpu);
    o.complete_mask = MAC27_PAC_PROBE_ALL_READS;
    o.current_el = 8;
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &cpu) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&cpu);
    o.current_el = 4;
    o.source = MAC27_PAC_SOURCE_MOCK;
    CHECK(mac27_pac_probe_to_cpu_sample(&o, &cpu) == MAC27_PAC_PROBE_NOT_ATTESTED);
    assert_empty_sample(&cpu);
}

int main(void)
{
    disabled_is_transactional();
    mock_never_attests();
    failure_and_early_stop();
    conversion_gate();
    printf("PASS %u macOS27 passive PAC mock assertions; no hardware sampled, native_ready=0\n", checks);
    return 0;
}
