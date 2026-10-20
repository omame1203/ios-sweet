/* Synthetic GLINK payloads; no battery reading is sourced from hardware. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pmic_glink_sched.h"

static uint32_t sample[DIZI_BC_COUNT] = {
    2, 1, 7534, 4001000, (uint32_t)-123000, 3150, 8100000, 0
};

static void reply(uint8_t b[24], unsigned slot, uint32_t value, uint32_t rc)
{
    dizi_bc_put32(b, DIZI_BC_OWNER);
    dizi_bc_put32(b + 4, DIZI_BC_REQ_RESP);
    dizi_bc_put32(b + 8, dizi_bc_opcode(slot));
    dizi_bc_put32(b + 12, dizi_bc_property(slot));
    dizi_bc_put32(b + 16, value);
    dizi_bc_put32(b + 20, rc);
}

static void notification(uint8_t b[16], uint32_t kind)
{
    dizi_bc_put32(b, DIZI_BC_OWNER);
    dizi_bc_put32(b + 4, DIZI_BC_NOTIFY);
    dizi_bc_put32(b + 8, DIZI_BC_NOTIFY_IND);
    dizi_bc_put32(b + 12, kind);
}

static void test_handoff_and_schedule(void)
{
    struct dizi_pmic_sched s = {0};
    struct dizi_bc_state bc = {0};
    uint8_t tx[24], rx[24], note[16];
    size_t n = 0;
    struct dizi_bc_snapshot snapshot = {0};
    assert(!dizi_pmic_sched_next(&s, &bc, 1, 100, tx, &n));
    assert(!dizi_pmic_sched_open(&s, &bc, 1, DIZI_PMIC_EV_ALL & ~DIZI_PMIC_EV_RX_DRAINED, true));
    assert(!dizi_pmic_sched_open(&s, &bc, 1, DIZI_PMIC_EV_ALL, false));
    assert(!bc.online && !bc.have);
    assert(dizi_pmic_sched_open(&s, &bc, 1, DIZI_PMIC_EV_ALL, true));
    assert(!dizi_pmic_sched_open(&s, &bc, 1, DIZI_PMIC_EV_ALL, true));
    assert(!bc.online && !bc.have); /* cannot reopen same epoch */
    assert(dizi_pmic_sched_open(&s, &bc, 2, DIZI_PMIC_EV_ALL, true));

    for (unsigned i = 0; i < DIZI_BC_COUNT; i++) {
        uint64_t now = 1000u + (uint64_t)i * 150u;
        assert(!dizi_pmic_sched_next(&s, &bc, 1, now, tx, &n));
        assert(dizi_pmic_sched_next(&s, &bc, 2, now, tx, &n));
        assert(n == 24 && dizi_bc_get32(tx) == DIZI_BC_OWNER);
        assert(dizi_bc_get32(tx + 8) == dizi_bc_opcode(i));
        assert(dizi_bc_get32(tx + 16) == dizi_bc_property(i));
        assert(!dizi_pmic_sched_next(&s, &bc, 2, now, tx, &n));
        if (i == 3) {
            notification(note, DIZI_BC_NOTIFY_BATT);
            assert(dizi_pmic_sched_receive(&s, &bc, 2, note, sizeof(note), now + 1));
            assert(bc.pending); /* unsolicited note never satisfies reply */
        }
        reply(rx, i, sample[i], 0);
        if (i == 4) {
            uint8_t wrong[24];
            memcpy(wrong, rx, sizeof(wrong));
            dizi_bc_put32(wrong + 12, 0xffffffffu);
            assert(!dizi_pmic_sched_receive(&s, &bc, 2, wrong, sizeof(wrong), now + 2));
            assert(bc.pending);
        }
        assert(dizi_pmic_sched_receive(&s, &bc, 2, rx, sizeof(rx), now + 3));
    }
    /* The battery notification at slot 3 invalidated earlier battery fields.
     * These synthetic replies exercise a fresh complete round. */
    assert(!dizi_bc_snapshot(&bc, 2300, &snapshot));
    for (unsigned i = 0; i < DIZI_BC_COUNT; i++) {
        uint64_t now = 8000u + (uint64_t)i * 150u;
        assert(dizi_pmic_sched_next(&s, &bc, 2, now, tx, &n));
        reply(rx, i, sample[i], 0);
        assert(dizi_pmic_sched_receive(&s, &bc, 2, rx, sizeof(rx), now + 2));
    }
    assert(dizi_bc_snapshot(&bc, 9200, &snapshot));
    assert(snapshot.capacity_basis == 7534 && !snapshot.usb_online);
    assert(snapshot.current_ua == -123000 && snapshot.temp_centi == 3150);
    assert(!dizi_pmic_sched_next(&s, &bc, 2, 9500, tx, &n));
    assert(dizi_pmic_sched_next(&s, &bc, 2, 15000, tx, &n));
    assert(dizi_bc_get32(tx + 16) == dizi_bc_property(0));
    dizi_pmic_sched_tx_error(&s, &bc, 1); /* old epoch cannot kill current */
    assert(bc.online && bc.pending);
    dizi_pmic_sched_tx_error(&s, &bc, 2);
    assert(!bc.online && !bc.pending && bc.have == 0);
    assert(!dizi_bc_snapshot(&bc, 15000, &snapshot));
    assert(!dizi_pmic_sched_receive(&s, &bc, 2, rx, 24, 15001));
    assert(!dizi_pmic_sched_open(&s, &bc, 2, DIZI_PMIC_EV_ALL, true));
    assert(dizi_pmic_sched_open(&s, &bc, 3, DIZI_PMIC_EV_ALL, true));
    assert(!dizi_pmic_sched_receive(&s, &bc, 2, rx, 24, 9000));
    assert(bc.have == 0);
}

static void test_faults_and_timeouts(void)
{
    struct dizi_pmic_sched s = {0};
    struct dizi_bc_state bc = {0};
    uint8_t tx[24], rx[24];
    size_t n;
    assert(dizi_pmic_sched_open(&s, &bc, 10, DIZI_PMIC_EV_ALL, true));
    assert(dizi_pmic_sched_next(&s, &bc, 10, 10000, tx, &n));
    assert(!dizi_pmic_sched_check(&s, &bc, 11001)); /* wait>1000ms closes */
    assert(!bc.online && bc.have == 0);
    assert(!dizi_pmic_sched_receive(&s, &bc, 10, rx, 24, 11002));
    assert(!dizi_pmic_sched_open(&s, &bc, 10, DIZI_PMIC_EV_ALL, true));
    assert(dizi_pmic_sched_open(&s, &bc, 11, DIZI_PMIC_EV_ALL, true));
    assert(dizi_pmic_sched_next(&s, &bc, 11, 12000, tx, &n));
    reply(rx, 0, 2, 5); /* valid shape, remote negative result */
    assert(!dizi_pmic_sched_receive(&s, &bc, 11, rx, 24, 12002));
    assert(!bc.pending && bc.online);
    assert(!dizi_pmic_sched_next(&s, &bc, 11, 12003, tx, &n));
    assert(dizi_pmic_sched_next(&s, &bc, 11, 12200, tx, &n));
    assert(dizi_bc_get32(tx + 16) == dizi_bc_property(1));
    reply(rx, 1, 1, 0);
    assert(!dizi_pmic_sched_receive(&s, &bc, 11, rx, 12, 12202));
    assert(bc.pending);
    assert(!dizi_pmic_sched_check(&s, &bc, 12199)); /* monotonic regression */
    assert(!bc.online);
    assert(dizi_pmic_sched_open(&s, &bc, 12, DIZI_PMIC_EV_ALL, true));
    assert(dizi_pmic_sched_next(&s, &bc, 12, 13000, tx, &n));
    reply(rx, 0, 0, 0); /* invalid status rejected */
    assert(!dizi_pmic_sched_receive(&s, &bc, 12, rx, 24, 13005));
    assert(!bc.pending && bc.have == 0);
    dizi_pmic_sched_close(&s, &bc); /* PDR down, all values invalidated */
    assert(!dizi_pmic_sched_next(&s, &bc, 12, 13100, tx, &n));
    assert(dizi_pmic_sched_open(&s, &bc, 13, DIZI_PMIC_EV_ALL, true));
    assert(!dizi_pmic_sched_next(&s, &bc, 12, 13200, tx, &n));
}

int main(void)
{
    test_handoff_and_schedule();
    test_faults_and_timeouts();
    puts("PASS PMIC-GLINK 0110 scheduler: verified gates, wire, SSR/PDR epoch, no retry after timeout, TX errors, negative reply, notifications, stale epoch, freshness");
    return 0;
}
