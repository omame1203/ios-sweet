/* Isolated host tests of the exact 0105 header parser and async state. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "DiziPmicTelemetry.h"

static const uint32_t valid[DIZI_BC_COUNT] = {
    2,       /* POWER_SUPPLY_STATUS_DISCHARGING */
    1,       /* present */
    7350,    /* 73.50% */
    3950000, /* 3950 mV */
    (uint32_t)-512000,  /* signed -512 mA */
    2975,    /* 29.75 C */
    8800000, /* 8800 mAh from ADSP, NOT guessed */
    0        /* USB disconnected */
};

static void make_reply(uint8_t msg[24], uint32_t opcode, uint32_t prop,
    uint32_t value, uint32_t result)
{
    dizi_bc_put32(msg, DIZI_BC_OWNER);
    dizi_bc_put32(msg + 4, DIZI_BC_REQ_RESP);
    dizi_bc_put32(msg + 8, opcode);
    dizi_bc_put32(msg + 12, prop);
    dizi_bc_put32(msg + 16, value);
    dizi_bc_put32(msg + 20, result);
}

static void make_note(uint8_t msg[16], uint32_t what)
{
    dizi_bc_put32(msg, DIZI_BC_OWNER);
    dizi_bc_put32(msg + 4, DIZI_BC_NOTIFY);
    dizi_bc_put32(msg + 8, DIZI_BC_NOTIFY_IND);
    dizi_bc_put32(msg + 12, what);
}

static bool request_reply(struct dizi_bc_state *s, unsigned slot,
    uint32_t value, uint64_t now)
{
    uint8_t query[24] = {0}, resp[24] = {0};
    size_t n = 0;
    if (!dizi_bc_make_get(s, slot, now, query, &n)) return false;
    assert(n == 24);
    assert(dizi_bc_get32(query) == DIZI_BC_OWNER);
    assert(dizi_bc_get32(query + 4) == DIZI_BC_REQ_RESP);
    assert(dizi_bc_get32(query + 8) == dizi_bc_opcode(slot));
    assert(dizi_bc_get32(query + 12) == 0);
    assert(dizi_bc_get32(query + 16) == dizi_bc_property(slot));
    assert(dizi_bc_get32(query + 20) == 0);
    make_reply(resp, dizi_bc_opcode(slot), dizi_bc_property(slot), value, 0);
    return dizi_bc_receive(s, resp, sizeof(resp), now + 1);
}

static void test_transport_and_messages(void)
{
    struct dizi_bc_state st = {0};
    uint8_t request[24] = {0}, resp[24] = {0}, note[16] = {0};
    size_t n = 0;
    struct dizi_bc_snapshot snap = {0};
    assert(!dizi_bc_make_get(&st, 0, 1, request, &n));
    dizi_bc_link(&st, true, false); /* no exclusive GLINK owner */
    assert(!dizi_bc_make_get(&st, 0, 1, request, &n));
    dizi_bc_link(&st, true, true);
    assert(!dizi_bc_snapshot(&st, 1, &snap));
    assert(!dizi_bc_make_get(&st, 8, 1, request, &n));
    assert(!dizi_bc_make_get(&st, 0, 1, NULL, &n));
    assert(!dizi_bc_make_get(&st, 0, 1, request, NULL));
    assert(dizi_bc_make_get(&st, 0, 100, request, &n));
    assert(n == 24);
    assert(!dizi_bc_make_get(&st, 1, 100, request, &n)); /* only one in flight */
    make_reply(resp, 0x30, 0, valid[0], 0);
    assert(!dizi_bc_receive(&st, resp, 11, 101));
    assert(!dizi_bc_receive(&st, resp, 25, 101));
    assert(!dizi_bc_receive(&st, NULL, 24, 101));
    dizi_bc_put32(resp, 32777);
    assert(!dizi_bc_receive(&st, resp, 24, 101));
    dizi_bc_put32(resp, DIZI_BC_OWNER);
    dizi_bc_put32(resp + 4, 3);
    assert(!dizi_bc_receive(&st, resp, 24, 101));
    dizi_bc_put32(resp + 4, DIZI_BC_REQ_RESP);
    dizi_bc_put32(resp + 8, 0x32); /* wrong opcode */
    assert(!dizi_bc_receive(&st, resp, 24, 101));
    dizi_bc_put32(resp + 8, 0x30);
    dizi_bc_put32(resp + 12, 3); /* wrong property */
    assert(!dizi_bc_receive(&st, resp, 24, 101));
    dizi_bc_put32(resp + 12, 0);
    dizi_bc_put32(resp + 20, 1); /* ADSP rejected GET */
    assert(!dizi_bc_receive(&st, resp, 24, 101));
    assert(st.have == 0 && !st.pending);
    assert(!dizi_bc_snapshot(&st, 102, &snap));
    assert(request_reply(&st, 0, valid[0], 120));
    assert(!dizi_bc_receive(&st, resp, 24, 121)); /* duplicate, no request */
    for (unsigned i = 1; i < DIZI_BC_COUNT; i++) {
        assert(request_reply(&st, i, valid[i], 122 + i * 2));
        assert(!dizi_bc_snapshot(&st, 122 + i * 2, &snap) || i == 7);
    }
    assert(dizi_bc_snapshot(&st, 150, &snap));
    assert(snap.status == 2 && snap.present && !snap.usb_online);
    assert(snap.capacity_basis == 7350 && snap.voltage_uv == 3950000);
    assert(snap.current_ua == -512000 && snap.temp_centi == 2975);
    assert(snap.full_uah == 8800000);
    assert(!dizi_bc_snapshot(&st, 20000, &snap)); /* expiry */
    assert(!dizi_bc_snapshot(&st, 0, &snap)); /* clock rollback */
    assert(!dizi_bc_snapshot(&st, 200, NULL));
    make_note(note, DIZI_BC_BATT_GET);
    assert(dizi_bc_receive(&st, note, 16, 150));
    assert(!dizi_bc_snapshot(&st, 151, &snap));
    assert(st.have == (1u << DZ_USB_ONLINE));
    make_note(note, DIZI_BC_USB_GET);
    assert(dizi_bc_receive(&st, note, 16, 152));
    assert(st.have == 0);
    make_note(note, DIZI_BC_NOTIFY_BATT);
    assert(dizi_bc_receive(&st, note, 16, 153));
    make_note(note, 0x12345678);
    assert(!dizi_bc_receive(&st, note, 16, 154));
    assert(!dizi_bc_receive(&st, note, 15, 154));
    dizi_bc_link(&st, false, false);
    assert(st.have == 0 && !st.pending && !st.online);
    assert(!dizi_bc_receive(&st, resp, 24, 160));
}

static void test_malformed_values(void)
{
    struct dizi_bc_state st = {0};
    dizi_bc_link(&st, true, true);
    const unsigned bad_slots[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const uint32_t bad_values[] = {0, 0, 10001, 0, (uint32_t)17000000,
        (uint32_t)-5000, 0, 2};
    for (unsigned k = 0; k < sizeof(bad_slots)/sizeof(bad_slots[0]); k++) {
        assert(!request_reply(&st, bad_slots[k], bad_values[k], 100 + 5*k));
        assert(st.have == 0 && !st.pending);
    }
    assert(!dizi_bc_value_valid(111, 10));
    assert(dizi_bc_value_valid(DZ_BATT_CAPACITY, 0)); /* 0% is real, not assumed invalid */
    assert(dizi_bc_value_valid(DZ_BATT_CAPACITY, 10000));
    assert(dizi_bc_value_valid(DZ_BATT_TEMP_CENTI, (uint32_t)-4000));
    assert(!dizi_bc_value_valid(DZ_BATT_TEMP_CENTI, (uint32_t)-4001));
    assert(!dizi_bc_value_valid(DZ_BATT_CURR_UA, (uint32_t)-15000001));
}

static void test_timeout_and_resets(void)
{
    struct dizi_bc_state st = {0};
    uint8_t req[24], resp[24];
    size_t n;
    dizi_bc_link(&st, true, true);
    assert(dizi_bc_make_get(&st, DZ_BATT_STATUS, 100, req, &n));
    assert(!dizi_bc_expire(&st, 1100));
    assert(dizi_bc_expire(&st, 1101));
    assert(!st.online && !st.pending && st.have == 0);
    make_reply(resp, DIZI_BC_BATT_GET, 0, 1, 0);
    assert(!dizi_bc_receive(&st, resp, 24, 1102)); /* stale after down */
    assert(!dizi_bc_make_get(&st, DZ_BATT_STATUS, 1102, req, &n));
    dizi_bc_link(&st, true, true); /* requires future channel revalidation */
    assert(dizi_bc_make_get(&st, DZ_BATT_STATUS, 1102, req, &n));
    assert(dizi_bc_expire(&st, 1100)); /* backward monotonic */
    assert(!st.online);
    dizi_bc_link(&st, true, true);
    assert(request_reply(&st, DZ_BATT_STATUS, 4, 10));
    assert(st.have == 1);
    dizi_bc_link(&st, true, true); /* SSR/PDR restart invalidates all */
    assert(st.have == 0);
}

int main(void)
{
    assert(DIZI_BC_OWNER == 32778);
    assert(DIZI_BC_REQ_RESP == 1 && DIZI_BC_NOTIFY == 2);
    assert(DIZI_BC_COUNT == 8);
    test_transport_and_messages();
    test_malformed_values();
    test_timeout_and_resets();
    puts("PASS PMIC GLINK 0105 ownership, exact wire length/opcodes/property ID, async state, SSR, notify, bounds, expiration and fail-closed telemetry");
    return 0;
}
