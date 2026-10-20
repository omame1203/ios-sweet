/* Deterministic policy cases; all seconds are synthetic, not measured RTC. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "rtc_wallclock_0113.h"

static void test_two_independent_samples(void)
{
    struct dizi_rtc_wall_pair p = {
        .first = 1790000000u, .next = 1790000001u,
        .elapsed_ms = 1050u, .first_valid = true, .next_valid = true,
    };
    uint32_t result = 0;
    assert(dizi_rtc_wall_candidate(&p, &result));
    assert(result == p.next);
    assert(dizi_rtc_wall_may_seed(30u));
    assert(!dizi_rtc_wall_may_seed(1700000000u));
    assert(!dizi_rtc_wall_may_seed(DIZI_RTC_CLOCK_INVALID_BEFORE));

    struct dizi_rtc_wall_pair invalid = p;
    invalid.first_valid = false;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.next_valid = false;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.first = invalid.next;
    assert(!dizi_rtc_wall_candidate(&invalid, &result)); /* halted RTC */
    invalid = p;
    invalid.next = p.first - 1;
    assert(!dizi_rtc_wall_candidate(&invalid, &result)); /* backwards */
    invalid = p;
    invalid.next = p.first + 4;
    assert(!dizi_rtc_wall_candidate(&invalid, &result)); /* large jump */
    invalid = p;
    invalid.elapsed_ms = DIZI_RTC_MIN_TICK_WAIT_MS - 1;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.elapsed_ms = DIZI_RTC_MAX_TICK_WAIT_MS + 1;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));

    invalid = p;
    invalid.first = 0u;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.first = DIZI_RTC_WALL_MIN - 1;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.first = DIZI_RTC_WALL_MAX - 1;
    invalid.next = DIZI_RTC_WALL_MAX;
    assert(!dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.first = DIZI_RTC_WALL_MIN;
    invalid.next = DIZI_RTC_WALL_MIN + 1;
    assert(dizi_rtc_wall_candidate(&invalid, &result));
    invalid = p;
    invalid.first = DIZI_RTC_WALL_MAX - 2;
    invalid.next = DIZI_RTC_WALL_MAX - 1;
    assert(dizi_rtc_wall_candidate(&invalid, &result));
    assert(!dizi_rtc_wall_candidate(NULL, &result));
    assert(!dizi_rtc_wall_candidate(&p, NULL));
}

static void test_candidate_output_stability(void)
{
    const struct dizi_rtc_wall_pair p = {
        .first = 0xfeedbeefu, .next = 0xfeedbef0u,
        .elapsed_ms = 1100u, .first_valid = true, .next_valid = true,
    };
    uint32_t out = 0x11223344u;
    assert(!dizi_rtc_wall_candidate(&p, &out));
    assert(out == 0x11223344u);
    /* The RTC year bound and monotonic progress gate are separate from XNU's
     * final current-calendar gate, which must execute inside settime_lock. */
    assert(dizi_rtc_wall_may_seed(DIZI_RTC_CLOCK_INVALID_BEFORE - 1));
    assert(!dizi_rtc_wall_may_seed((uint64_t)UINT32_MAX + 1u));
}

int main(void)
{
    test_two_independent_samples();
    test_candidate_output_stability();
    puts("PASS 0113 RTC: strict UTC window, independent tick, stalled/backwards/torn invalid, monotonic elapsed guard and never-seed-valid-time policy");
    return 0;
}
