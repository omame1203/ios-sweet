/* Dizi PMK8350 RTC policy for an optional, one-time XNU wall-clock seed.
 * Pure policy: no RTC writes, MMIO, clock setters or boot hooks here.
 * A single plausible number is insufficient: two separately validated
 * observer snapshots must demonstrate the seconds register advancing.
 */
#ifndef DIZI_RTC_WALLCLOCK_0113_H
#define DIZI_RTC_WALLCLOCK_0113_H
#include <stdint.h>
#include <stdbool.h>

/* This intentionally narrow time window is a sanity policy, not proof that
 * the chip's value is synchronized to UTC. Exclude counter resets and wrap.
 * Both endpoints are seconds since UNIX epoch in UTC. */
#define DIZI_RTC_WALL_MIN 1704067200u /* 2024-01-01 00:00:00 UTC */
#define DIZI_RTC_WALL_MAX 2051222400u /* 2035-01-01 exclusive */
#define DIZI_RTC_CLOCK_INVALID_BEFORE 1577836800u /* 2020-01-01 */
#define DIZI_RTC_MIN_TICK_WAIT_MS 20u
#define DIZI_RTC_MAX_TICK_WAIT_MS 2800u

struct dizi_rtc_wall_pair {
    uint32_t first;       /* stable double-read with CTRL.EN verified */
    uint32_t next;        /* second double-read with CTRL.EN reverified */
    uint32_t elapsed_ms;  /* monotonic elapsed between independent samples */
    bool first_valid;
    bool next_valid;
};

static inline bool
dizi_rtc_wall_candidate(const struct dizi_rtc_wall_pair *p, uint32_t *seconds)
{
    if (!p || !seconds || !p->first_valid || !p->next_valid ||
        p->elapsed_ms < DIZI_RTC_MIN_TICK_WAIT_MS ||
        p->elapsed_ms > DIZI_RTC_MAX_TICK_WAIT_MS ||
        p->first < DIZI_RTC_WALL_MIN || p->next >= DIZI_RTC_WALL_MAX ||
        p->next <= p->first || p->next - p->first > 3u)
        return false;
    *seconds = p->next;
    return true;
}

/* Must be rechecked INSIDE XNU's settime_lock, atomically with the update:
 * a check in the RTC caller alone would race settimeofday/NTP. Once the
 * calendar has any plausible date, never seed it from untrusted RTC again. */
static inline bool
dizi_rtc_wall_may_seed(uint64_t existing_secs)
{
    return existing_secs < DIZI_RTC_CLOCK_INVALID_BEFORE;
}

#endif /* DIZI_RTC_WALLCLOCK_0113_H */
