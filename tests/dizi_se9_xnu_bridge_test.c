/* SPDX-License-Identifier: MIT
 * The compiled XNU adapter MUST remain disabled even for forged ownership.
 * No MMIO address is dereferenced by this program or the adapter.
 */
#include "dizi_se9_xnu.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int read_fake(void *ctx, uint64_t pa, uint32_t *out)
{
    struct se9_snapshot *s = ctx;
    if (!s || !out) return -1;
    for (unsigned i = 0; i < s->count; ++i)
        if (s->regs[i].pa == pa) {
            *out = s->regs[i].value;
            return 0;
        }
    return -1;
}
int main(void)
{
    struct se9_snapshot s = {0};
    struct se9_plan plan;
    struct se9_ownership fake_authorized;
    memset(&fake_authorized, 1, sizeof(fake_authorized));
    assert(dizi_se9_xnu_enabled() == 0);
    memset(&plan, 0xf5, sizeof(plan));
    assert(dizi_se9_xnu_plan(&s, &plan) == SE9_NO_OWNER);
    assert(plan.count == 0);
    memset(&plan, 0xf5, sizeof(plan));
    assert(se9_make_plan(&s, &fake_authorized, true, &plan) == SE9_NO_OWNER);
    assert(plan.count == 0);
    memset(&plan, 0xf5, sizeof(plan));
    assert(se9_make_plan(&s, &fake_authorized, false, &plan) == SE9_NO_OWNER);
    assert(plan.count == 0);
    assert(dizi_se9_xnu_plan(NULL, &plan) == SE9_BAD_ARG);
    assert(dizi_se9_xnu_plan(&s, NULL) == SE9_BAD_ARG);
    assert(se9_verify_unchanged(&plan, read_fake, &s) == SE9_BAD_ARG);
    puts("PASS XNU SE9 offline default-disabled ownership gate");
    return 0;
}
