/* SPDX-License-Identifier: MIT
 * Hostile matching/ABI assertions for 26A434 offline provider resolution.
 * This DOES NOT connect an IOKit service or imply macOS27 boot capability.
 */
#include "../ports/macos27/iokit_resolver.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static struct m27_iokit_personality driver(
    const char *bundle, const char *persona, const char *cls,
    const char *provider, const char *name, const char *resource)
{
    struct m27_iokit_personality d = {0};
    d.bundle_id = bundle;
    d.personality = persona;
    d.io_class = cls;
    d.provider_class = provider;
    d.resource_match = resource;
    if (name) {
        d.names[0] = name;
        d.names_count = 1;
    }
    return d;
}

static void real_metadata_paths(void)
{
    struct m27_iokit_runtime_evidence claims = {
        .arm64e_pac_verified = true, .kc_fixups_verified = true,
        .metaclass_abi_verified = true, .driver_xnu27_abi_verified = true,
        .provider_runtime_observed = true, .exclusive_hardware_owner_verified = true,
        .probe_and_start_observed = true, .platform_policy_verified = true
    };
    struct m27_iokit_personality gic = driver(
        "com.apple.driver.AppleARMGIC", "AppleARMGICv3", "AppleARMGICv3",
        "AppleARMIODevice", "ARM,gicv3", 0);
    /* XNU22 GICv3 lives in ARM machine code; NO registered AppleARMIODevice
     * nub is available to bind the 26A434 AppleARMGICv3 personality. */
    assert(m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_GIC) == NULL);
    struct m27_iokit_provider synthetic = {
        .name = "ARM,gicv3", .class_name = "AppleARMIODevice"
    };
    struct m27_iokit_result r = m27_iokit_resolve(&gic, &synthetic, NULL);
    assert(r.match == M27_IOKIT_CANDIDATE_ONLY && r.metadata_candidate);
    assert(r.blockers == M27_IOKIT_ALL_BLOCKERS && !r.attach_authorized);
    /* Even a hostile caller setting every flag cannot turn an offline
     * metadata match into a runtime IOService registration. */
    r = m27_iokit_resolve(&gic, &synthetic, &claims);
    assert(!r.blockers && r.metadata_candidate && !r.attach_authorized);

    struct m27_iokit_personality pe = driver(
        "com.apple.driver.AppleARMPlatform", "AppleARMPE", "AppleARMPE",
        "IOPlatformExpertDevice", "AppleARM", 0);
    r = m27_iokit_resolve(&pe,
        m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_PLATFORM), NULL);
    assert(r.match == M27_IOKIT_NO_NAME_MATCH && !r.metadata_candidate);

    struct m27_iokit_personality virt = driver(
        "com.apple.driver.AppleVirtualPlatform", "AppleVirtualPlatformARMPE",
        "AppleVirtualPlatformARMPE", "IOPlatformExpertDevice",
        "AppleVirtualPlatformARM", 0);
    r = m27_iokit_resolve(&virt,
        m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_PLATFORM), NULL);
    assert(r.match == M27_IOKIT_NO_NAME_MATCH && !r.attach_authorized);

    struct m27_iokit_personality gpu = driver(
        "com.apple.driver.AppleParavirtGPUIOGPUFamily", "AppleParavirtGPUARM",
        "AppleParavirtGPU", "AppleARMIODevice", "paravirtualizedgraphics,gpu", 0);
    r = m27_iokit_resolve(&gpu,
        m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_DISPLAY), NULL);
    assert(r.match == M27_IOKIT_NO_PROVIDER_CLASS);

    struct m27_iokit_personality display = driver(
        "com.apple.iokit.IOGraphicsFamily", "AppleDisplay", "AppleDisplay",
        "IODisplayConnect", NULL, NULL);
    r = m27_iokit_resolve(&display,
        m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_DISPLAY), NULL);
    assert(r.match == M27_IOKIT_NO_PROVIDER_CLASS);
    /* IOMobileFramebuffer/AppleCLCD is not a desktop IODisplayConnect. */

    struct m27_iokit_personality hid = driver(
        "com.apple.iokit.IOHIDFamily", "IOHIDEventServiceUserClient",
        "IOHIDProviderPropertyMerger", "IOHIDEventService", NULL, NULL);
    r = m27_iokit_resolve(&hid,
        m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_HID), NULL);
    assert(r.match == M27_IOKIT_NO_PROVIDER_CLASS);
    /* XNU22 defines a private IOHIDEventService class, which is not
     * binary ABI-compatible with the macOS27 IOHIDFamily object layout. */

    struct m27_iokit_personality hid_sys = driver(
        "com.apple.iokit.IOHIDFamily", "IOHIDSystem", "IOHIDSystem",
        "IOResources", NULL, "IOBSD");
    r = m27_iokit_resolve(&hid_sys,
        m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_IORESOURCES), NULL);
    assert(r.match == M27_IOKIT_CANDIDATE_ONLY && !r.attach_authorized);
    assert(r.blockers == M27_IOKIT_ALL_BLOCKERS);
    /* Presence of IOResources/IOBSD in a name table cannot prove
     * macOS27 HIDSystem is loaded, scheduled, or supplied with input. */
}

static void malformed_and_selector_tests(void)
{
    struct m27_iokit_personality d = driver("org.vendor.driver", "probe", "Main",
        "IOPlatformDevice", "dizi,display", 0);
    struct m27_iokit_provider p = {
        .name = "dizi,display", .class_name = "IOPlatformDevice"
    };
    assert(m27_iokit_resolve(NULL, &p, NULL).match == M27_IOKIT_INVALID);
    assert(m27_iokit_resolve(&d, NULL, NULL).match == M27_IOKIT_INVALID);
    d.bundle_id = NULL;
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_INVALID);
    d.bundle_id = "org.vendor.driver";
    d.names_count = 9;
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_INVALID);
    d.names_count = 1;
    d.names[0] = NULL;
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_INVALID);
    d.names[0] = "dizi,display";
    p.superclasses_count = 7;
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_INVALID);
    p.superclasses_count = 0;
    d.resource_match = "IOKit";
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_NO_RESOURCE_MATCH);
    p.resource = "IOBSD";
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_NO_RESOURCE_MATCH);
    p.resource = "IOKit";
    assert(m27_iokit_resolve(&d, &p, NULL).metadata_candidate);
    d.property_match_present = true;
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_UNSUPPORTED_KEYS);
    d.property_match_present = false;
    d.other_unsupported_selectors = true;
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_UNSUPPORTED_KEYS);
    d.other_unsupported_selectors = false;
    d.match_category = "AppleGraphicsDisplay";
    p.match_category = "SomethingElse";
    /* MatchCategory is a personality arbitration label and not a provider
     * property! The resolver must NOT accidentally gate on it. */
    assert(m27_iokit_resolve(&d, &p, NULL).metadata_candidate);
    d.names[0] = "paravirtualizedgraphics,gpu";
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_NO_NAME_MATCH);
    d.names[1] = "dizi,display"; d.names_count = 2;
    assert(m27_iokit_resolve(&d, &p, NULL).metadata_candidate);
    d.names_count = 0;
    assert(m27_iokit_resolve(&d, &p, NULL).metadata_candidate);
    d.provider_class = "AppleARMIODevice";
    assert(m27_iokit_resolve(&d, &p, NULL).match == M27_IOKIT_NO_PROVIDER_CLASS);
    p.superclasses[0] = "AppleARMIODevice"; p.superclasses_count = 1;
    assert(m27_iokit_resolve(&d, &p, NULL).metadata_candidate);
    /* The hierarchy above is test data, not witnessed by macOS27 runtime:
     * attach_authorized always false. */
    assert(!m27_iokit_resolve(&d, &p, NULL).attach_authorized);
    assert(!m27_iokit_dizi_xnu22_provider((enum m27_iokit_dizi_provider_id)-1));
    assert(!m27_iokit_dizi_xnu22_provider(M27_IOKIT_DIZI_COUNT));
}

static void ranking_and_fuzz(void)
{
    struct m27_iokit_personality d[4];
    d[0] = driver("b.one", "p1", "Class1", "IOResources", NULL, "IOKit");
    d[1] = driver("b.two", "p2", "Class2", "IOResources", NULL, "IOKit");
    d[2] = driver("b.three", "p3", "Class3", "IOResources", NULL, "IOBSD");
    d[3] = driver("b.four", "p4", "Class4", "IOPlatformDevice", "x", NULL);
    struct m27_iokit_provider p = {.name = "IOResources", .class_name = "IOResources",
                                  .resource = "IOKit"};
    d[0].probe_score = -100; d[1].probe_score = 100;
    struct m27_iokit_choice c = m27_iokit_choose(d, 4, &p);
    assert(c.matching_count == 2 && c.selected_index == 1 &&
        c.best_score == 100 && !c.tie_for_best && !c.attach_authorized);
    d[0].probe_score = 100;
    c = m27_iokit_choose(d, 4, &p);
    assert(c.matching_count == 2 && c.selected_index == UINT16_MAX && c.tie_for_best);
    d[0].probe_score = INT32_MIN; d[1].probe_score = INT32_MIN;
    c = m27_iokit_choose(d, 4, &p);
    assert(c.selected_index == UINT16_MAX && c.tie_for_best);
    assert(m27_iokit_choose(NULL, 4, &p).selected_index == UINT16_MAX);
    assert(m27_iokit_choose(d, 65, &p).selected_index == UINT16_MAX);
    assert(m27_iokit_choose(d, 4, NULL).selected_index == UINT16_MAX);

    uint32_t rng = 0x7265736Fu;
    for (unsigned i = 0; i < 100000; ++i) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        bool expected = (rng & 3u) == 3;
        p.name = (rng & 1u) ? "ARM,gicv3" : "ARM,psci";
        p.class_name = (rng & 2u) ? "AppleARMIODevice" : "IOPlatformDevice";
        struct m27_iokit_personality a = driver("com.apple.driver.AppleARMGIC",
            "AppleARMGICv3", "AppleARMGICv3", "AppleARMIODevice", "ARM,gicv3", 0);
        struct m27_iokit_result r = m27_iokit_resolve(&a, &p, NULL);
        assert(r.metadata_candidate == expected);
        assert(!r.attach_authorized);
        if (expected) assert(r.match == M27_IOKIT_CANDIDATE_ONLY);
    }
}

int main(void)
{
    real_metadata_paths();
    malformed_and_selector_tests();
    ranking_and_fuzz();
    puts("PASS macOS27 IOKit: 26A434 provider/name/resource gating, XNU22 class mismatch, PAC fail-closed, 100k hostile combinations, zero attachments");
    return 0;
}
