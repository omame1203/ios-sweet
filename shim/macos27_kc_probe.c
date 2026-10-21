#include "macos27_kc_probe.h"
#include "../ports/macos27/kc_fixups.h"
#include "fdt.h"

const char *mac27_dizi_probe_dtb(uintptr_t dtb)
{
    uint64_t lo, hi;
    if (!fdt_chosen_u64(dtb, "linux,initrd-start", &lo) ||
        !fdt_chosen_u64(dtb, "linux,initrd-end", &hi) ||
        lo >= hi || hi - lo > MAC27_KC_MAX_BYTES || hi > UINTPTR_MAX)
        return "macOS27: missing/bad initrd";
    /* GKI boot v4 can concatenate the vendor ramdisk and supplied ramdisk.
     * Search for the decompressed Mach-O magic, but accept it only if the
     * complete fileset AND all fixup chain bounds pass validation. Raw IMG4
     * is never mistaken for a runnable kernel. No physical writes here. */
    const volatile uint8_t *data = (const volatile uint8_t *)(uintptr_t)lo;
    for (uint64_t index = 0; index + 32 <= hi - lo; ++index) {
        if (data[index] != 0xcf || data[index+1] != 0xfa ||
            data[index+2] != 0xed || data[index+3] != 0xfe)
            continue;
        /* mac27_kc_plan only reads byte-addressed fields; the ramdisk may
         * be unaligned. A caller could reuse plan/layout staging off-device. */
        struct mac27_kc_fixup_report report;
        if (mac27_kc_inspect_fixups((const void *)(uintptr_t)(lo + index),
                                   (size_t)(hi - lo - index),
                                   UINT64_C(0x8c0000000), UINT64_C(0xb0000000),
                                   &report) == MAC27_FIXUP_OK)
            return "macOS27: real KC parsed; PAC/APFS/driver gate BLOCKED";
    }
    return "macOS27: no validated decompressed KC in initrd";
}
