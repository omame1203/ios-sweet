#ifndef DIZI_SHIM_MACOS27_KC_H
#define DIZI_SHIM_MACOS27_KC_H

#include "../ports/macos27/kc_loader.h"
#include "../ports/macos27/kc_fixups.h"
#include "../ports/macos27/boot_args.h"

#define MAC27_DIZI_RAM_BASE UINT64_C(0x8c0000000)
#define MAC27_DIZI_RAM_BYTES UINT64_C(0xb0000000)
#define MAC27_SHIM_MAX_RESERVATIONS 8

struct mac27_shim_range { uint64_t pa, bytes; };

struct mac27_shim_request {
    uint64_t phys_base, memory_size;
    const void *adt;
    size_t adt_size;
    const char *command_line;
    size_t command_line_size;
    struct mac27_shim_range reserved[MAC27_SHIM_MAX_RESERVATIONS];
    uint32_t reserved_count;
};

struct mac27_shim_layout {
    struct mac27_kc_plan kc;
    struct mac27_kc_fixup_report fixups;
    uint64_t adt_pa, boot_args_pa, top_pa;
    /* Zero by construction: no authenticated fixup/signing, platform driver,
     * APFS trust, or SM7435 PAC gate has established execution safety. */
    uint32_t native_boot_allowed;
};

enum mac27_shim_error {
    MAC27_SHIM_OK = 0, MAC27_SHIM_ARGUMENT, MAC27_SHIM_KC,
    MAC27_SHIM_FIXUP, MAC27_SHIM_MEMORY, MAC27_SHIM_BOOT_ARGS
};

/* Prepare a real dizi RAM/ADT/boot-args layout without touching physical RAM.
 * reserved[] MUST describe all externally owned physical ranges including
 * initrd, live ABL shim, DTB and firmware. This is a layout check, not proof
 * of EL1 RAM ownership or native boot readiness. */
int mac27_shim_plan(const void *kc, size_t kc_size,
                    const struct mac27_shim_request *request,
                    struct mac27_shim_layout *layout);

/* Materialize to an explicit caller-owned mapped buffer for OFFLINE tests.
 * Never jumps to entry_pa, rebases pointers, signs PAC or touches MMIO.
 * Caller must prove destination memory actually belongs to it. */
int mac27_shim_stage(const void *kc, size_t kc_size,
                     const struct mac27_shim_request *request,
                     const struct mac27_shim_layout *layout,
                     void *window, size_t capacity);

#endif
