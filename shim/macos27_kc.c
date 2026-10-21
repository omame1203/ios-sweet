#include "macos27_kc.h"

static int inside(uint64_t off, uint64_t size, uint64_t limit)
{ return off <= limit && size <= limit - off; }

static int intersect(uint64_t start, uint64_t size, uint64_t other, uint64_t n)
{
    /* Treat overflowing/unrepresentable intervals as overlapping. */
    return size > UINT64_MAX - start || n > UINT64_MAX - other ||
           (size && n && start < other + n && other < start + size);
}

static int disjoint_pointers(const void *a, size_t n, const void *b, size_t size)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x <= UINTPTR_MAX - n && y <= UINTPTR_MAX - size &&
           !(n && size && x < y + size && y < x + n);
}

static int round_page(uint64_t addr, uint64_t *result)
{
    if (addr > UINT64_MAX - (MAC27_KC_PAGE - 1)) return 0;
    *result = (addr + MAC27_KC_PAGE - 1) & ~(MAC27_KC_PAGE - 1);
    return 1;
}

static void clear_bytes(void *ptr, size_t bytes)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < bytes; ++i) p[i] = 0;
}

static int derive(const void *kc, size_t kc_size,
                  const struct mac27_shim_request *req,
                  struct mac27_shim_layout *layout)
{
    struct mac27_shim_layout tmp;
    struct mac27_boot_params args;
    uint8_t encoded[MAC27_BOOT_ARGS_SIZE];
    uint64_t after_adt;
    if (!kc || !req || !layout || !req->adt || !req->adt_size ||
        req->adt_size > UINT32_MAX || req->phys_base != MAC27_DIZI_RAM_BASE ||
        req->memory_size != MAC27_DIZI_RAM_BYTES ||
        req->reserved_count > MAC27_SHIM_MAX_RESERVATIONS ||
        (req->command_line_size && !req->command_line))
        return MAC27_SHIM_ARGUMENT;
    clear_bytes(&tmp, sizeof(tmp));
    clear_bytes(&args, sizeof(args));
    if (mac27_kc_plan(kc, kc_size, req->phys_base, req->memory_size, &tmp.kc))
        return MAC27_SHIM_KC;
    /* Exactly the observed 26A434 kernel ABI: ARM64E subtype 2 with its
     * Mach-O capability bits. An arbitrary arm64/arm64e.x1 fileset must not
     * be classified as the inspected macOS 27 kernel. */
    if (tmp.kc.cpu_subtype != UINT32_C(0xc0000002))
        return MAC27_SHIM_KC;
    if (mac27_kc_inspect_fixups(kc, kc_size, req->phys_base, req->memory_size,
                               &tmp.fixups))
        return MAC27_SHIM_FIXUP;
    if (!round_page(tmp.kc.kernel_end_pa, &tmp.adt_pa) ||
        !inside(tmp.adt_pa - req->phys_base, req->adt_size, req->memory_size) ||
        req->adt_size > UINT64_MAX - tmp.adt_pa)
        return MAC27_SHIM_MEMORY;
    after_adt = tmp.adt_pa + req->adt_size;
    if (!round_page(after_adt, &tmp.boot_args_pa) ||
        tmp.boot_args_pa > UINT64_MAX - MAC27_KC_PAGE)
        return MAC27_SHIM_MEMORY;
    tmp.top_pa = tmp.boot_args_pa + MAC27_KC_PAGE;
    if (!inside(tmp.boot_args_pa - req->phys_base, MAC27_KC_PAGE, req->memory_size))
        return MAC27_SHIM_MEMORY;
    for (uint32_t i = 0; i < req->reserved_count; ++i) {
        struct mac27_shim_range range = req->reserved[i];
        if (!range.bytes || range.bytes > UINT64_MAX - range.pa ||
            intersect(req->phys_base, tmp.top_pa - req->phys_base, range.pa, range.bytes))
            return MAC27_SHIM_MEMORY;
    }
    args.virt_base = tmp.kc.virt_base;
    args.phys_base = req->phys_base;
    args.mem_size = args.mem_size_actual = req->memory_size;
    args.device_tree_pa = tmp.adt_pa;
    args.device_tree_length = (uint32_t)req->adt_size;
    args.boot_args_pa = tmp.boot_args_pa;
    args.top_of_kernel_data = tmp.top_pa;
    args.command_line = req->command_line;
    args.command_line_length = req->command_line_size;
    if (mac27_encode_boot_args(encoded, sizeof(encoded), &args))
        return MAC27_SHIM_BOOT_ARGS;
    /* No native entry API exists. A successful structural stage intentionally
     * leaves signed fixups opaque and boot authorization false. */
    tmp.native_boot_allowed = 0;
    volatile uint8_t *dest = (volatile uint8_t *)layout;
    const uint8_t *src = (const uint8_t *)&tmp;
    for (size_t i = 0; i < sizeof(tmp); ++i) dest[i] = src[i];
    return MAC27_SHIM_OK;
}

int mac27_shim_plan(const void *kc, size_t kc_size,
                    const struct mac27_shim_request *request,
                    struct mac27_shim_layout *layout)
{
    if (!request || !layout ||
        !disjoint_pointers(layout, sizeof(*layout), kc, kc_size) ||
        !disjoint_pointers(layout, sizeof(*layout), request, sizeof(*request)))
        return MAC27_SHIM_ARGUMENT;
    return derive(kc, kc_size, request, layout);
}

int mac27_shim_stage(const void *kc, size_t kc_size,
                     const struct mac27_shim_request *req,
                     const struct mac27_shim_layout *layout,
                     void *window, size_t capacity)
{
    struct mac27_shim_layout verified;
    struct mac27_kc_plan loaded;
    struct mac27_boot_params args;
    uint8_t encoded[MAC27_BOOT_ARGS_SIZE];
    uint64_t adt_offset, args_offset;
    if (!kc || !req || !layout || !window ||
        !disjoint_pointers(window, capacity, kc, kc_size) ||
        !disjoint_pointers(window, capacity, req->adt, req->adt_size) ||
        !disjoint_pointers(window, capacity, req, sizeof(*req)) ||
        !disjoint_pointers(window, capacity, layout, sizeof(*layout)))
        return MAC27_SHIM_ARGUMENT;
    /* Replan from unmodified input. Ignore any forged or stale plan passed by
     * the caller, including its physical layout and boot authorization. */
    int err = derive(kc, kc_size, req, &verified);
    if (err) return err;
    if (layout->kc.phys_base != verified.kc.phys_base ||
        layout->kc.virt_base != verified.kc.virt_base ||
        layout->kc.entry_pa != verified.kc.entry_pa ||
        layout->kc.occupied_size != verified.kc.occupied_size ||
        layout->adt_pa != verified.adt_pa ||
        layout->boot_args_pa != verified.boot_args_pa ||
        layout->top_pa != verified.top_pa || layout->native_boot_allowed)
        return MAC27_SHIM_ARGUMENT;
    adt_offset = verified.adt_pa - req->phys_base;
    args_offset = verified.boot_args_pa - req->phys_base;
    if (!inside(0, verified.top_pa - req->phys_base, capacity))
        return MAC27_SHIM_MEMORY;
    clear_bytes(&args, sizeof(args));
    args.virt_base = verified.kc.virt_base;
    args.phys_base = req->phys_base;
    args.mem_size = args.mem_size_actual = req->memory_size;
    args.device_tree_pa = verified.adt_pa;
    args.device_tree_length = (uint32_t)req->adt_size;
    args.boot_args_pa = verified.boot_args_pa;
    args.top_of_kernel_data = verified.top_pa;
    args.command_line = req->command_line;
    args.command_line_length = req->command_line_size;
    if (mac27_encode_boot_args(encoded, sizeof(encoded), &args))
        return MAC27_SHIM_BOOT_ARGS;
    if (mac27_kc_load(kc, kc_size, req->phys_base, req->memory_size,
                      window, capacity, &loaded))
        return MAC27_SHIM_KC;
    volatile uint8_t *dst = (volatile uint8_t *)window;
    const uint8_t *adt = req->adt;
    for (size_t i = 0; i < req->adt_size; ++i) dst[adt_offset + i] = adt[i];
    for (uint64_t i = 0; i < MAC27_KC_PAGE; ++i) dst[args_offset + i] = 0;
    for (size_t i = 0; i < sizeof(encoded); ++i) dst[args_offset + i] = encoded[i];
    return MAC27_SHIM_OK;
}
