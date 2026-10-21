#include "boot_args.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The macOS ARM64 boot-argument wire format requires little endian"
#endif

_Static_assert(sizeof(struct mac27_boot_args) == MAC27_BOOT_ARGS_SIZE, "boot args extent");
_Static_assert(offsetof(struct mac27_boot_args, virt_base) == 8, "virtBase entry load");
_Static_assert(offsetof(struct mac27_boot_args, phys_base) == 16, "physBase entry load");
_Static_assert(offsetof(struct mac27_boot_args, mem_size) == 24, "memSize entry load");
_Static_assert(offsetof(struct mac27_boot_args, video) == 40, "Boot_Video layout");
_Static_assert(offsetof(struct mac27_boot_args, device_tree_va) == 96, "ADT virtual pointer");
_Static_assert(offsetof(struct mac27_boot_args, command_line) == 108, "command-line layout");
_Static_assert(offsetof(struct mac27_boot_args, boot_flags) == 0x470, "actual 26A434 entry load");
_Static_assert(offsetof(struct mac27_boot_args, mem_size_actual) == 0x478, "memory tail");

static int aligned(uint64_t value)
{
    return !(value & (MAC27_BOOT_PAGE_SIZE - 1));
}

static int inside(uint64_t address, uint64_t length, uint64_t base, uint64_t size)
{
    return address >= base && address - base < size && length <= size - (address - base);
}

int mac27_encode_boot_args(void *output, size_t output_size,
                          const struct mac27_boot_params *p)
{
    struct mac27_boot_args args;
    uint64_t dt_end, args_end, dt_va;
    uint8_t *bytes = (uint8_t *)&args;
    if (!output || !p || output_size < sizeof(args))
        return MAC27_ARGS_OUTPUT;
    if (!p->mem_size || !aligned(p->virt_base) || !aligned(p->phys_base) ||
        !aligned(p->mem_size) || p->mem_size > UINT64_MAX - p->phys_base ||
        p->mem_size > UINT64_MAX - p->virt_base ||
        p->mem_size_actual < p->mem_size ||
        !aligned(p->top_of_kernel_data) || !aligned(p->boot_args_pa) ||
        !aligned(p->device_tree_pa) || !p->device_tree_length ||
        !inside(p->device_tree_pa, p->device_tree_length, p->phys_base, p->mem_size) ||
        !inside(p->boot_args_pa, sizeof(args), p->phys_base, p->mem_size))
        return MAC27_ARGS_RANGE;
    dt_end = p->device_tree_pa + p->device_tree_length;
    args_end = p->boot_args_pa + sizeof(args);
    if (dt_end > p->boot_args_pa || p->top_of_kernel_data < args_end ||
        p->top_of_kernel_data > p->phys_base + p->mem_size)
        return MAC27_ARGS_RANGE;
    dt_va = p->virt_base + (p->device_tree_pa - p->phys_base);
    if (p->command_line_length >= MAC27_BOOT_LINE_LENGTH ||
        (p->command_line_length && !p->command_line))
        return MAC27_ARGS_COMMAND_LINE;
    for (size_t i = 0; i < p->command_line_length; i++)
        if (!p->command_line[i])
            return MAC27_ARGS_COMMAND_LINE;
    if (p->video.display) {
        if (!p->video.width || !p->video.height || !p->video.base ||
            (p->video.depth & 0xff) != 32 || p->video.width > UINT64_MAX / 4 ||
            p->video.row_bytes < p->video.width * 4 ||
            p->video.height > p->framebuffer_extent / p->video.row_bytes ||
            p->framebuffer_extent > UINT64_MAX - p->video.base)
            return MAC27_ARGS_VIDEO;
    } else if (p->video.base || p->video.row_bytes || p->video.width || p->video.height ||
               p->video.depth || p->framebuffer_extent) {
        return MAC27_ARGS_VIDEO;
    }
    for (size_t i = 0; i < sizeof(args); i++)
        bytes[i] = 0;
    args.revision = 2;
    args.version = 2;
    args.virt_base = p->virt_base;
    args.phys_base = p->phys_base;
    args.mem_size = p->mem_size;
    args.top_of_kernel_data = p->top_of_kernel_data;
    /* A struct assignment can emit memcpy even with -ffreestanding and
     * -fno-builtin when compiling without SIMD. Keep the shim self-contained. */
    args.video.base = p->video.base;
    args.video.display = p->video.display;
    args.video.row_bytes = p->video.row_bytes;
    args.video.width = p->video.width;
    args.video.height = p->video.height;
    args.video.depth = p->video.depth;
    args.machine_type = p->machine_type;
    args.device_tree_va = dt_va;
    args.device_tree_length = p->device_tree_length;
    for (size_t i = 0; i < p->command_line_length; i++)
        args.command_line[i] = p->command_line[i];
    args.boot_flags = p->boot_flags;
    args.mem_size_actual = p->mem_size_actual;
    for (size_t i = 0; i < sizeof(args); i++)
        ((uint8_t *)output)[i] = bytes[i];
    return MAC27_ARGS_OK;
}
