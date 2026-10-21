#ifndef DIZI_MACOS27_BOOT_ARGS_H
#define DIZI_MACOS27_BOOT_ARGS_H

#include <stddef.h>
#include <stdint.h>

/* Public xnu-12377 ARM64 boot.h layout, independently compared with the
 * 26A434 VMAPPLE entry loads: x20+8/16/24/0x470. This is a serializer for
 * loader work, not a claim that the rest of the macOS27 boot ABI is ported.
 * In particular never replace the legacy iPadOS shim's 608-byte command line.
 */
#define MAC27_BOOT_LINE_LENGTH 1024
#define MAC27_BOOT_ARGS_SIZE 1152
#define MAC27_BOOT_PAGE_SIZE UINT64_C(0x4000)

struct mac27_boot_video {
    uint64_t base, display, row_bytes, width, height, depth;
};

struct mac27_boot_args {
    uint16_t revision, version;
    uint64_t virt_base, phys_base, mem_size, top_of_kernel_data;
    struct mac27_boot_video video;
    uint32_t machine_type;
    uint64_t device_tree_va;
    uint32_t device_tree_length;
    char command_line[MAC27_BOOT_LINE_LENGTH];
    uint64_t boot_flags, mem_size_actual;
};

struct mac27_boot_params {
    uint64_t virt_base, phys_base, mem_size, top_of_kernel_data;
    uint64_t boot_args_pa, device_tree_pa, mem_size_actual;
    uint32_t device_tree_length, machine_type;
    struct mac27_boot_video video;
    uint64_t framebuffer_extent, boot_flags;
    const char *command_line;
    size_t command_line_length;
};

enum mac27_boot_error {
    MAC27_ARGS_OK = 0, MAC27_ARGS_OUTPUT, MAC27_ARGS_RANGE,
    MAC27_ARGS_COMMAND_LINE, MAC27_ARGS_VIDEO
};

/* Validate all arithmetic before modifying output. No allocations, physical
 * memory accesses, MMIO, fixup writes, jump to XNU or boot image generation.
 * Caller must separately prove KC mapping, CPU/ISA, ADT content, platform and
 * storage/boot policy. Params merely describe those locations, not authority.
 */
int mac27_encode_boot_args(void *output, size_t output_size,
                          const struct mac27_boot_params *params);

#endif
