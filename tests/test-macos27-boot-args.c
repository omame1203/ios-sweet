#include "../ports/macos27/boot_args.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct mac27_boot_params params(void)
{
    struct mac27_boot_params p = {0};
    p.virt_base = UINT64_C(0xfffffe0007000000);
    p.phys_base = UINT64_C(0x8c0000000);
    p.mem_size = p.mem_size_actual = UINT64_C(0xb0000000);
    p.device_tree_pa = p.phys_base + 0x8000000;
    p.device_tree_length = 12492;
    p.boot_args_pa = p.device_tree_pa + 0x4000;
    p.top_of_kernel_data = p.boot_args_pa + 0x4000;
    p.video = (struct mac27_boot_video){0xb8000000, 1, 6400, 1600, 2560, 32};
    p.framebuffer_extent = 0x2b00000;
    p.boot_flags = 1;
    p.command_line = "debug=0x144 keepsyms=1";
    p.command_line_length = strlen(p.command_line);
    return p;
}

static void reject(struct mac27_boot_params p, int expected)
{
    unsigned char bytes[MAC27_BOOT_ARGS_SIZE];
    memset(bytes, 0xa5, sizeof(bytes));
    assert(mac27_encode_boot_args(bytes, sizeof(bytes), &p) == expected);
    for (size_t i = 0; i < sizeof(bytes); i++) assert(bytes[i] == 0xa5);
}

int main(int argc, char **argv)
{
    struct mac27_boot_params p = params(), bad;
    struct mac27_boot_args result;
    unsigned char bytes[MAC27_BOOT_ARGS_SIZE + 2];
    memset(bytes, 0xa5, sizeof(bytes));
    /* Output may be unaligned host storage: the encoder copies bytes only. */
    assert(mac27_encode_boot_args(bytes + 1, sizeof(bytes) - 2, &p) == 0);
    assert(bytes[0] == 0xa5 && bytes[sizeof(bytes) - 1] == 0xa5);
    memcpy(&result, bytes + 1, sizeof(result));
    assert(result.revision == 2 && result.version == 2);
    assert(result.virt_base == p.virt_base && result.phys_base == p.phys_base);
    assert(result.mem_size == p.mem_size && result.mem_size_actual == p.mem_size_actual);
    assert(result.device_tree_va == p.virt_base + 0x8000000);
    assert(result.device_tree_length == 12492 && result.boot_flags == 1);
    assert(!strcmp(result.command_line, p.command_line));
    assert(!result.command_line[1023]);
    for (size_t i = 4; i < 8; i++) assert(bytes[1 + i] == 0);
    for (size_t i = 92; i < 96; i++) assert(bytes[1 + i] == 0);
    assert(mac27_encode_boot_args(bytes, MAC27_BOOT_ARGS_SIZE - 1, &p) == MAC27_ARGS_OUTPUT);
    assert(mac27_encode_boot_args(NULL, sizeof(bytes), &p) == MAC27_ARGS_OUTPUT);
    assert(mac27_encode_boot_args(bytes, sizeof(bytes), NULL) == MAC27_ARGS_OUTPUT);

    bad = p; bad.phys_base = UINT64_MAX - 0x3fff; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.virt_base = UINT64_MAX - 0x3fff; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.mem_size = 0; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.mem_size_actual = p.mem_size - 1; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.device_tree_pa = p.phys_base - 0x4000; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.device_tree_length = 0; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.device_tree_length = 0x4001; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.boot_args_pa++; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.top_of_kernel_data = p.boot_args_pa; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.top_of_kernel_data = p.phys_base + p.mem_size + 0x4000; reject(bad, MAC27_ARGS_RANGE);
    bad = p; bad.video.row_bytes = 0; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.video.width = UINT64_MAX; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.video.height = UINT64_MAX; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.video.base = UINT64_MAX; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.framebuffer_extent = 1600; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.video.depth = 24; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.video.display = 0; reject(bad, MAC27_ARGS_VIDEO);
    bad = p; bad.command_line = NULL; reject(bad, MAC27_ARGS_COMMAND_LINE);
    bad = p; bad.command_line = "a\0b"; bad.command_line_length = 3; reject(bad, MAC27_ARGS_COMMAND_LINE);
    char longline[1024]; memset(longline, 'x', sizeof(longline));
    bad = p; bad.command_line = longline; bad.command_line_length = 1024; reject(bad, MAC27_ARGS_COMMAND_LINE);
    bad.command_line_length = 1023;
    assert(mac27_encode_boot_args(&result, sizeof(result), &bad) == 0);
    assert(result.command_line[1022] == 'x' && result.command_line[1023] == 0);
    bad = p; bad.video = (struct mac27_boot_video){0}; bad.framebuffer_extent = 0;
    bad.command_line = NULL; bad.command_line_length = 0;
    assert(mac27_encode_boot_args(&result, sizeof(result), &bad) == 0);
    assert(!result.video.display && !result.command_line[0]);

    if (argc == 2) {
        assert(mac27_encode_boot_args(&result, sizeof(result), &p) == 0);
        FILE *f = fopen(argv[1], "wb"); assert(f);
        assert(fwrite(&result, sizeof(result), 1, f) == 1);
        assert(fclose(f) == 0);
    }
    puts("PASS macOS27 boot args: range/overflow/placement/video/cmdline and transactional failure; no boot");
    return 0;
}
