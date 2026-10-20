/* Exercise the actual loader with an unaligned GKI vendor-ramdisk prefix,
 * valid payload placement, BSS tails, and malformed size/offset fields.
 * Only the final architecture-specific jump is intercepted. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LOADER_HOST_TEST 1
#include "loader.c"

char _head[1], _end[1];
static uint64_t initrd_start, initrd_end;
static unsigned jumps;
static unsigned char *kernel;

int fdt_chosen_u64(uintptr_t dtb, const char *name, uint64_t *out)
{
	(void)dtb;
	*out = strcmp(name, "linux,initrd-start") == 0 ? initrd_start : initrd_end;
	return 1;
}
void con_hex(const char *label, uint64_t value) { (void)label; (void)value; }
void con_hex2(const char *label, const char *a, uint32_t va, const char *b, uint32_t vb)
{ (void)label; (void)a; (void)va; (void)b; (void)vb; }
void con_str(const char *label, const char *s) { (void)label; (void)s; }

void loader_host_jump(uint64_t address)
{
	struct boot_args *ba = (struct boot_args *)(uintptr_t)address;
	assert(ba->physBase == (uintptr_t)kernel);
	assert(ba->Version == 2 && ba->Revision == 2);
	assert(ba->Video.v_baseAddr == FB_BASE && ba->Video.v_width == FB_W);
	assert(ba->Video.v_height == FB_H && ba->Video.v_rowBytes == FB_STRIDE);
	assert(memcmp(kernel + PAGE_16K, "0123456789abcdef!", 17) == 0);
	for (int i = 17; i < 64; i++)
		assert(kernel[PAGE_16K + i] == 0);
	assert(memcmp(kernel + 2 * PAGE_16K, "ADT-fixture!", 12) == 0);
	assert(ba->CommandLine[BOOT_LINE_LENGTH - 1] == 0);
	jumps++;
}

static unsigned char *fixture(unsigned prefix)
{
	unsigned char *ramdisk = calloc(1, 2048 + prefix);
	assert(ramdisk);
	memset(ramdisk, 0x1f, prefix);
	struct payload p = { .version = 1, .nsegs = 1,
		.virt_base = 0xfffffe0000000000ULL, .adt_off = 1024, .adt_size = 12,
		.phys_base = (uintptr_t)kernel, .mem_size = 16 * PAGE_16K };
	memcpy(p.magic, "SWEETXNU", 8);
	p.entry_va = p.virt_base + PAGE_16K;
	p.kernel_end = p.virt_base + 2 * PAGE_16K;
	memset(p.cmdline, 'x', sizeof(p.cmdline));
	struct payload_seg seg = { .vmaddr = p.entry_va, .vmsize = 64, .file_off = 768, .file_size = 17 };
	memcpy(ramdisk + prefix, &p, sizeof(p));
	memcpy(ramdisk + prefix + sizeof(p), &seg, sizeof(seg));
	memcpy(ramdisk + prefix + 768, "0123456789abcdef!", 17);
	memcpy(ramdisk + prefix + 1024, "ADT-fixture!", 12);
	initrd_start = (uintptr_t)ramdisk;
	initrd_end = initrd_start + prefix + 1036;
	memset(kernel, 0xaa, 16 * PAGE_16K);
	return ramdisk;
}

int main(void)
{
	kernel = aligned_alloc(PAGE_16K, 16 * PAGE_16K);
	assert(kernel);
	for (unsigned prefix = 0; prefix < 64; prefix++) {
		unsigned char *data = fixture(prefix);
		assert(strcmp(loader_boot(0), "xnu returned") == 0);
		free(data);
	}
	assert(jumps == 64);
	unsigned char *data = fixture(37);
	struct payload p;
	memcpy(&p, data + 37, sizeof(p));
	p.nsegs = 129;
	memcpy(data + 37, &p, sizeof(p));
	assert(strcmp(loader_boot(0), "bad payload header") == 0);
	free(data);
	data = fixture(37);
	struct payload_seg seg;
	memcpy(&seg, data + 37 + sizeof(p), sizeof(seg));
	seg.file_off = UINT64_MAX;
	memcpy(data + 37 + sizeof(p), &seg, sizeof(seg));
	assert(strcmp(loader_boot(0), "bad payload segment") == 0);
	free(data);
	data = fixture(37);
	initrd_end = initrd_start + 50;
	assert(strcmp(loader_boot(0), "no SWEETXNU payload") == 0);
	free(data);
	assert(jumps == 64);
	free(kernel);
	puts("PASS: 64 prefix alignments, segment/BSS/ADT/boot-args copies and malformed payload bounds");
	return 0;
}
