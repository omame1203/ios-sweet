/*
 * Milestone 4: act as iBoot for xnu.
 *
 * mkpayload.py already resolved the kernel's chained fixups and built the
 * ADT, so this only has to: find the payload in the ABL ramdisk, copy the
 * segments to phys_base + (vmaddr - virt_base), place the ADT and
 * boot_args behind the kernel, and jump to the entry point with the MMU
 * and caches off, x0 = boot_args (physical).
 */
#include <stdint.h>
#include "console.h"
#include "fdt.h"
#include "loader.h"

#define BOOT_LINE_LENGTH	608
#define PAGE_16K		0x4000UL

struct payload_seg {
	uint64_t vmaddr, vmsize, file_off, file_size;
};

struct payload {
	char magic[8];
	uint32_t version, nsegs;
	uint64_t virt_base, entry_va, adt_off, adt_size, kernel_end;
	uint64_t phys_base, mem_size;
	char cmdline[BOOT_LINE_LENGTH];
	struct payload_seg segs[];
};

/* pexpert/pexpert/arm64/boot.h, Revision/Version 2 */
struct boot_video {
	uint64_t v_baseAddr, v_display, v_rowBytes, v_width, v_height, v_depth;
};

struct boot_args {
	uint16_t Revision, Version;
	uint64_t virtBase, physBase, memSize, topOfKernelData;
	struct boot_video Video;
	uint32_t machineType;
	uint64_t deviceTreeP;
	uint32_t deviceTreeLength;
	char CommandLine[BOOT_LINE_LENGTH];
	uint64_t bootFlags, memSizeActual;
};

_Static_assert(__builtin_offsetof(struct payload, segs) == 0x2a8, "payload header layout");
_Static_assert(__builtin_offsetof(struct boot_args, Video) == 40, "boot_args layout");
_Static_assert(__builtin_offsetof(struct boot_args, CommandLine) == 108, "boot_args layout");
_Static_assert(sizeof(struct boot_args) == 736, "boot_args layout");

/* MMU off: everything is Device memory, so copy in aligned 8-byte words. */
static void copy64(uintptr_t dst, uintptr_t src, uint64_t n)
{
	/* GKI boot v4 concatenates the vendor ramdisk and ours. Its length need
	 * not be aligned to 8, even though mkpayload's relative offsets are. */
	if ((src | dst | n) & 7) {
		volatile uint8_t *d8 = (volatile uint8_t *)dst;
		volatile const uint8_t *s8 = (volatile const uint8_t *)src;
		for (uint64_t i = 0; i < n; i++)
			d8[i] = s8[i];
		return;
	}
	volatile uint64_t *d = (volatile uint64_t *)dst;
	volatile const uint64_t *s = (volatile const uint64_t *)src;
	for (uint64_t i = 0; i < (n + 7) / 8; i++)
		d[i] = s[i];
}

static void zero64(uintptr_t dst, uint64_t n)
{
	while ((dst & 7) && n) {
		*(volatile uint8_t *)dst++ = 0;
		n--;
	}
	volatile uint64_t *d = (volatile uint64_t *)dst;
	for (uint64_t i = 0; i < n / 8; i++)
		d[i] = 0;
	for (uint64_t i = n & ~7ULL; i < n; i++)
		*(volatile uint8_t *)(dst + i) = 0;
}

static int magic_ok(const char *m)
{
	static const char want[] = "SWEETXNU";
	for (int i = 0; i < 8; i++)
		if (m[i] != want[i])
			return 0;
	return 1;
}

typedef void (*xnu_entry_t)(uint64_t boot_args_pa);

const char *loader_boot(uintptr_t dtb)
{
	uint64_t rd_start, rd_end;
	struct payload header;
	struct payload_seg segments[128];

	if (!fdt_chosen_u64(dtb, "linux,initrd-start", &rd_start) ||
	    !fdt_chosen_u64(dtb, "linux,initrd-end", &rd_end))
		return "no initrd in /chosen";
	con_hex2("INITRD", "lo=", rd_start, "hi=", rd_end);
	if (rd_start >= rd_end || rd_end - rd_start > 128UL * 1024 * 1024)
		return "bad initrd bounds";

	/* Legacy boot v2 starts with the payload. GKI boot v4 prepends the
	 * existing vendor ramdisk. Search only within the supplied initrd;
	 * never interpret unaligned Device memory as a C struct. */
	uintptr_t payload_start = rd_start;
	for (; rd_end - payload_start >= sizeof(header); payload_start++)
		if (magic_ok((const char *)payload_start))
			break;
	if (rd_end - payload_start < sizeof(header))
		return "no SWEETXNU payload";
	copy64((uintptr_t)&header, payload_start, sizeof(header));
	const struct payload *p = &header;
	uint64_t payload_size = rd_end - payload_start;
	if (p->version != 1 || p->nsegs == 0 || p->nsegs > 128 || (p->adt_off & 7))
		return "bad payload header";
	uint64_t table_end = sizeof(header) + p->nsegs * sizeof(segments[0]);
	if (table_end > payload_size || p->adt_off < table_end ||
	    p->adt_off > payload_size || p->adt_size > payload_size - p->adt_off)
		return "bad payload offsets";
	if (p->mem_size == 0 || p->phys_base > UINT64_MAX - p->mem_size ||
	    (p->phys_base & (PAGE_16K - 1)) || (p->mem_size & (PAGE_16K - 1)) ||
	    p->kernel_end < p->virt_base || p->kernel_end - p->virt_base > p->mem_size ||
	    p->entry_va < p->virt_base || p->entry_va - p->virt_base >= p->mem_size)
		return "bad kernel memory bounds";
	uint64_t kernel_bytes = p->kernel_end - p->virt_base;
	if (p->adt_size == 0 || p->mem_size - kernel_bytes < p->adt_size ||
	    p->mem_size - kernel_bytes - p->adt_size < 2 * PAGE_16K)
		return "no room for ADT and boot args";
	copy64((uintptr_t)segments, payload_start + sizeof(header), p->nsegs * sizeof(segments[0]));
	int entry_loaded = 0;
	for (uint32_t i = 0; i < p->nsegs; i++) {
		const struct payload_seg *s = &segments[i];
		if (s->file_off < table_end || s->file_off > payload_size ||
		    s->file_size > payload_size - s->file_off || s->file_size > s->vmsize ||
		    s->vmaddr < p->virt_base || s->vmaddr - p->virt_base > kernel_bytes ||
		    s->vmsize > kernel_bytes - (s->vmaddr - p->virt_base) ||
		    (s->vmaddr & 7) || (s->vmsize & 7))
			return "bad payload segment";
		if (p->entry_va >= s->vmaddr && p->entry_va - s->vmaddr < s->file_size)
			entry_loaded = 1;
	}
	if (!entry_loaded)
		return "entry outside loaded segments";

	uint64_t pa_of_va_base = p->phys_base - p->virt_base;	/* pa = va + this */
	con_hex2("PHYS", "base=", p->phys_base, "size=", p->mem_size);
	con_hex("VIRT", p->virt_base);
	con_hex("ENTRY", p->entry_va);

	/* The payload must not overlap where the kernel goes. */
	if (rd_end > p->phys_base && rd_start < p->phys_base + p->mem_size)
		return "ramdisk overlaps kernel memory";
	extern char _head[], _end[];
	if ((uintptr_t)_end > p->phys_base && (uintptr_t)_head < p->phys_base + p->mem_size)
		return "kernel memory overlaps loader";

	for (uint32_t i = 0; i < p->nsegs; i++) {
		const struct payload_seg *s = &segments[i];
		uintptr_t dst = s->vmaddr + pa_of_va_base;
		copy64(dst, payload_start + s->file_off, s->file_size);
		if (s->vmsize > s->file_size)
			zero64(dst + s->file_size, s->vmsize - s->file_size);
	}
	con_hex2("SEGS", "n=", p->nsegs, "end=", p->kernel_end + pa_of_va_base);

	/* ADT, then boot_args, behind the kernel; everything below topOfKernelData is ours. */
	uintptr_t adt_pa = p->kernel_end + pa_of_va_base;
	copy64(adt_pa, payload_start + p->adt_off, p->adt_size);
	uintptr_t ba_pa = (adt_pa + p->adt_size + PAGE_16K - 1) & ~(PAGE_16K - 1);
	uintptr_t top = ba_pa + PAGE_16K;

	zero64(ba_pa, PAGE_16K);
	volatile struct boot_args *ba = (volatile struct boot_args *)ba_pa;
	ba->Revision = 2;
	ba->Version = 2;
	ba->virtBase = p->virt_base;
	ba->physBase = p->phys_base;
	ba->memSize = p->mem_size;
	ba->topOfKernelData = top;
	ba->Video.v_baseAddr = FB_BASE;
	ba->Video.v_display = 1;
	ba->Video.v_rowBytes = FB_STRIDE;
	ba->Video.v_width = FB_W;
	ba->Video.v_height = FB_H;
	ba->Video.v_depth = 32;
	ba->deviceTreeP = adt_pa - pa_of_va_base;	/* xnu reads it with the MMU on: a VA */
	ba->deviceTreeLength = (uint32_t)p->adt_size;
	for (int i = 0; i < BOOT_LINE_LENGTH; i++)
		ba->CommandLine[i] = p->cmdline[i];
	ba->CommandLine[BOOT_LINE_LENGTH - 1] = 0;
	ba->memSizeActual = p->mem_size;
	con_hex2("BOOTARG", "pa=", ba_pa, "top=", top);

	uintptr_t entry_pa = p->entry_va + pa_of_va_base;
	con_hex("JUMP", entry_pa);
	con_str("XNU", "jumping (fbcon clears screen)");

	/* Everything was written with the MMU and caches off; drop any stale I-cache lines too. */
#ifdef LOADER_HOST_TEST
	extern void loader_host_jump(uint64_t);
	loader_host_jump(ba_pa);
#else
	__asm__ volatile("dsb sy; ic iallu; dsb sy; isb" ::: "memory");
	((xnu_entry_t)entry_pa)(ba_pa);
#endif
	return "xnu returned";
}
