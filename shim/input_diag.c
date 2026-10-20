/* Dizi input inventory. No PMIC configuration, GPIO or touch-device writes.
 * The sole SPMI write issues an EXT_READL on the read-only observer path.
 * Register layout: pinned MiCode ruan-u-oss spmi-pmic-arb.c/gcc-parrot.c.
 */
#include <stdint.h>
#include "console.h"

#if defined(BOARD_DIZI) && defined(DIZI_INPUT_DIAG)
static uint32_t rd(uintptr_t a)
{
	uint32_t v;
	__asm__ volatile("ldr %w0, [%1]; dmb oshld" : "=r"(v) : "r"(a) : "memory");
	return v;
}

static int pmic_read(unsigned apid, unsigned addr)
{
	uintptr_t channel = 0xc440000UL + 0x20u * apid;
	uint32_t cmd = (1u << 27) | ((addr & 255u) << 4);
	__asm__ volatile("dmb oshst; str %w0, [%1]; dsb osh" : : "r"(cmd), "r"(channel) : "memory");
	for (unsigned i = 0; i < 100000; i++) {
		uint32_t status = rd(channel + 8);
		if (status & 1) return status & 14 ? -1 : (int)(rd(channel + 0x18) & 255);
	}
	return -1;
}

void dizi_input_diag(void)
{
	con_str("INPUT", "SPMI v7 inventory");
	uint32_t ver = rd(0xc400000), count = rd(0xc400004) & 0x7ff;
	con_hex2("PMIC arb", "ver=", ver, "count=", count);
	if (ver >= 0x70000000 && ver < 0x80000000 && count && count <= 1024) {
		for (unsigned i = 0; i < count; i++) {
			uint32_t map = rd(0xc402000UL + 4 * i), ppid = (map >> 8) & 0xfff;
			if (!map || (ppid != 0x013 && ppid != 0x188)) continue;
			unsigned owner = rd(0xc42d000UL + 4 * i) & 7;
			con_hex2("PMIC map", "ppid=", ppid, "apid=", i);
			con_hex2("PMIC data", "owner=", owner, "status=", (uint32_t)pmic_read(i, (ppid << 8) | 0x10));
			if (ppid == 0x188) {
				con_hex2("GPIO1", "mode=", (uint32_t)pmic_read(i, 0x8840), "enable=", (uint32_t)pmic_read(i, 0x8846));
				con_hex("GPIO1 type", (uint32_t)pmic_read(i, 0x8805));
			}
		}
	}
	con_str("INPUT", "TLMM and SPI clock inventory");
	for (unsigned i = 0; i < 5; i++) {
		unsigned pin = i == 4 ? 54 : 10 + i;
		uintptr_t a = 0xf100000UL + pin * 0x1000;
		con_hex2("TLMM", "pin=", pin, "cfg=", rd(a));
		con_hex("GPIO IO", rd(a + 4));
	}
	uint32_t se = rd(0x1283a8), m = rd(0x128004), s = rd(0x128008);
	con_hex2("SPI clocks", "se=", se, "m-ahb=", m);
	con_hex2("SPI source", "s-ahb=", s, "vote=", rd(0x162008));
	con_hex2("SPI RCG", "cmd=", rd(0x1283b0), "cfg=", rd(0x1283b4));
#ifdef DIZI_INPUT_SPI_CLOCK
	/* Vote only this SE and its two wrapper AHB clocks. Restore on return.
	 * No source/divider, pin mux, sequencer RAM or touch-device mutation. */
	uintptr_t vote_reg = 0x162008;
	uint32_t saved_vote = rd(vote_reg), vote = saved_vote | (1u << 25) | (3u << 20);
	__asm__ volatile("str %w0, [%1]; dsb osh" : : "r"(vote), "r"(vote_reg) : "memory");
	for (unsigned i = 0; i < 100000; i++) {
		se = rd(0x1283a8); m = rd(0x128004); s = rd(0x128008);
		if (!((se | m | s) & 0x80000000u)) break;
	}
	con_hex2("SPI voted", "se=", se, "m-ahb=", m);
	con_hex("SPI s-ahb", s);
#endif
	if ((se | m | s) & 0x80000000u) {
		con_str("SPI", "clock off; SE registers withheld");
	} else {
		con_hex2("SPI SE", "status=", rd(0xa8c040), "fw=", rd(0xa8c068));
		con_hex2("SPI FIFO", "tx=", rd(0xa8ce24), "rx=", rd(0xa8ce28));
		con_hex2("SPI mode", "dma=", rd(0xa8c258), "fifo-disable=", rd(0xa8c064));
	}
#ifdef DIZI_INPUT_GPI
	/* Live FDT: gpi1 base a00000, ee-offset10000 SUBTRACTED by gpi.c,
	 * dynamic GPII mask3e. No channel/event commands or DMA submitted. */
	con_str("GPI", "reading Android-owned context inventory");
	/* This is an independent optional first-access experiment. A trap or
	 * permission fault should be correlated with the exact single address;
	 * no device-visible DMA/command is issued. */
#ifdef DIZI_INPUT_GPI_SINGLE
	/* SPI SE9's FDT DMA specifier 0x02 selects static GPII0 (gpi.c). */
	con_str("GPI", "single read i0 TX context0 at A10000");
	con_hex("GPI TX0", rd(0xa10000UL));
#elif defined(DIZI_INPUT_GPI_TOUCH_STATE)
	/* Probe06 established that GPII0 TX context0 is readable and zero.
	 * Extend only to peer channel/event contexts, without commands or DMA. */
	con_str("GPI", "read static i0 TX context0 A10000");
	con_hex("GPI TX0", rd(0xa10000UL));
	con_str("GPI", "read static i0 RX context0 A10080");
	con_hex("GPI RX0", rd(0xa10080UL));
	con_str("GPI", "read static i0 event context0 A11000");
	con_hex("GPI EV0", rd(0xa11000UL));
#ifdef DIZI_INPUT_GPI_TOUCH_DETAIL
	/* Only after probe07 established all three context0 registers readable. */
	con_str("GPI", "read static i0 TX ring length A10004");
	con_hex("GPI TX len", rd(0xa10004UL));
	con_str("GPI", "read static i0 event ring length A11004");
	con_hex("GPI EV len", rd(0xa11004UL));
	con_str("GPI", "read static i0 TX scratch0 A10060");
	con_hex("GPI TX scratch", rd(0xa10060UL));
#endif
#else
	for (unsigned i = 1; i <= 5; i++) {
		uintptr_t base = 0x9f0000UL + 0x4000u * i;
		con_hex2("GPI instance", "id=", i, "tx=", rd(base + 0x20000));
		con_hex2("GPI channels", "rx=", rd(base + 0x20080), "ev=", rd(base + 0x21000));
		con_hex2("GPI scratch", "tx=", rd(base + 0x20060), "rx=", rd(base + 0x200e0));
		con_hex2("GPI status", "irq=", rd(base + 0x23080), "error=", rd(base + 0x23200));
	}
#endif
#endif
#ifdef DIZI_INPUT_SMMU_ID0
	/* Architectural ID0 is read-only. Apps SMMU at 0x15000000 is confirmed
	 * by live FDT; this separate EL1/Gunyah MMIO permission is unproven.
	 * A data abort may be surfaced on the diagnostic framebuffer. */
	con_str("SMMU", "single read apps_smmu ID0 PA15000020");
	con_hex("SMMU ID0", rd(0x15000020UL));
#ifdef DIZI_INPUT_SMMU_ID1
	/* Only enable following successful physical probe09 ID0 read. */
	con_str("SMMU", "read apps_smmu ID1 PA15000024");
	con_hex("SMMU ID1", rd(0x15000024UL));
#ifdef DIZI_INPUT_SMMU_SMR0
	/* The first mapping slot read is staged independently of a full scan;
	 * SMMU ID0/ID1 have been observed accessible, SMR pages have not. */
	con_str("SMMU", "single read SMR[0] PA15000800");
	con_hex("SMMU SMR0", rd(0x15000800UL));
#ifdef DIZI_INPUT_SMMU_SCAN
	/* ID0=4c017e7e => EXIDS=0, NUMSMRG=126; FDT overrides to 120.
	 * For each of the two measured DMA stream IDs, match a valid SMR's
	 * ID+MASK, then read only the corresponding S2CR. No other MMIO writes. */
	unsigned valid = 0, hit_gpi = 0, hit_qup = 0;
	for (unsigned i = 0; i < 120; ++i) {
		if ((i & 15u) == 0u) con_hex("SMMU scan slot", i);
		uint32_t smr = rd(0x15000800UL + 4u * i);
		if (!(smr & 0x80000000u)) continue;
		++valid;
		uint32_t mask = (smr >> 16) & 0x7fffu;
		uint32_t id = smr & 0x7fffu;
		unsigned gpi = (((0x416u ^ id) & ~mask) & 0x7fffu) == 0;
		unsigned qup = (((0x403u ^ id) & ~mask) & 0x7fffu) == 0;
		if (!gpi && !qup) continue;
		hit_gpi += gpi;
		hit_qup += qup;
		con_hex2("SMMU match", "slot=", i, "smr=", smr);
		con_hex2("SMMU stream", "gpi=", gpi, "qup=", qup);
		con_hex2("SMMU S2CR", "slot=", i, "s2cr=", rd(0x15000c00UL + 4u * i));
	}
	con_hex2("SMMU scan", "valid=", valid, "gpi=", hit_gpi);
	con_hex("SMMU qup matches", hit_qup);
#endif
#endif
#ifdef DIZI_INPUT_SMMU_SCR0
	/* Read-only global control. Unlike IDx this register may be emulated
	 * by Gunyah. No control bits are changed and no DMA is submitted. */
	con_str("SMMU", "single read global sCR0 PA15000000");
	con_hex("SMMU sCR0", rd(0x15000000UL));
#endif
#endif
#endif
#ifdef DIZI_INPUT_SPI_CLOCK
	__asm__ volatile("str %w0, [%1]; dsb osh" : : "r"(saved_vote), "r"(vote_reg) : "memory");
	con_hex("SPI restored", rd(vote_reg));
#endif
}
#endif
