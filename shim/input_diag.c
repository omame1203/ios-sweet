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
#ifdef DIZI_INPUT_SPI_CLOCK
	__asm__ volatile("str %w0, [%1]; dsb osh" : : "r"(saved_vote), "r"(vote_reg) : "memory");
	con_hex("SPI restored", rd(vote_reg));
#endif
}
#endif
