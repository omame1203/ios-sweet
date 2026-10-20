/* Dizi bare-metal EP0 diagnostic transport. Adapted from ios-sweet's
 * bsd/dev/sweet_usb.c, with dizi clock guards and a read-only log request.
 * Runs with MMU/D-cache OFF: DMA buffers are physical Device memory.
 * PHY, regulators, clocks and SMMU configuration remain as ABL left them.
 */
#include <stdint.h>
#include "board.h"
#include "console.h"
#include "bootlog.h"
#include "usb_control.h"
#include "usb_diag.h"

#if defined(BOARD_DIZI) && defined(__aarch64__)
#define GCTL 0xc110
#define GSNPSID 0xc120
#define EVADRLO 0xc400
#define EVADRHI 0xc404
#define EVSIZE 0xc408
#define EVCOUNT 0xc40c
#define DCFG 0xc700
#define DCTL 0xc704
#define DEVTEN 0xc708
#define DSTS 0xc70c
#define DALEPENA 0xc720
#define CMDPAR2(ep) (0xc800 + 16 * (ep))
#define CMDPAR1(ep) (0xc804 + 16 * (ep))
#define CMDPAR0(ep) (0xc808 + 16 * (ep))
#define CMD(ep) (0xc80c + 16 * (ep))
#define CMD_ACTIVE (1u << 10)
#define RUN_STOP (1u << 31)
#define SOFT_RESET (1u << 30)
#define CONTROL_SETUP (2u << 4)
#define CONTROL_STATUS2 (3u << 4)
#define CONTROL_STATUS3 (4u << 4)
#define CONTROL_DATA (5u << 4)
#define DMA_SIZE 0x2000
#define EVENT_SIZE 0x1000
#define TRB_OUT 0x1000
#define TRB_IN 0x1040
#define SETUP_BUF 0x1080
#define DATA_BUF 0x1100

static uint32_t dma[DMA_SIZE / 4] __attribute__((aligned(4096)));
static uint8_t snapshot[16384];
static unsigned snapshot_size, event_pos, configured, status_ep;
static int failed;
static enum { SETUP, DATA, WAIT_STATUS2, WAIT_STATUS3, STATUS } state;

static uint32_t read32(uintptr_t p)
{
	uint32_t v = *(volatile uint32_t *)p;
	__asm__ volatile("dmb oshld" ::: "memory");
	return v;
}
static void write32(uintptr_t p, uint32_t v)
{
	*(volatile uint32_t *)p = v;
	__asm__ volatile("dsb sy" ::: "memory");
}
static uint32_t rd(unsigned off) { return read32(BOARD_USB_DWC + off); }
static void wr(unsigned off, uint32_t v) { write32(BOARD_USB_DWC + off, v); }
static uint64_t ticks(void)
{
	uint64_t value;
	__asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(value));
	return value;
}
static uint64_t frequency(void)
{
	uint64_t value;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
	return value;
}
static void delay_us(unsigned us)
{
	uint64_t end = ticks() + frequency() / 1000000 * us;
	while (ticks() < end) ;
}
static int epcmd(unsigned ep, unsigned cmd, unsigned p0, unsigned p1, unsigned p2)
{
	wr(CMDPAR0(ep), p0); wr(CMDPAR1(ep), p1); wr(CMDPAR2(ep), p2);
	wr(CMD(ep), cmd | CMD_ACTIVE);
	for (unsigned i = 0; i < 1000; i++) {
		uint32_t v = rd(CMD(ep));
		if (!(v & CMD_ACTIVE)) return (v >> 12) & 15 ? -1 : 0;
		delay_us(1);
	}
	return -1;
}
static void transfer(unsigned ep, unsigned buf, unsigned n, unsigned control)
{
	uintptr_t trb_pa = (uintptr_t)dma + (ep ? TRB_IN : TRB_OUT);
	volatile uint32_t *trb = (volatile uint32_t *)trb_pa;
	uint64_t data_pa = (uintptr_t)dma + buf;
	trb[0] = data_pa; trb[1] = data_pa >> 32; trb[2] = n;
	trb[3] = control | 1u | 2u | (1u << 10) | (1u << 11);
	__asm__ volatile("dsb sy" ::: "memory");
	if (epcmd(ep, 6, trb_pa >> 32, trb_pa, 0)) failed = 1;
}
static void arm_setup(void)
{
	state = SETUP;
	transfer(0, SETUP_BUF, 8, CONTROL_SETUP);
}
static void setup_request(void)
{
	const uint8_t *setup = (const uint8_t *)dma + SETUP_BUF;
	uint8_t *out = (uint8_t *)dma + DATA_BUF;
	struct usb_reply reply = usb_control_reply(setup, out, 128,
	    snapshot, snapshot_size, configured);
	if (reply.action == USB_STALL) {
		if (epcmd(0, 4, 0, 0, 0)) failed = 1;
		arm_setup();
		return;
	}
	if (reply.action == USB_ADDRESS)
		wr(DCFG, (rd(DCFG) & ~(127u << 3)) | (reply.value << 3));
	if (reply.action == USB_CONFIG) configured = reply.value;
	if (!(setup[6] | setup[7])) { state = WAIT_STATUS2; return; }
	state = DATA;
	transfer(1, DATA_BUF, reply.size, CONTROL_DATA);
}
static void event(uint32_t value)
{
	if (value & 1) {
		unsigned type = (value >> 8) & 15;
		if (type == 1) { /* USB reset */
			configured = 0; status_ep = 0;
			wr(DCFG, rd(DCFG) & ~(127u << 3)); arm_setup();
		} else if (type == 2) { /* connect done: high/full-speed maxpacket 64 */
			if (epcmd(0, 1, (64u << 3) | (2u << 30), (1u << 8) | (1u << 10), 0) ||
			    epcmd(1, 1, (64u << 3) | (2u << 30), (1u << 8) | (1u << 10) | (1u << 25), 0))
				failed = 1;
		}
		return;
	}
	unsigned ep = (value >> 1) & 31, type = (value >> 6) & 15, status = (value >> 12) & 15;
	if (ep > 1) return;
	if (type == 1) {
		if (state == SETUP && ep == 0) setup_request();
		else if (state == DATA && ep == 1) state = WAIT_STATUS3;
		else if (state == STATUS && ep == status_ep) arm_setup();
	} else if (type == 3 && status == 2 && (state == WAIT_STATUS2 || state == WAIT_STATUS3)) {
		/* No-data requests acknowledge on IN; IN-data requests on OUT. */
		if (ep != (state == WAIT_STATUS2 ? 1u : 0u)) return;
		unsigned control = state == WAIT_STATUS2 ? CONTROL_STATUS2 : CONTROL_STATUS3;
		status_ep = ep; state = STATUS;
		transfer(ep, DATA_BUF, 0, control);
	}
}

void usb_diag_run(unsigned milliseconds)
{
	uint64_t sctlr;
	__asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
	if (sctlr & 5) { con_str("USB", "MMU/cache still on; skipped"); return; }
	uint32_t power = read32(BOARD_USB_GCC + BOARD_USB_GDSCR);
	uint32_t master = read32(BOARD_USB_GCC + BOARD_USB_MASTER_CBCR);
	uint32_t iface = read32(BOARD_USB_GCC + BOARD_USB_IFACE_CBCR);
	uint32_t aggre = read32(BOARD_USB_GCC + BOARD_USB_AGGRE_CBCR);
	uint32_t utmi = read32(BOARD_USB_GCC + BOARD_USB_UTMI_CBCR);
	uint32_t sleep = read32(BOARD_USB_GCC + BOARD_USB_SLEEP_CBCR);
	con_hex2("USB GCC", "gdsc=", power, "master=", master);
	con_hex2("USB clocks", "iface=", iface, "aggre=", aggre);
	con_hex2("USB clocks", "utmi=", utmi, "sleep=", sleep);
	/* Never touch a gated USB block or enable guessed clocks/regulators. */
	if (!(power & (1u << 31)) ||
	    ((master | iface | aggre | utmi | sleep) & (1u << 31))) {
		con_str("USB", "power/clock off; skipped"); return;
	}
	uint32_t id = rd(GSNPSID);
	con_hex2("USB DWC", "id=", id, "gctl=", rd(GCTL));
	if ((id >> 16) != 0x5533 || ((rd(GCTL) >> 12) & 3) != 2) {
		con_str("USB", "unsupported core/mode; skipped"); return;
	}
	for (unsigned i = 0; i < DMA_SIZE / 4; i++) dma[i] = 0;
	wr(DCTL, SOFT_RESET);
	for (unsigned i = 0; i < 500 && (rd(DCTL) & SOFT_RESET); i++) delay_us(1000);
	if (rd(DCTL) & SOFT_RESET) { con_str("USB", "soft reset timeout"); return; }
	wr(EVADRLO, (uintptr_t)dma); wr(EVADRHI, (uint64_t)(uintptr_t)dma >> 32);
	wr(EVSIZE, (1u << 31) | EVENT_SIZE); wr(EVCOUNT, rd(EVCOUNT) & 65535);
	wr(DCFG, rd(DCFG) & ~(7u | (127u << 3))); wr(DEVTEN, 7);
	if (epcmd(0, 9, 0, 0, 0) ||
	    epcmd(0, 1, 512u << 3, (1u << 8) | (1u << 10), 0) || epcmd(0, 2, 1, 0, 0) ||
	    epcmd(1, 1, 512u << 3, (1u << 8) | (1u << 10) | (1u << 25), 0) || epcmd(1, 2, 1, 0, 0)) {
		con_str("USB", "EP0 setup failed"); return;
	}
	wr(DALEPENA, 3); event_pos = configured = status_ep = 0; failed = 0; arm_setup();
	uintptr_t hs = BOARD_USB_QSCRATCH + 0x10, ss = BOARD_USB_QSCRATCH + 0x30;
	write32(hs, read32(hs) | (1u << 20) | (1u << 28));
	write32(ss, read32(ss) | (1u << 24));
	con_hex("USB DMA", (uintptr_t)dma);
	con_str("USB", "EP0 diagnostic transport prepared; read-only snapshot");
	snapshot_size = bootlog_snapshot(snapshot, sizeof(snapshot));
	wr(DCTL, rd(DCTL) | RUN_STOP);
	uint64_t end = ticks() + frequency() * milliseconds / 1000;
	while (!failed && ticks() < end) {
		unsigned count = rd(EVCOUNT) & 65535;
		if (count > EVENT_SIZE || (count & 3)) { failed = 1; break; }
		for (unsigned done = 0; done < count; done += 4) {
			__asm__ volatile("dmb oshld" ::: "memory");
			uint32_t value = *(volatile uint32_t *)((uintptr_t)dma + event_pos);
			event_pos = (event_pos + 4) % EVENT_SIZE; event(value);
		}
		if (count) wr(EVCOUNT, count);
	}
	wr(DCTL, rd(DCTL) & ~RUN_STOP);
	con_hex2("USB end", "failed=", failed, "configured=", configured);
}
#else
void usb_diag_run(unsigned milliseconds) { (void)milliseconds; }
#endif
