/* Linux persistent_ram_buffer ABI, android12-5.10/fs/pstore/ram_core.c.
 * Only the console zone is used. No partition or calibration writes. */
#include <stdint.h>
#include "board.h"
#include "bootlog.h"

#if defined(BOARD_LOG_BASE) && defined(__aarch64__)
struct ram_log {
	uint32_t sig, start, size;
	char data[];
};
static volatile struct ram_log *logbuf;
static uint32_t total;

static uint32_t ring_size(void)
{
	return BOARD_LOG_SIZE - sizeof(struct ram_log);
}

void bootlog_init(void)
{
	logbuf = (volatile struct ram_log *)BOARD_LOG_BASE;
	logbuf->sig = 0x43474244;
	logbuf->start = 0;
	logbuf->size = 0;
	total = 0;
	__asm__ volatile("dsb sy" ::: "memory");
}

void bootlog_puts(const char *s)
{
	if (!logbuf)
		return;
	const uint32_t capacity = ring_size();
	while (*s) {
		uint32_t pos = logbuf->start;
		logbuf->data[pos] = *s++;
		__asm__ volatile("dsb sy" ::: "memory");
		logbuf->start = pos + 1 == capacity ? 0 : pos + 1;
		if (logbuf->size < capacity)
			logbuf->size++;
		total++;
	}
	__asm__ volatile("dsb sy" ::: "memory");
}

uint32_t bootlog_total(void)
{
	return total;
}

void bootlog_sync(void)
{
	uint64_t ctr;
	__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
	uint64_t line = 4UL << ((ctr >> 16) & 0xf);
	for (uintptr_t p = BOARD_LOG_BASE; p < BOARD_LOG_BASE + BOARD_LOG_SIZE; p += line)
		__asm__ volatile("dc cvac, %0" : : "r"(p) : "memory");
	__asm__ volatile("dsb sy" ::: "memory");
}

uint32_t bootlog_oldest(void)
{
	uint32_t size = logbuf ? logbuf->size : 0;
	return total - size;
}

unsigned bootlog_read(uint32_t offset, uint8_t *out, unsigned capacity)
{
	if (!logbuf || offset >= total)
		return 0;
	uint32_t oldest = bootlog_oldest();
	if (offset < oldest)
		return 0;
	uint32_t ring = ring_size();
	uint32_t size = logbuf->size;
	uint32_t start = (logbuf->start + ring - size) % ring;	/* oldest byte */
	uint32_t index = (start + (offset - oldest)) % ring;
	unsigned n = total - offset < capacity ? total - offset : capacity;
	for (unsigned i = 0; i < n; i++)
		out[i] = logbuf->data[(index + i) % ring];
	return n;
}
#else
void bootlog_init(void) {}
void bootlog_puts(const char *s) { (void)s; }
void bootlog_sync(void) {}
uint32_t bootlog_total(void) { return 0; }
uint32_t bootlog_oldest(void) { return 0; }
unsigned bootlog_read(uint32_t offset, uint8_t *out, unsigned capacity)
{ (void)offset; (void)out; (void)capacity; return 0; }
#endif
