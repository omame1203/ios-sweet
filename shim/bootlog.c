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

void bootlog_init(void)
{
	logbuf = (volatile struct ram_log *)BOARD_LOG_BASE;
	logbuf->sig = 0x43474244;
	logbuf->start = 0;
	logbuf->size = 0;
	__asm__ volatile("dsb sy" ::: "memory");
}

void bootlog_puts(const char *s)
{
	if (!logbuf)
		return;
	const uint32_t capacity = BOARD_LOG_SIZE - sizeof(struct ram_log);
	while (*s) {
		uint32_t pos = logbuf->start;
		logbuf->data[pos] = *s++;
		__asm__ volatile("dsb sy" ::: "memory");
		logbuf->start = pos + 1 == capacity ? 0 : pos + 1;
		if (logbuf->size < capacity)
			logbuf->size++;
	}
	__asm__ volatile("dsb sy" ::: "memory");
}
#else
void bootlog_init(void) {}
void bootlog_puts(const char *s) { (void)s; }
#endif
