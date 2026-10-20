#pragma once
#include <stdint.h>

void bootlog_init(void);
void bootlog_puts(const char *s);
/* Push the ring out of a cacheable mapping before changing the MMU state. */
void bootlog_sync(void);
/* Absolute byte counters for the current boot, oldest first. */
uint32_t bootlog_total(void);
uint32_t bootlog_oldest(void);
/* Copy log bytes starting at absolute offset; returns bytes copied. */
unsigned bootlog_read(uint32_t offset, uint8_t *out, unsigned capacity);
