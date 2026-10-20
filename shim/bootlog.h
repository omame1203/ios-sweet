#pragma once
#include <stdint.h>
void bootlog_init(void);
void bootlog_puts(const char *s);
unsigned bootlog_snapshot(uint8_t *out, unsigned capacity);
