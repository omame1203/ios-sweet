#ifndef DIZI_MAC27_SHIM_PROBE_H
#define DIZI_MAC27_SHIM_PROBE_H
#include <stdint.h>

/* Compiled only in experimental dizi macOS27 preflight builds. Never jumps,
 * writes memory, changes PAuth or grants ownership. */
const char *mac27_dizi_probe_dtb(uintptr_t dtb);
#endif
