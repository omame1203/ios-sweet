#pragma once

/* 0 when the diagnostic completed; nonzero identifies the early exit so the
 * reset delay can report it without a screen. */
int usb_diag_run(unsigned milliseconds);
