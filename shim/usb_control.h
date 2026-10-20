#pragma once
#include <stdint.h>

enum usb_action { USB_REPLY, USB_ADDRESS, USB_CONFIG, USB_STALL, USB_DONE };
struct usb_reply { enum usb_action action; unsigned size; unsigned value; };

/* Live boot-log ring access. read() returns 0 outside [oldest, total). */
struct usb_log {
	unsigned (*read)(uint32_t offset, uint8_t *out, unsigned capacity);
	uint32_t total, oldest;
};

/* Pure control-request decoding, shared by the actual shim and host tests. */
struct usb_reply usb_control_reply(const uint8_t setup[8], uint8_t *out,
    unsigned capacity, const struct usb_log *log, unsigned configured);
