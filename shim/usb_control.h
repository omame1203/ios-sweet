#pragma once
#include <stdint.h>

enum usb_action { USB_REPLY, USB_ADDRESS, USB_CONFIG, USB_STALL };
struct usb_reply { enum usb_action action; unsigned size; unsigned value; };
/* Pure control-request decoding, shared by the actual shim and host tests. */
struct usb_reply usb_control_reply(const uint8_t setup[8], uint8_t *out,
    unsigned capacity, const uint8_t *log, unsigned log_size, unsigned configured);
