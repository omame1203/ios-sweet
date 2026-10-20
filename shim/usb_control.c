/* Lab-only diagnostics device, pid.codes test VID/PID 1209:0001.
 * No storage interface, OUT payloads or device-memory access requests. */
#include "usb_control.h"

static const uint8_t device_desc[] = {
	18, 1, 0, 2, 0, 0, 0, 64, 0x09, 0x12, 0x01, 0,
	0, 1, 1, 2, 3, 1,
};
static const uint8_t config_desc[] = {
	9, 2, 18, 0, 1, 1, 0, 0x80, 50,
	9, 4, 0, 0, 0, 0xff, 0, 0, 0,
};
static const uint8_t qualifier_desc[] = { 10, 6, 0, 2, 0, 0, 0, 64, 1, 0 };

static unsigned min(unsigned a, unsigned b) { return a < b ? a : b; }

struct usb_reply usb_control_reply(const uint8_t setup[8], uint8_t *out,
    unsigned capacity, const uint8_t *log, unsigned log_size, unsigned configured)
{
	unsigned type = setup[0], req = setup[1];
	unsigned value = setup[2] | ((unsigned)setup[3] << 8);
	unsigned index = setup[4] | ((unsigned)setup[5] << 8);
	unsigned length = setup[6] | ((unsigned)setup[7] << 8);
	struct usb_reply reply = { USB_STALL, 0, 0 };
	uint8_t desc[64];
	const uint8_t *source = desc;
	unsigned n = 0;
	if (type == 0xc0 && req == 0x51 && index == 0 && length > 0) {
		/* 63-byte chunks avoid an extra terminating ZLP when the snapshot's
		 * final data length happens to be an exact multiple of EP0's 64. */
		if (log_size && !log) return reply;
		n = value < log_size ? min(63, log_size - value) : 0;
		if (n) source = log + value;
	} else if (type == 0x80 && req == 6) {
		/* Device, configuration and qualifier descriptors have index zero;
		 * strings use English (0x0409) once the language is selected. */
		if ((value >> 8) == 3) {
			if (index != 0 && index != 0x0409) return reply;
		} else if ((value & 255) != 0 || index != 0) {
			return reply;
		}
		switch (value >> 8) {
		case 1: source = device_desc; n = sizeof(device_desc); break;
		case 2: case 7:
			n = sizeof(config_desc);
			for (unsigned i = 0; i < n; i++) desc[i] = config_desc[i];
			desc[1] = value >> 8;
			break;
		case 6: source = qualifier_desc; n = sizeof(qualifier_desc); break;
		case 3: {
			const char *s;
			switch (value & 255) {
			case 0: desc[0] = 4; desc[1] = 3; desc[2] = 9; desc[3] = 4; n = 4; s = ""; break;
			case 1: s = "ios-pocopad"; break;
			case 2: s = "Dizi boot diagnostics"; break;
			case 3: s = "DIAG-0001"; break;
			default: return reply;
			}
			if (n) break;
			n = 2;
			while (*s && n < 62) { desc[n++] = (uint8_t)*s++; desc[n++] = 0; }
			desc[0] = n; desc[1] = 3;
			break;
		}
		default: return reply;
		}
	} else if (type == 0 && req == 5 && value <= 127 && index == 0 && length == 0) {
		reply.action = USB_ADDRESS; reply.value = value; return reply;
	} else if (type == 0 && req == 9 && value <= 1 && index == 0 && length == 0) {
		reply.action = USB_CONFIG; reply.value = value; return reply;
	} else if (type == 0x80 && req == 8 && value == 0 && index == 0 && length == 1) {
		desc[0] = configured; n = 1;
	} else if (req == 0 && value == 0 && length == 2 &&
	    ((type == 0x80 && index == 0) ||
	     (type == 0x81 && index == 0 && configured) ||
	     (type == 0x82 && (index == 0 || index == 0x80)))) {
		desc[0] = desc[1] = 0; n = 2;
	} else if (type == 0x81 && req == 10 && index == 0 && value == 0 && length == 1 && configured) {
		desc[0] = 0; n = 1;
	} else if (type == 1 && req == 11 && index == 0 && value == 0 && length == 0 && configured) {
		n = 0;
	} else {
		return reply;
	}
	n = min(n, min(length, capacity));
	for (unsigned i = 0; i < n; i++) out[i] = source[i];
	reply.action = USB_REPLY; reply.size = n;
	return reply;
}
