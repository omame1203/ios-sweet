#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "usb_control.h"

static uint8_t log_bytes[1027];
static const uint8_t *fake_data = log_bytes;
static uint32_t fake_total = sizeof(log_bytes), fake_oldest;
static uint32_t rng = 0x10203040;

static uint32_t random32(void)
{
	rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng;
}

static unsigned fake_read(uint32_t offset, uint8_t *out, unsigned capacity)
{
	if (!fake_data || offset < fake_oldest || offset >= fake_total)
		return 0;
	unsigned n = fake_total - offset < capacity ? fake_total - offset : capacity;
	memcpy(out, fake_data + (offset - fake_oldest), n);
	return n;
}

static struct usb_reply call(uint8_t setup[8], uint8_t *out, unsigned capacity,
    unsigned configured)
{
	struct usb_log log = { fake_read, fake_total, fake_oldest };
	return usb_control_reply(setup, out, capacity, &log, configured);
}

static struct usb_reply request(unsigned type, unsigned req, unsigned value,
    unsigned index, unsigned length, unsigned capacity, unsigned configured, uint8_t *result)
{
	uint8_t setup[8] = { type, req, value, value >> 8, index, index >> 8, length, length >> 8 };
	uint8_t guarded[160];
	assert(capacity <= 128);
	memset(guarded, 0xa5, sizeof(guarded));
	struct usb_reply reply = call(setup, guarded + 16, capacity, configured);
	assert(reply.size <= capacity && reply.size <= length);
	for (unsigned i = 0; i < 16; i++) assert(guarded[i] == 0xa5);
	for (unsigned i = 16 + capacity; i < sizeof(guarded); i++) assert(guarded[i] == 0xa5);
	if (reply.action != USB_REPLY)
		for (unsigned i = 0; i < sizeof(guarded); i++) assert(guarded[i] == 0xa5);
	memcpy(result, guarded + 16, reply.size);
	return reply;
}

int main(void)
{
	uint8_t out[128], reconstructed[sizeof(log_bytes)];
	for (unsigned i = 0; i < sizeof(log_bytes); i++) log_bytes[i] = (i * 37) ^ (i >> 8);
	struct usb_reply r = request(0x80, 6, 0x100, 0, 18, 128, 0, out);
	assert(r.action == USB_REPLY && r.size == 18);
	assert(out[0] == 18 && out[1] == 1 && out[7] == 64);
	assert(out[8] == 9 && out[9] == 0x12 && out[10] == 1 && out[11] == 0);
	r = request(0x80, 6, 0x200, 0, 255, 128, 0, out);
	assert(r.size == 18 && out[2] == 18 && out[4] == 1 && out[13] == 0 && out[14] == 0xff);
	r = request(0x80, 6, 0x302, 0x409, 255, 128, 0, out);
	assert(r.size == out[0] && out[1] == 3 && r.size < 64);
	assert(request(0x80, 6, 0x100, 0, 18, 128, 0, out).action == USB_REPLY);
	assert(request(0x80, 6, 0x101, 0, 18, 128, 0, out).action == USB_STALL);
	assert(request(0x80, 6, 0x200, 1, 18, 128, 0, out).action == USB_STALL);
	assert(request(0x80, 6, 0x302, 0x040c, 63, 128, 0, out).action == USB_STALL);
	assert(request(0x80, 6, 0x399, 0x0409, 63, 128, 0, out).action == USB_STALL);
	assert(request(0x80, 6, 0x300, 0, 4, 128, 0, out).size == 4);
	assert(request(0x80, 6, 0x600, 0, 10, 128, 0, out).size == 10);
	assert(request(0x80, 6, 0x700, 0, 18, 128, 0, out).size == 18);
	assert(out[1] == 7);
	assert(request(0x80, 6, 0x100, 0, 18, 0, 0, out).size == 0);
	assert(request(0x80, 6, 0x100, 0, 8, 128, 0, out).size == 8);
	assert(request(0x80, 8, 0, 0, 1, 128, 0, out).size == 1 && out[0] == 0);
	assert(request(0x80, 8, 0, 0, 1, 128, 1, out).size == 1 && out[0] == 1);
	assert(request(0x80, 0, 0, 0, 2, 128, 0, out).size == 2);
	assert(request(0x81, 0, 0, 0, 2, 128, 0, out).action == USB_STALL);
	assert(request(0x81, 0, 0, 0, 2, 128, 1, out).size == 2);
	assert(request(0x82, 0, 0, 0x80, 2, 128, 0, out).size == 2);
	assert(request(0x82, 0, 0, 0x81, 2, 128, 1, out).action == USB_STALL);
	assert(request(0x82, 0, 0, 0x100, 2, 128, 1, out).action == USB_STALL);
	assert(request(0x80, 0, 0, 1, 2, 128, 1, out).action == USB_STALL);
	assert(request(0x81, 10, 0, 0, 1, 128, 0, out).action == USB_STALL);
	assert(request(0x81, 10, 0, 0, 1, 128, 1, out).size == 1 && out[0] == 0);
	assert(request(1, 11, 0, 0, 0, 128, 1, out).action == USB_REPLY);
	assert(request(1, 11, 1, 0, 0, 128, 1, out).action == USB_STALL);

	/* Live log reconstruction, including the offset split across value/index. */
	for (unsigned size = 0; size <= 2 * 63 + 1; size++) {
		unsigned total = 0;
		fake_total = size;
		while (total < size) {
			r = request(0xc0, 0x51, total, total >> 16, 63, 63, 0, out);
			assert(r.action == USB_REPLY && r.size <= 63);
			assert(!memcmp(log_bytes + total, out, r.size));
			total += r.size;
		}
		r = request(0xc0, 0x51, size, 0, 63, 63, 0, out);
		assert(r.action == USB_STALL);
	}
	fake_total = sizeof(log_bytes);
	unsigned offset = 0;
	do {
		r = request(0xc0, 0x51, offset & 0xffff, offset >> 16, 63, 128, 1, out);
		assert(r.action == USB_REPLY && r.size <= 63);
		assert(offset + r.size <= sizeof(reconstructed));
		memcpy(reconstructed + offset, out, r.size); offset += r.size;
	} while (r.size == 63);
	assert(offset == sizeof(log_bytes) && memcmp(reconstructed, log_bytes, offset) == 0);
	assert(request(0xc0, 0x51, 0xffff, 0, 63, 128, 1, out).action == USB_STALL);
	assert(request(0x40, 0x51, 0, 0, 63, 128, 1, out).action == USB_STALL);
	assert(request(0xc0, 0x51, 0, 0, 0, 128, 1, out).action == USB_STALL);

	/* Ring state and host exit request. */
	r = request(0xc0, 0x52, 0, 0, 16, 128, 0, out);
	assert(r.action == USB_REPLY && r.size == 16);
	uint32_t words[4];
	memcpy(words, out, sizeof(words));
	assert(words[0] == 0x474c4f50u && words[1] == fake_total && words[2] == 0);
	r = request(0xc0, 0x52, 0, 0, 12, 128, 0, out);
	assert(r.action == USB_REPLY && r.size == 12);
	assert(request(0xc0, 0x52, 0, 0, 16, 8, 0, out).action == USB_STALL);
	assert(request(0x00, 0x53, 0, 0, 0, 128, 1, out).action == USB_DONE);
	assert(request(0x00, 0x53, 0, 0, 1, 128, 1, out).action == USB_STALL);

	/* The reader clamps to the surviving part after the ring wrapped. */
	fake_oldest = 400;
	r = request(0xc0, 0x51, 300, 0, 63, 63, 0, out);
	assert(r.action == USB_STALL);
	r = request(0xc0, 0x51, 400, 0, 63, 63, 0, out);
	assert(r.action == USB_REPLY && !memcmp(out, log_bytes, r.size));
	fake_oldest = 0;

	fake_data = NULL; fake_total = 1027;
	assert(request(0xc0, 0x51, 0, 0, 63, 128, 0, out).action == USB_STALL);
	assert(request(0xc0, 0x52, 0, 0, 16, 128, 0, out).action == USB_REPLY);
	fake_data = log_bytes;

	assert(request(0, 5, 128, 0, 0, 128, 0, out).action == USB_STALL);
	assert(request(0, 5, 127, 0, 0, 128, 0, out).value == 127);
	assert(request(0, 9, 2, 0, 0, 128, 0, out).action == USB_STALL);
	assert(request(0, 9, 1, 0, 0, 128, 0, out).action == USB_CONFIG);
	for (unsigned i = 0; i < 10000; i++)
		(void)request(random32() & 255, random32() & 255, random32() & 65535,
		    random32() & 65535, random32() & 65535, random32() % 129, i & 1, out);
	puts("PASS: descriptors, live log reads, ring state, exit request and 10000 guarded requests");
	return 0;
}
