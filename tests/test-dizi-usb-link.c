/* Offline policy tests for xnu/patches/0106-dizi-usb-io-networking.patch.
 * The Python harness extracts the exact header from the patch before build.
 */
#include <assert.h>
#include <stdio.h>
#include "dizi_usb_link.h"
int main(void)
{
    struct dizi_usb_link link = {0};
    assert(!dizi_usb_link_ready(&link));
    link.enabled = true;
    assert(!dizi_usb_link_ready(&link));
    link.attached = true;
    assert(!dizi_usb_link_ready(&link));
    link.connected = true;
    assert(!dizi_usb_link_ready(&link));
    link.configured = true;
    assert(!dizi_usb_link_ready(&link));
    link.alt = 1;
    assert(dizi_usb_link_ready(&link));
    link.alt = 0;
    assert(!dizi_usb_link_ready(&link));
    link.alt = 1;
    assert(dizi_usb_link_ready(&link));
    link.configured = false;
    assert(!dizi_usb_link_ready(&link));
    link.configured = true;
    assert(dizi_usb_link_ready(&link));
    dizi_usb_link_reset(&link);
    assert(!dizi_usb_link_ready(&link));
    assert(link.enabled && link.attached);
    assert(!link.connected && !link.configured && link.alt == 0);
    link.connected = link.configured = true;
    link.alt = 1;
    assert(dizi_usb_link_ready(&link));
    link.attached = false;
    assert(!dizi_usb_link_ready(&link));
    link.attached = true;
    link.enabled = false;
    assert(!dizi_usb_link_ready(&link));
    puts("PASS: dizi USB CDC-ECM link gate / alt 0 / reset / disconnect / missing ifnet / disabled");
    return 0;
}
