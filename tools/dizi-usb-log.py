#!/usr/bin/env python3
"""Read the temporary dizi shim's boot log through USB EP0.

Start this on the host BEFORE `fastboot boot`. Uses libusb through ctypes;
no Python packages, kernel driver detachment, device writes or disk access.
The firmware implements a vendor-class lab device (1209:0001), not an iPad.

Protocol: vendor IN 0x52 returns {magic 'POLG', total, oldest, 0}; vendor IN
0x51 (wValue=offset low16, wIndex=high16) returns up to 63 live log bytes;
vendor OUT 0x53 asks the shim to stop waiting and reboot Android.
"""
import argparse
import ctypes as ct
import ctypes.util
from pathlib import Path
import struct
import sys
import time

VID, PID = 0x1209, 0x0001
POLG = 0x474C4F50


class DeviceDescriptor(ct.Structure):
    _fields_ = [
        ('bLength', ct.c_uint8), ('bDescriptorType', ct.c_uint8),
        ('bcdUSB', ct.c_uint16), ('bDeviceClass', ct.c_uint8),
        ('bDeviceSubClass', ct.c_uint8), ('bDeviceProtocol', ct.c_uint8),
        ('bMaxPacketSize0', ct.c_uint8), ('idVendor', ct.c_uint16),
        ('idProduct', ct.c_uint16), ('bcdDevice', ct.c_uint16),
        ('iManufacturer', ct.c_uint8), ('iProduct', ct.c_uint8),
        ('iSerialNumber', ct.c_uint8), ('bNumConfigurations', ct.c_uint8),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--wait', type=float, default=130)
    ap.add_argument('--settle', type=float, default=0.6,
                    help='idle time before asking the shim to reboot')
    args = ap.parse_args()
    if args.out.exists():
        ap.error('Output already exists; choose a fresh log filename')
    name = ctypes.util.find_library('usb-1.0')
    if not name:
        raise SystemExit('libusb-1.0 is not installed')
    lib = ct.CDLL(name)
    lib.libusb_init.argtypes = [ct.POINTER(ct.c_void_p)]
    lib.libusb_init.restype = ct.c_int
    lib.libusb_exit.argtypes = [ct.c_void_p]
    lib.libusb_open_device_with_vid_pid.argtypes = [ct.c_void_p, ct.c_uint16, ct.c_uint16]
    lib.libusb_open_device_with_vid_pid.restype = ct.c_void_p
    lib.libusb_get_device_list.argtypes = [ct.c_void_p, ct.POINTER(ct.POINTER(ct.c_void_p))]
    lib.libusb_get_device_list.restype = ct.c_ssize_t
    lib.libusb_get_device_descriptor.argtypes = [ct.c_void_p, ct.c_void_p]
    lib.libusb_get_device_descriptor.restype = ct.c_int
    lib.libusb_free_device_list.argtypes = [ct.POINTER(ct.c_void_p), ct.c_int]
    lib.libusb_close.argtypes = [ct.c_void_p]
    lib.libusb_control_transfer.argtypes = [ct.c_void_p, ct.c_uint8, ct.c_uint8,
        ct.c_uint16, ct.c_uint16, ct.POINTER(ct.c_ubyte), ct.c_uint16, ct.c_uint]
    lib.libusb_control_transfer.restype = ct.c_int
    context = ct.c_void_p()
    status = lib.libusb_init(ct.byref(context))
    if status:
        raise SystemExit(f'libusb_init failed: {status}')

    def control(handle, kind, request, value=0, index=0, length=0, timeout=1500):
        buffer = (ct.c_ubyte * max(length, 1))()
        n = lib.libusb_control_transfer(handle, kind, request, value, index,
                                        buffer, length, timeout)
        if n < 0:
            raise RuntimeError(f'USB control request 0x{request:02x} failed: '
                               f'libusb status {n}')
        return bytes(buffer[:n])

    def matching_device_present():
        devices = ct.POINTER(ct.c_void_p)()
        count = lib.libusb_get_device_list(context, ct.byref(devices))
        if count < 0:
            return False
        found = False
        try:
            for i in range(count):
                desc = DeviceDescriptor()
                if (lib.libusb_get_device_descriptor(devices[i], ct.byref(desc)) == 0 and
                        desc.idVendor == VID and desc.idProduct == PID):
                    found = True
                    break
        finally:
            lib.libusb_free_device_list(devices, 1)
        return found

    handle = None
    try:
        deadline = time.monotonic() + args.wait
        present_since = None
        print('Waiting for dizi diagnostic USB device 1209:0001...', flush=True)
        while time.monotonic() < deadline:
            handle = lib.libusb_open_device_with_vid_pid(context, VID, PID)
            if handle:
                break
            if matching_device_present():
                present_since = present_since or time.monotonic()
                if time.monotonic() - present_since > 1.0:
                    raise RuntimeError(
                        'The diagnostic device is present but libusb cannot open it '
                        '(permission denied?); run this tool with sudo')
            else:
                present_since = None
            time.sleep(0.1)
        if not handle:
            print('No readable diagnostic device appeared before timeout.', file=sys.stderr)
            return 2
        product = control(handle, 0x80, 6, 0x302, 0x409, 63)
        if len(product) < 2 or product[2:].decode('utf-16-le') != 'Dizi boot diagnostics':
            raise RuntimeError('Different USB prototype device; no log requested')

        state = control(handle, 0xc0, 0x52, 0, 0, 16)
        if len(state) < 12:
            raise RuntimeError(f'Short log state reply ({len(state)} bytes)')
        magic, total, oldest = struct.unpack('<III', state[:12])
        if magic != POLG:
            raise RuntimeError(f'Bad log state magic 0x{magic:08x}')
        print(f'Log ring: {total} bytes written, {oldest} overwritten', flush=True)

        chunks = []
        offset = oldest
        last_growth = time.monotonic()
        while True:
            if offset < oldest:
                print(f'WARNING: log overwrote {oldest - offset} unread bytes', file=sys.stderr)
                offset = oldest
            while offset < total:
                chunk = control(handle, 0xc0, 0x51, offset & 0xffff,
                                offset >> 16, min(63, total - offset))
                if not chunk:
                    raise RuntimeError(f'Empty log chunk at offset {offset}/{total}')
                chunks.append(chunk)
                offset += len(chunk)
                last_growth = time.monotonic()
            time.sleep(0.1)
            state = control(handle, 0xc0, 0x52, 0, 0, 16)
            magic, total, oldest = struct.unpack('<III', state[:12])
            if magic != POLG:
                raise RuntimeError(f'Bad log state magic 0x{magic:08x}')
            if offset > total:
                raise RuntimeError(f'Log position {offset} beyond total {total}')
            if offset == total:
                if time.monotonic() - last_growth >= args.settle:
                    break
                if time.monotonic() >= deadline:
                    print('WARNING: shim did not finish; saving what was read', file=sys.stderr)
                    break

        data = b''.join(chunks)
        if not data:
            raise RuntimeError('No log bytes were returned')
        if b'POCOPAD diagnostic' not in data or b'SHIM: dizi' not in data:
            print('WARNING: expected dizi boot markers are missing', file=sys.stderr)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('xb') as stream:
            stream.write(data)
        print(data.decode('utf-8', errors='replace'), end='')
        print(f'Saved {len(data)} bytes to {args.out}', flush=True)
        try:
            control(handle, 0x00, 0x53, timeout=200)
        except RuntimeError:
            pass  # the device may reboot before the status stage completes
        return 0
    finally:
        if handle:
            lib.libusb_close(handle)
        lib.libusb_exit(context)


if __name__ == '__main__':
    sys.exit(main())
