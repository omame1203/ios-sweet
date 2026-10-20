#!/usr/bin/env python3
"""Read the temporary dizi shim's diagnostic snapshot through USB EP0.

Start this on the host BEFORE `fastboot boot`. Uses libusb through ctypes;
no Python packages, kernel driver detachment, device writes or disk access.
The firmware implements a vendor-class lab device (1209:0001), not an iPad.
"""
import argparse
import ctypes as ct
import ctypes.util
from pathlib import Path
import sys
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--wait', type=float, default=70)
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
    lib.libusb_close.argtypes = [ct.c_void_p]
    lib.libusb_control_transfer.argtypes = [ct.c_void_p, ct.c_uint8, ct.c_uint8,
        ct.c_uint16, ct.c_uint16, ct.POINTER(ct.c_ubyte), ct.c_uint16, ct.c_uint]
    lib.libusb_control_transfer.restype = ct.c_int
    context = ct.c_void_p()
    status = lib.libusb_init(ct.byref(context))
    if status:
        raise SystemExit(f'libusb_init failed: {status}')

    def read(handle, kind, request, value, index):
        buffer = (ct.c_ubyte * 63)()
        n = lib.libusb_control_transfer(handle, kind, request, value, index, buffer, 63, 1500)
        if n < 0:
            raise RuntimeError(f'USB control read failed: libusb status {n}')
        return bytes(buffer[:n])

    handle = None
    try:
        deadline = time.monotonic() + args.wait
        print('Waiting for dizi diagnostic USB device 1209:0001...', flush=True)
        while time.monotonic() < deadline:
            handle = lib.libusb_open_device_with_vid_pid(context, 0x1209, 1)
            if handle:
                break
            time.sleep(0.1)
        if not handle:
            print('No readable diagnostic device appeared before timeout.', file=sys.stderr)
            return 2
        product = read(handle, 0x80, 6, 0x302, 0x409)
        if len(product) < 2 or product[2:].decode('utf-16-le') != 'Dizi boot diagnostics':
            raise RuntimeError('Different USB prototype device; no log requested')
        chunks = []
        offset = 0
        while offset < 16384:
            chunk = read(handle, 0xc0, 0x51, offset, 0)
            chunks.append(chunk)
            offset += len(chunk)
            if len(chunk) < 63:
                break
        data = b''.join(chunks)
        if b'POCOPAD diagnostic' not in data or b'SHIM: dizi' not in data:
            raise RuntimeError('Snapshot does not contain the expected dizi boot markers')
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('xb') as stream:
            stream.write(data)
        print(data.decode('utf-8', errors='replace'), end='')
        print(f'Saved {len(data)} bytes to {args.out}', flush=True)
        return 0
    finally:
        if handle:
            lib.libusb_close(handle)
        lib.libusb_exit(context)


if __name__ == '__main__':
    sys.exit(main())
