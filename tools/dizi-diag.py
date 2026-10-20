#!/usr/bin/env python3
"""Temporarily boot the dizi shim and collect its diagnostics over USB.

Runs the EP0 logger before `fastboot boot`, then (after the shim resets to
Android, if installed) also saves the ramoops/pstore console as a fallback.
Use --no-android with a native iPadOS root: the tablet will not return to
Android, so USB is the only capture channel. No partitions are flashed.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT.parent / 'host-tools' / 'platform-tools'
ADB = str(TOOLS / 'adb')
FASTBOOT = str(TOOLS / 'fastboot')
USB_LOG = ROOT / 'tools' / 'dizi-usb-log.py'


def run(cmd, timeout=120, capture=True):
    return subprocess.run(cmd, timeout=timeout, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def adb_devices():
    out = run([ADB, 'devices']).stdout
    return [line.split()[0] for line in out.splitlines()[1:]
            if line.strip() and line.split()[1] == 'device']


def fastboot_devices():
    out = run([FASTBOOT, 'devices']).stdout
    return [line.split()[0] for line in out.splitlines() if line.strip()]


def wait_for(predicate, seconds, label):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(1)
    print(f'Timed out waiting for {label}', file=sys.stderr)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image', type=Path,
                    default=ROOT / 'shim' / 'out' / 'dizi' / 'shim-boot.img')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--usb-wait', type=float, default=130)
    ap.add_argument('--no-boot', action='store_true',
                    help='skip reboot/fastboot boot and only collect pstore')
    ap.add_argument('--no-android', action='store_true',
                    help='collect via USB only; skip Android return and pstore')
    args = ap.parse_args()
    if args.no_android and args.no_boot:
        ap.error('--no-android cannot be combined with --no-boot')
    if not args.image.exists():
        raise SystemExit(f'Missing boot image: {args.image}')
    if not args.out.parent.exists():
        args.out.parent.mkdir(parents=True)
    usb_log = args.out.with_suffix(args.out.suffix + '.usb')
    pstore = args.out.with_suffix(args.out.suffix + '.pstore')
    for path in (usb_log, pstore):
        if path.exists():
            raise SystemExit(f'Output already exists: {path}')

    logger = None
    if not args.no_boot:
        if not fastboot_devices():
            if not adb_devices():
                raise SystemExit('No adb or fastboot device; connect the tablet')
            print('Rebooting Android to the bootloader...', flush=True)
            run([ADB, 'reboot', 'bootloader'])
            if not wait_for(fastboot_devices, 90, 'fastboot'):
                return 2
        print('Starting USB log capture...', flush=True)
        logger_cmd = [sys.executable, str(USB_LOG), '--out', str(usb_log),
                      '--wait', str(args.usb_wait)]
        if os.geteuid() != 0 and run(['sudo', '-n', 'true'], timeout=10).returncode == 0:
            logger_cmd = ['sudo', '-n'] + logger_cmd
        elif os.geteuid() != 0:
            print('NOTE: USB bulk access usually needs root; the capture may fail.',
                  file=sys.stderr)
        logger = subprocess.Popen(logger_cmd, text=True)
        time.sleep(0.3)
        print(f'fastboot boot {args.image}', flush=True)
        result = run([FASTBOOT, 'boot', str(args.image)], timeout=120,
                     capture=False)
        if result.returncode:
            logger.terminate()
            raise SystemExit(f'fastboot boot failed with {result.returncode}')

    usb_ok = False
    if logger:
        print('Waiting for the shim to expose its USB log...', flush=True)
        usb_ok = logger.wait(timeout=args.usb_wait + 120) == 0
        if usb_ok:
            args.out.write_bytes(usb_log.read_bytes())
            print(f'USB diagnostics saved to {args.out}', flush=True)
        else:
            print('USB log capture failed' +
                  ('; Android pstore fallback disabled' if args.no_android
                   else '; relying on pstore'), file=sys.stderr)

    if args.no_android:
        if not usb_ok:
            print('No USB log captured; Android pstore fallback disabled.',
                  file=sys.stderr)
            return 4
        print('USB capture complete; Android return check skipped.', flush=True)
        return 0

    if args.no_boot and not adb_devices():
        raise SystemExit('No adb device for the pstore fallback')
    if not args.no_boot:
        if not wait_for(lambda: bool(adb_devices()), 240, 'Android return'):
            return 3
        if not wait_for(lambda: run([ADB, 'shell', 'getprop', 'sys.boot_completed']).stdout.strip() == '1',
                        180, 'sys.boot_completed'):
            return 3
    print('Reading /sys/fs/pstore...', flush=True)
    listing = run([ADB, 'shell', 'su', '-c', 'ls /sys/fs/pstore']).stdout
    print(listing, end='')
    data = b''
    if 'console-ramoops' in listing:
        raw = subprocess.run(
            [ADB, 'exec-out', 'su', '-c',
             'cat /sys/fs/pstore/console-ramoops-0'],
            timeout=120, stdout=subprocess.PIPE).stdout
        if raw:
            pstore.write_bytes(raw)
            data = raw
            print(f'pstore console saved to {pstore} ({len(raw)} bytes)', flush=True)
    if not usb_ok and not data:
        print('No diagnostics were recovered.', file=sys.stderr)
        return 4
    if not usb_ok:
        args.out.write_bytes(data)
        print(f'Fallback pstore diagnostics saved to {args.out}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
