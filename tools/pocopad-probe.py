#!/usr/bin/env python3
"""Read-only rooted Android inventory and verified boot/calibration backups.

Private device data goes under backup/ (excluded from git). Never writes to
the tablet, changes its boot mode, or reads the user's userdata partition.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--adb', default='adb')
    ap.add_argument('--serial')
    ap.add_argument('--out', type=Path, default=Path('backup/dizi'))
    ap.add_argument('--backup', action='store_true')
    args = ap.parse_args()
    adb = [args.adb] + (['-s', args.serial] if args.serial else ['-d'])
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out / 'manifest.json').exists():
        raise SystemExit('Existing snapshot preserved. Use --out with a new directory for another probe.')

    def read(command, root=True, timeout=60):
        remote = 'su -c ' + shlex.quote(command) if root else command
        return subprocess.check_output(adb + ['exec-out', remote], timeout=timeout)

    if not read('id').startswith(b'uid=0('):
        raise SystemExit('Root access is required; no backups made.')
    device = read('getprop ro.product.device', root=False).decode().strip()
    if device != 'dizi':
        raise SystemExit(f'Expected dizi, connected device is {device!r}')
    inventory = {
        'getprop.txt': 'getprop',
        'partitions.txt': 'ls -l /dev/block/by-name; cat /proc/partitions',
        'cmdline.txt': 'cat /proc/cmdline; cat /proc/bootconfig',
        'input.txt': 'cat /proc/bus/input/devices',
        'iomem.txt': 'cat /proc/iomem',
        'dmesg.txt': 'dmesg',
        'mounts.txt': 'cat /proc/mounts',
        'fdt': 'cat /sys/firmware/fdt',
        'drm.txt': 'cat /sys/class/drm/card0-DSI-1/modes; cat /sys/class/drm/card0-DSI-1/status; cat /sys/kernel/debug/dri/0/state',
        'cpu.txt': 'cat /proc/cpuinfo; cat /sys/devices/system/cpu/online',
    }
    manifest = {}
    for name, command in inventory.items():
        try:
            data = read(command)
            (args.out / name).write_bytes(data)
            manifest[name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            print(f'Saved {name} ({len(data)} bytes)', flush=True)
        except subprocess.CalledProcessError as exc:
            # Some vendor kernels omit debugfs; keep available output.
            if exc.output:
                (args.out / name).write_bytes(exc.output)
            print(f'Optional inventory {name}: exit {exc.returncode}', flush=True)

    if args.backup:
        partitions = ['persist', 'modemst1', 'modemst2', 'fsg', 'fsc']
        for stem in ['boot', 'vendor_boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'recovery', 'abl']:
            partitions.extend([stem + '_a', stem + '_b'])
        for part in partitions:
            remote = '/dev/block/by-name/' + part
            size = int(read('blockdev --getsize64 ' + remote))
            if not 0 < size <= 256 * 1024 * 1024:
                raise SystemExit(f'Unexpected {part} size {size}; stopping')
            expected = read('sha256sum ' + remote).decode().split()[0]
            dest = args.out / (part + '.img')
            if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == expected:
                print(f'Already verified {part}', flush=True)
            else:
                if dest.exists():
                    raise SystemExit(f'{part}: existing backup differs; preserved. Choose a fresh --out directory.')
                partial = dest.with_suffix('.partial')
                with partial.open('wb') as stream:
                    subprocess.run(adb + ['exec-out', 'su -c ' + shlex.quote('cat ' + remote)],
                                   stdout=stream, check=True, timeout=180)
                digest = hashlib.sha256(partial.read_bytes()).hexdigest()
                if partial.stat().st_size != size or digest != expected:
                    raise SystemExit(f'{part}: size/hash mismatch; retaining .partial')
                partial.replace(dest)
                print(f'Backed up and device-hash verified {part} ({size} bytes)', flush=True)
            manifest[dest.name] = {'size': size, 'sha256': expected}
            (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
