#!/usr/bin/env python3
"""Run offline POCO Pad port foundation checks without touching the tablet."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0104-dizi-nt36532-firmware.patch'


def check_firmware_mirror():
    names = {'bsd/dev/dizi_nt36532_fw.c': 'ports/dizi/nt36532_fw.c',
             'bsd/dev/nt36532_fw.h': 'ports/dizi/nt36532_fw.h'}
    lines = {name: [] for name in names}
    current = None
    for line in PATCH.read_text().splitlines(keepends=True):
        if line.startswith('--- '):
            current = None
        elif line.startswith('+++ b/'):
            candidate = line[6:].strip()
            current = candidate if candidate in names else None
        elif line.startswith('@@'):
            continue
        elif current and line.startswith('+') and not line.startswith('+++'):
            lines[current].append(line[1:])
    for patch_name, source_path in names.items():
        assert lines[patch_name], f'no added source for {patch_name}'
        assert ''.join(lines[patch_name]) == (ROOT / source_path).read_text(), (
            f'XNU patch and host-tested {source_path} differ')
    print('PASS firmware portable source matches actual XNU patch byte-for-byte', flush=True)


def run(args):
    subprocess.run(args, check=True, cwd=ROOT)


def main():
    check_firmware_mirror()
    run([sys.executable, 'tests/test-dizi-cpu-topology.py'])
    run([sys.executable, 'tools/test-dizi-rtc.py'])
    run([sys.executable, 'tests/test-dizi-smmu-dma.py'])
    run([sys.executable, 'tests/test-dizi-se9-xnu.py'])
    run([sys.executable, 'tests/test-dizi-ufs-gpt.py'])
    run([sys.executable, 'tests/test-dizi-lcd.py'])
    run([sys.executable, 'tests/test-dizi-lcd-generation-race.py'])
    run([sys.executable, 'tests/test-dizi-pmic-glink.py'])
    run([sys.executable, 'tests/test-dizi-pmic-sched-0110.py'])
    run([sys.executable, 'tests/test-dizi-usb-link.py'])
    blob = ROOT / 'research/dizi-novatek-fw/novatek_ts_fw_boe.bin'
    with tempfile.TemporaryDirectory(prefix='dizi-nvt-port-') as folder:
        binary = str(Path(folder) / 'fw-test')
        run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g',
             '-Wall', '-Wextra', '-Werror', '-pedantic',
             '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
             'ports/dizi/nt36532_fw.c', 'ports/dizi/nt36532_fw_test.c',
             '-o', binary])
        if blob.is_file():
            run([binary, str(blob)])
        else:
            print('SKIP firmware image test: optional ignored BOE blob unavailable')
    print('PASS dizi offline port foundation suite')


if __name__ == '__main__':
    main()
