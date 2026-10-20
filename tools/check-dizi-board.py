#!/usr/bin/env python3
"""Verify the committed dizi MMIO/RAM profile against a private live FDT."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('fdt', type=Path)
    ap.add_argument('--check-shim', action='store_true', help='Also compile checks tying shim constants to this profile')
    args = ap.parse_args()
    profile = json.loads((Path(__file__).resolve().parents[1] / 'boards/dizi.json').read_text())

    def words(path, prop):
        data = subprocess.check_output(['fdtget', '-t', 'x', str(args.fdt), path, prop], text=True)
        return [int(v, 16) for v in data.split()]

    def string(path, prop):
        return subprocess.check_output(['fdtget', '-t', 's', str(args.fdt), path, prop], text=True).strip()

    def check(actual, expected, label):
        if actual != expected:
            raise SystemExit(f'{label}: actual {actual!r}, expected {expected!r}')
        print('Verified:', label)

    check('DIZI' in string('/', 'model'), True, 'DIZI model')
    check(words('/soc/interrupt-controller@17200000', 'reg'),
          [int(v, 0) for v in profile['gic']], 'GIC distributor/redistributor')
    timer = words('/soc/timer', 'interrupts')
    check(timer[6:8], [1, profile['virtual_timer_intid'] - 16], 'virtual timer PPI')
    check(timer[3:5], [1, profile['physical_timer_intid'] - 16], 'physical timer PPI')
    check(words('/soc/timer', 'clock-frequency'), [profile['timer_frequency']], 'timer frequency')
    check(string('/soc/psci', 'method'), profile['psci'], 'PSCI conduit')
    usb = profile['usb']
    usb_path = '/soc/ssusb@a600000'
    check(words(usb_path, 'reg'), [int(usb['core_base'], 0), int(usb['core_size'], 0)], 'USB wrapper resource')
    check(words(usb_path + '/dwc3@a600000', 'reg'),
          [int(usb['core_base'], 0), int(usb['dwc_size'], 0)], 'DWC3 resource')
    check(words('/soc/qcom,gdsc@149004', 'reg'), [int(usb['gdsc'], 0), 4], 'USB GDSC resource')
    gcc_phandle = words('/soc/clock-controller@100000', 'phandle')[0]
    clocks = words(usb_path, 'clocks')
    check(clocks[::2], [gcc_phandle] * len(usb['clock_ids']), 'USB clocks use measured GCC controller')
    check(clocks[1::2], usb['clock_ids'], 'USB clock IDs match pinned gcc-parrot source')
    check(string('/soc/clock-controller@100000', 'compatible').split()[0], 'qcom,parrot-gcc', 'parrot GCC compatible')
    fb = profile['framebuffer']
    check(words('/reserved-memory/splash_region', 'reg'),
          [0, int(fb['base'], 0), 0, int(fb['reserved_size'], 0)], 'splash reservation')
    for i, mpidr in enumerate(profile['cpu_mpidrs']):
        check(words(f'/cpus/cpu@{mpidr:x}', 'reg'), [0, mpidr], f'CPU {i} MPIDR')
    base, size = (int(v, 0) for v in profile['kernel_ram'])
    memory = words('/memory', 'reg')
    ranges = [(memory[i] << 32 | memory[i+1], memory[i+2] << 32 | memory[i+3])
              for i in range(0, len(memory), 4)]
    check(any(base >= a and base + size <= a + n for a, n in ranges), True, 'kernel RAM inside DDR bank')
    nodes = subprocess.check_output(['fdtget', '-l', str(args.fdt), '/reserved-memory'], text=True).split()
    for name in nodes:
        path = '/reserved-memory/' + name
        props = subprocess.check_output(['fdtget', '-p', str(args.fdt), path], text=True).split()
        if 'reg' not in props:
            continue
        reg = words(path, 'reg')
        for i in range(0, len(reg), 4):
            lo, length = reg[i] << 32 | reg[i+1], reg[i+2] << 32 | reg[i+3]
            if base < lo + length and lo < base + size:
                raise SystemExit(f'Kernel RAM overlaps reserved-memory/{name}')
    print('Verified: no fixed reserved-memory overlap')
    if args.check_shim:
        expected = {
            'BOARD_GICD': int(profile['gic'][0], 0), 'BOARD_GICR': int(profile['gic'][2], 0),
            'BOARD_VTIMER_INTID': profile['virtual_timer_intid'],
            'BOARD_FB_BASE': int(fb['base'], 0), 'BOARD_FB_W': fb['width'],
            'BOARD_FB_H': fb['height'], 'BOARD_FB_STRIDE': fb['stride'],
            'BOARD_USB_GCC': int(usb['gcc_base'], 0),
            'BOARD_USB_GDSCR': int(usb['gdsc'], 0) - int(usb['gcc_base'], 0),
            'BOARD_USB_DWC': int(usb['core_base'], 0), 'BOARD_USB_QSCRATCH': int(usb['qscratch'], 0),
        }
        for key, value in usb['clock_cbcr'].items():
            expected['BOARD_USB_' + key.upper() + '_CBCR'] = int(value, 0)
        source = '#include "board.h"\n' + '\n'.join(
            f'_Static_assert({key} == {value}ULL, "{key}");' for key, value in expected.items())
        include = Path(__file__).resolve().parents[1] / 'shim'
        subprocess.run(['cc', '-DBOARD_DIZI', '-I', str(include), '-x', 'c', '-fsyntax-only', '-'],
                       input=source, text=True, check=True)
        print('Verified: compiled shim constants agree with checked profile')
    print('Not verified by FDT: framebuffer pixel format/stride, actual boot or peripheral operation')


if __name__ == '__main__':
    main()
