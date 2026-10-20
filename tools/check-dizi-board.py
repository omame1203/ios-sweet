#!/usr/bin/env python3
"""Verify the committed dizi MMIO/RAM profile against a private live FDT."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('fdt', type=Path)
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
    print('Not verified by FDT: framebuffer pixel format/stride, actual boot or peripheral operation')


if __name__ == '__main__':
    main()
