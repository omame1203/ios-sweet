#!/usr/bin/env python3
"""Source-only dizi GIC/Timer gate regression check; no device, no MMIO."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SIL = ROOT / 'ports/renegade/edk2-overlay/Silicon/Qualcomm/sm7435/Drivers/DiziGicTimer'
PLAN = SIL / 'DiziGicTimerPlan.c'
DXE = SIL / 'DiziGicTimerDxe.c'
INF = SIL / 'DiziGicTimerDxe.inf'
TEST = ROOT / 'tests/test-dizi-renegade-gic-timer.c'
UPSTREAM = Path('/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9')


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def source_audit():
    a, b, c = PLAN.read_text(), DXE.read_text(), INF.read_text()
    assert 'DIZI_GT_TIMER_HZ' in a and 'DIZI_GT_VTIMER_PPI' in a
    assert 'DIZI_GIC_TIMER_ENABLE' in b and 'DIZI_GIC_TIMER_OWNER_IMPL_PRESENT' in b
    assert 'return EFI_UNSUPPORTED;' in b
    assert 'DiziGicTimerGetTrustedGrant' in b
    assert 'GtLiveSnapshot(&snapshot)' in b
    assert b.index('DiziGicTimerGetTrustedGrant(&grant)') < b.index('GtLiveSnapshot(&snapshot)')
    assert b.index('DiziGicTimerPlanValidate(&grant, &snapshot)') < b.index('MmioWrite8(')
    assert 'MmioWrite32(DIZI_GT_GICR_BASE + GICR_ISENABLER0' in b
    assert 'ArmGenericTimerEnableTimer();' in b
    assert 'ArmGicV3EnableInterruptInterface();' in b
    for hazard in ('GICR_WAKER,', 'ArmGicEnableDistributor(', 'ArmGicDisableDistributor(',
                   'ArmGicSetInterruptPriority(', 'ArmGenericTimerSetTimerFreq('):
        assert hazard not in b, f'unsafe global GIC or timer mutation: {hazard}'
    assert 'gHardwareInterruptProtocolGuid' in c
    assert 'gEfiTimerArchProtocolGuid' in c
    assert '[Depex]' in c and 'gEfiCpuArchProtocolGuid' in c
    parent = (ROOT / 'ports/renegade/edk2-overlay/Platform/Qualcomm/sm7435/sm7435.dsc').read_text()
    fdf = (ROOT / 'ports/renegade/edk2-overlay/Platform/Qualcomm/sm7435/sm7435.fdf').read_text()
    assert 'DiziGicTimerDxe.inf' not in parent + fdf, 'production default must exclude driver'


def host(tmp):
    cc = shutil.which('gcc') or shutil.which('clang')
    assert cc, 'host compiler required'
    exe = tmp / 'test-gic-timer'
    run([cc, '-O1', '-g', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
         '-fsanitize=undefined,address', '-fno-sanitize-recover=all',
         str(TEST), str(PLAN), '-o', str(exe)])
    print(run([str(exe)]).strip())


def aarch64_plan(tmp):
    cc = shutil.which('aarch64-linux-gnu-gcc')
    if not cc:
        print('SKIP AArch64 cross compiler missing')
        return
    obj = tmp / 'DiziGicTimerPlan.o'
    run([cc, '-std=gnu17', '-O2', '-ffreestanding', '-Wall', '-Wextra', '-Werror',
         '-mgeneral-regs-only', '-c', str(PLAN), '-o', str(obj)])
    print('PASS AArch64 plan object compiled, no MMIO dependency')


if __name__ == '__main__':
    source_audit()
    with tempfile.TemporaryDirectory(prefix='dizi-gic-timer-audit-') as tmpdir:
        tmp = Path(tmpdir)
        host(tmp)
        aarch64_plan(tmp)
    print('PASS source-only GIC/Timer gate, no parent/FDF inclusion by default')
