#!/usr/bin/env python3
"""Offline checks for the source-identical 0110 PMIC-GLINK scheduler and XNU handoff.

No device access. Compile true XNU SweetBattery with saved kernel C++ flags;
the Apple allocator builtin shims are syntax-only and do not produce a kernel.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0110-dizi-pmic-glink-transport.patch'


def check(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def patch_added_source(data, path):
    target = '+++ b/' + path
    assert target in data, path
    segment = data.split(target, 1)[1].split('diff --git', 1)[0]
    return ''.join(line[1:] for line in segment.splitlines(True)
                   if line.startswith('+') and not line.startswith('+++'))


def main():
    data = PATCH.read_text()
    own = (ROOT / 'ports/dizi/pmic_glink_sched.h').read_text()
    assert patch_added_source(data, 'iokit/Kernel/arm/DiziPmicGlinkSched.h') == own
    endpoint = (ROOT / 'ports/dizi/pmic_glink_endpoint.h').read_text()
    assert patch_added_source(data, 'iokit/Kernel/arm/DiziPmicGlinkEndpoint.h') == endpoint
    assert 'dizi_pmic_glink_transport_open' in data
    assert 'dizi_pmic_glink_transport_receive_epoch' in data
    assert 'dizi_pmic_glink_transport_next_get' in data
    assert 'dizi_pmic_glink_transport_closed_epoch' in data
    assert 'dizipmictransport' in data
    assert 'dizi_pmic_sched_close(&dizi_bc_sched' in data
    for prohibited in ('ml_io_map(', 'writel(', 'ioremap(', 'fastboot ', 'fake_voltage', 'rpmsg_send('):
        assert prohibited not in data, prohibited

    dt_path = ROOT / 'research/ipad5/dizi-live.dts'
    if dt_path.exists():
        fdt = dt_path.read_text()
        assert 'qcom,pmic-glink-channel = "PMIC_RTR_ADSP_APPS"' in fdt
        assert '"msm/adsp/charger_pd"' in fdt
        assert 'smem_region@80900000' in fdt and 'qcom,remote-pid = <0x02>' in fdt
        print('PASS 0110 local dizi live FDT routing provenance')
    else:
        print('SKIP 0110 ignored device FDT not present in fresh clone')
    linux = ROOT / 'research/xiaomi-ruan'
    if (linux / 'drivers/rpmsg/qcom_glink_smem.c').exists():
        smem = (linux / 'drivers/rpmsg/qcom_glink_smem.c').read_text()
        for marker in ('SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR\t478',
                       'SMEM_GLINK_NATIVE_XPRT_FIFO_0\t\t479',
                       'SMEM_GLINK_NATIVE_XPRT_FIFO_1\t\t480'):
            assert marker in smem
        glink = (linux / 'drivers/soc/qcom/pmic_glink.c').read_text()
        assert 'QCOM_SSR_BEFORE_SHUTDOWN' in glink
        assert 'SERVREG_SERVICE_STATE_DOWN' in glink
        assert 'PMIC_RTR_ADSP_APPS' in glink
        print('PASS 0110 local MiCode GLINK/SSR/PDR source provenance')
    else:
        print('SKIP 0110 ignored MiCode kernel source not present in fresh clone')

    with tempfile.TemporaryDirectory(prefix='dizi-pmic-0110-') as temp:
        p = Path(temp)
        stage = p / 'xnu'
        target = stage / 'iokit/Kernel/arm'
        target.mkdir(parents=True)
        # This checked-in fixture is the exact real 0105 XNU source; verify
        # that reverse+forward applying the tracked 0105 patch is lossless.
        fixture = (ROOT / 'tests/fixtures/dizi_pmic_0110_baseline.cpp').read_bytes()
        (target / 'SweetBattery.cpp').write_bytes(fixture)
        p0105 = ROOT / 'xnu/patches/0105-dizi-pmic-glink-telemetry.patch'
        (target / 'DiziPmicTelemetry.h').write_text(
            patch_added_source(p0105.read_text(), 'iokit/Kernel/arm/DiziPmicTelemetry.h'))
        check(['git', 'apply', '--reverse', '--check', str(p0105)], cwd=stage)
        check(['git', 'apply', '--reverse', str(p0105)], cwd=stage)
        check(['git', 'apply', '--check', str(p0105)], cwd=stage)
        check(['git', 'apply', str(p0105)], cwd=stage)
        assert (target / 'SweetBattery.cpp').read_bytes() == fixture
        print('PASS tracked 0105 source fixture reverse/reapply provenance')
        local_0105 = ROOT / 'research/dizi-battery-0105/SweetBattery.cpp'
        if local_0105.exists():
            assert local_0105.read_bytes() == fixture
        check(['git', 'apply', '--check', str(PATCH)], cwd=stage)
        check(['git', 'apply', str(PATCH)], cwd=stage)
        assert (target / 'DiziPmicGlinkSched.h').read_text() == own
        print('PASS 0110 XNU patch applies cleanly after 0105, exact portable source')

        # Host uses the exact two headers that would be compiled into XNU.
        (p / 'pmic_glink_sched.h').write_text(own)
        (p / 'DiziPmicTelemetry.h').write_bytes((target / 'DiziPmicTelemetry.h').read_bytes())
        compiler = os.environ.get('CLANG', 'clang')
        exe = p / 'scheduler-test'
        check([compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
               '-Werror', '-pedantic', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
               '-I' + str(p), str(ROOT / 'tests/test_dizi_pmic_sched_0110.c'),
               '-o', str(exe)])
        check([str(exe)], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
        print('PASS 0110 ASan+UBSan synthetic PMIC channel lifecycle and telemetry')

        # ARM64 freestanding target: no host libc or mocked memory-mapped IO.
        probe = p / 'native.c'
        probe.write_text('#include "DiziPmicGlinkSched.h"\n'
                         'int test(struct dizi_pmic_sched *s, struct dizi_bc_state *b) {\n'
                         '  return dizi_pmic_sched_open(s,b,1,DIZI_PMIC_EV_ALL,1);\n}\n')
        check([compiler, '--target=aarch64-none-elf', '-ffreestanding',
               '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-pedantic',
               '-I' + str(target), '-c', str(probe), '-o', str(p / 'native.o')])
        print('PASS 0110 freestanding AArch64 object')

        buildtree = ROOT / 'research/usbnet-0106/buildtree'
        flags = (buildtree / 'build/xnu.obj/DEVELOPMENT_ARM64_SWEET/iokit/DEVELOPMENT')
        if flags.exists():
            spec = importlib.util.spec_from_file_location(
                'xnu_cc_0110', ROOT / 'tools/xnu-buildtree-cc.py')
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            args = mod.flags(flags / '.CFLAGS', buildtree) + mod.flags(
                flags / '.CXXFLAGS', buildtree)
            args += ['-D__builtin_xnu_type_signature(...)=""',
                     '-D__builtin_xnu_type_summary(...)=0',
                     '-D__builtin_xnu_types_compatible(...)=1']
            check([compiler, '--target=arm64-apple-macos14.0', '-fsyntax-only',
                   *args, str(target / 'SweetBattery.cpp')], cwd=flags,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print('PASS 0110 genuine XNU ARM64 SweetBattery C++ syntax compatibility')


if __name__ == '__main__':
    main()
