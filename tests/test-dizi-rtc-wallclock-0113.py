#!/usr/bin/env python3
"""Verify tracked 0113 host policy, optional true XNU ARM64 objects, and ABI.

Works from a clean git checkout without ignored MiCode or XNU build artifacts.
Hardware tick, RTC UTC accuracy and live iPadOS calendar remain unverified.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0113-dizi-rtc-wallclock.patch'
HEADER = ROOT / 'ports/dizi/rtc_wallclock_0113.h'


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def added_source(patch, name):
    marker = '+++ b/' + name
    assert marker in patch, marker
    part = patch.split(marker, 1)[1].split('diff --git', 1)[0]
    return ''.join(x[1:] for x in part.splitlines(True)
                   if x.startswith('+') and not x.startswith('+++'))


def main():
    data = PATCH.read_text()
    assert added_source(data, 'bsd/dev/dizi_rtc_wallclock_0113.h') == HEADER.read_text()
    # The new software clock seed never calls the platform clock SET method.
    assert 'clock_seed_calendar_from_dizi_rtc' in data
    after = data.split('+clock_seed_calendar_from_dizi_rtc(clock_sec_t secs', 1)[1]
    seed = after.split('+#endif /* ARM64_BOARD_CONFIG_SWEET */', 1)[0]
    assert 'PESetUTCTimeOfDay(' not in seed
    assert '+    lck_mtx_lock(&settime_lock);' in seed
    assert '+    if (dizi_rtc_wall_may_seed((uint64_t)oldsecs)) {' in seed
    assert '+    lck_mtx_unlock(&settime_lock);' in seed
    assert 'clock_initialize_calendar' in data
    assert 'PE_parse_boot_argn("dizirtctime"' in data
    assert 'rtc_wall = rtc && rtctime_requested == 1' in data
    assert 'dizi_rtc_sample(&pair.first)' in data
    assert 'dizi_rtc_sample(&pair.next)' in data
    assert 'dizi_rtc_wall_candidate(&pair, seconds)' in data
    assert 'dizi_rtc_wall_sample(&seconds)' in data
    for prohibited in ('rtc_write(', 'SPMI_WRITE', 'fastboot ', 'clock_set_calendar_microtime(seconds'):
        assert prohibited not in data, prohibited

    compiler = os.environ.get('CLANG', 'clang')
    with tempfile.TemporaryDirectory(prefix='dizi-rtc-0113-') as tmp:
        stage = Path(tmp)
        exe = stage / 'rtc-policy-test'
        run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
             '-O1', '-g', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
             '-I' + str(HEADER.parent), str(ROOT / 'tests/test_dizi_rtc_wallclock_0113.c'),
             '-o', str(exe)])
        run([str(exe)], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
        print('PASS 0113 deterministic ASan/UBSan RTC policy')

        arm = stage / 'rtc-arm.c'
        arm.write_text('#include "rtc_wallclock_0113.h"\n'
                       'int candidate(struct dizi_rtc_wall_pair *p, unsigned *n) {\n'
                       '  return dizi_rtc_wall_candidate(p, n);\n}\n')
        run([compiler, '--target=aarch64-none-elf', '-ffreestanding',
             '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
             '-I' + str(HEADER.parent), '-c', str(arm),
             '-o', str(stage / 'rtc-arm.o')])
        print('PASS 0113 freestanding AArch64 policy object')

        bt = ROOT / 'research/dizi-ci0106'
        if not (bt / 'xnu/osfmk/kern/clock.c').exists():
            print('SKIP optional real XNU source/buildtree missing in fresh checkout')
            return
        files = ['bsd/dev/sweet_keys.c', 'osfmk/kern/clock.c']
        for name in files:
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((bt / 'xnu' / name).read_bytes())
        run(['git', 'apply', '--check', str(PATCH)], cwd=stage)
        run(['git', 'apply', str(PATCH)], cwd=stage)
        print('PASS 0113 applies cleanly to real XNU 0101+0106 source')

        spec = importlib.util.spec_from_file_location(
            'xnu_cc_0113', ROOT / 'tools/xnu-buildtree-cc.py')
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not (bt / 'build/xnu.obj/DEVELOPMENT_ARM64_SWEET/bsd/DEVELOPMENT/.CFLAGS').exists():
            print('SKIP optional real XNU compiler flags unavailable')
            return
        nm = os.environ.get('LLVM_NM', 'llvm-nm')
        for name in files:
            component = name.split('/')[0]
            flag_file = (bt / 'build/xnu.obj/DEVELOPMENT_ARM64_SWEET' /
                         component / 'DEVELOPMENT/.CFLAGS')
            options = mod.flags(flag_file, bt)
            out = stage / (name.replace('/', '_') + '.o')
            run([compiler, '--target=arm64-apple-macos14.0', '-c', '-o', str(out),
                 *options, str(stage / name)], cwd=flag_file.parent)
            syms = subprocess.run([nm, str(out)], check=True, capture_output=True,
                                  text=True).stdout
            abi = '_clock_seed_calendar_from_dizi_rtc'
            lines = [line for line in syms.splitlines() if abi in line]
            if component == 'bsd':
                assert len(lines) == 1 and ' U ' + abi in lines[0], lines
            else:
                assert len(lines) == 1 and ' T ' + abi in lines[0], lines
            print('PASS 0113 native Mach-O ARM64 object and ABI:', name, lines)


if __name__ == '__main__':
    main()
