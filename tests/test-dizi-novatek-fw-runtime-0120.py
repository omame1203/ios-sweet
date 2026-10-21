#!/usr/bin/env python3
"""Real 0120 XNU firmware/HID bridge integration and fail-closed host tests.

No USB/device, boot, DMA, MMIO, GPI doorbell, hypervisor or SMMU writes.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0120-dizi-novatek-fw-runtime.patch'
SOURCES = ('nvt_session_0120.h', 'nvt_session_0120.c',
           'nvt_session_xnu_0120.h', 'nvt_session_xnu_0120.c')

def run(*args, cwd=None):
    subprocess.run(args, check=True, cwd=cwd)

def source_from_patch(patch, path):
    marker = f'diff --git a/bsd/dev/{path} b/bsd/dev/{path}\n'
    s = patch.split(marker, 1)[1].split('diff --git ', 1)[0]
    assert 'new file mode 100644' in s
    return ''.join(line[1:] for line in s.splitlines(keepends=True)
                   if line.startswith('+') and not line.startswith('+++'))

def main():
    patch = PATCH.read_text()
    for name in SOURCES:
        assert source_from_patch(patch, name) == (ROOT / 'ports/dizi' / name).read_text()
    assert '#define DIZI_NVT0120_NATIVE_TRANSPORT_READY 0' in patch
    assert 'sweet_hid_touch' in patch and 'dizi_nvt_fw_upload' in patch
    assert 'bsd/dev/nvt_session_xnu_0120.c' in patch
    # Stage only exact 0106 XNU files; 0117/0118/0119 can be added independently.
    with tempfile.TemporaryDirectory(prefix='dizi-nvt0120-') as temp:
        tmp = Path(temp)
        (tmp / 'bsd/conf').mkdir(parents=True)
        conf = ROOT / 'research/dizi-ci0106/xnu/bsd/conf/files'
        if conf.exists():
            shutil.copy2(conf, tmp / 'bsd/conf/files')
            run('git', 'apply', '--check', '--whitespace=error', str(PATCH), cwd=tmp)
            run('git', 'apply', str(PATCH), cwd=tmp)
            run('git', 'apply', '-R', '--check', str(PATCH), cwd=tmp)
            for name in SOURCES:
                assert (tmp/'bsd/dev'/name).read_text() == (ROOT/'ports/dizi'/name).read_text()
            print('PASS 0120: XNU conf/files + real 4 native-source patch applies/reverses')
        else:
            print('SKIP 0120 source apply: local CI buildtree absent')
        cc = shutil.which('clang') or shutil.which('gcc')
        assert cc is not None
        inc = str(ROOT / 'ports/dizi')
        exe = tmp/'nvt0120-host'
        run(cc, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            '-I', inc,
            str(ROOT/'ports/dizi/nvt_session_0120.c'),
            str(ROOT/'ports/dizi/nvt_session_xnu_0120.c'),
            str(ROOT/'ports/dizi/nt36532_fw.c'),
            str(ROOT/'tests/dizi_nvt_session_0120_test.c'),
            '-o', str(exe))
        run(str(exe))
        for name in ('nvt_session_0120.c','nvt_session_xnu_0120.c'):
            run(cc, '--target=aarch64-linux-gnu', '-std=c11', '-ffreestanding',
                '-Wall', '-Wextra', '-Werror', '-I',inc, '-c',
                str(ROOT/'ports/dizi'/name), '-o', str(tmp/(name+'.arm64.o')))
    print('PASS 0120: sanitizer and ARM64 native touch firmware/report coordinator')

if __name__ == '__main__':
    main()
