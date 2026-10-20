#!/usr/bin/env python3
"""0112 immutable-patch source contract + offline GPT CRC and overflow tests.

Extract the *actual* 0112 XNU header rather than testing a disconnected
implementation; stage 0111 -> 0112 in a disposable Git directory; never
access UFS, GPIO or the tablet. Apple ARM64 compile uses CI flags separately.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH_0111 = ROOT / 'xnu/patches/0111-dizi-ufs-gpt-bounds.patch'
PATCH_0112 = ROOT / 'xnu/patches/0112-dizi-ufs-gpt-integrity.patch'
PORTABLE = ROOT / 'ports/dizi/ufs_gpt_integrity_0112.h'
TEST = ROOT / 'ports/dizi/ufs_gpt_integrity_0112_test.c'


def run(args, cwd=ROOT, **kwargs):
    subprocess.run(args, cwd=cwd, check=True, **kwargs)


def extract_header(patch: str) -> str:
    name = 'bsd/dev/dizi_ufs_gpt_integrity_0112.h'
    section = patch.split('+++ b/' + name + '\n', 1)[1]
    result = []
    assert section.startswith('@@ -0,0 +1,')
    for line in section.splitlines(keepends=True):
        if line.startswith('@@ '):
            continue
        if line.startswith('+'):
            result.append(line[1:])
        else:
            raise AssertionError('0112 header must be a new file with additions only')
    return ''.join(result)


def main():
    patch = PATCH_0112.read_text()
    header = extract_header(patch)
    assert PORTABLE.read_text() == header, 'XNU and host GPT validators diverge'
    assert 'dizigptverify' in patch
    assert 'ufs_find_partition(want, dizi == 1 && gpt_verify == 1)' in patch
    assert 'dizi_gpt_0112_header(b, UFS_BLOCK, UFS_BLOCK,' in patch
    assert 'dizi_gpt_0112_entries(b, (size_t)table_blocks * UFS_BLOCK,' in patch
    assert 'if (verify_gpt && !dizi_gpt_0112_nonzero_guid(e))' in patch
    # Neither new code nor the pure header adds I/O primitives.  Existing
    # `ufs_read_blocks` call is a hunk context, not an added code operation.
    added = '\n'.join(line[1:] for line in patch.split('--- /dev/null\n', 1)[0].splitlines()
                      if line.startswith('+') and not line.startswith('+++'))
    for forbidden in ('ml_io_map(', 'ufs_write_blocks(', 'ufs_scsi(',
                      'ufs_read_blocks(', 'writel(', 'memcpy(b,', 'bzero(b,'):
        assert forbidden not in added, forbidden
    print('PASS: XNU 0112 header mirrors host byte-for-byte, default gated, only readonly metadata checks', flush=True)

    compiler = shutil.which('clang') or shutil.which('cc')
    assert compiler, 'C11 host compiler required'
    with tempfile.TemporaryDirectory(prefix='dizi-ufs-gpt0112-') as name:
        tmp = Path(name)
        (tmp / 'bsd/dev').mkdir(parents=True)
        (tmp / 'bsd/dev/sweet_ufs.c').write_bytes(
            (ROOT / 'research/bt0099/xnu/bsd/dev/sweet_ufs.c').read_bytes())
        run(['git', 'init', '-q'], cwd=tmp)
        run(['git', 'apply', '--check', '--directory=.', str(PATCH_0111)], cwd=tmp)
        run(['git', 'apply', '--directory=.', str(PATCH_0111)], cwd=tmp)
        run(['git', 'apply', '--check', '--directory=.', str(PATCH_0112)], cwd=tmp)
        run(['git', 'apply', '--directory=.', str(PATCH_0112)], cwd=tmp)
        run(['git', 'apply', '-R', '--check', '--directory=.', str(PATCH_0112)], cwd=tmp)
        assert (tmp / 'bsd/dev/dizi_ufs_gpt_integrity_0112.h').read_text() == header
        actual=(tmp / 'bsd/dev/sweet_ufs.c').read_text()
        a=actual.index('if (verify_gpt && !dizi_gpt_0112_header(')
        b=actual.index('error = ufs_read_blocks(entry_lba, table_blocks);')
        c=actual.index('if (verify_gpt && (integrity.table_lba != entry_lba')
        d=actual.index('for (uint32_t i = 0; i < nent; i++) {')
        e=actual.index('su.first_block = first;')
        assert a < b < c < d < e, 'CRC must precede table DMA reuse/partition selection'
        assert 'return ENXIO;' in actual[a:b] and 'return ENXIO;' in actual[c:d]
        print('PASS: pristine XNU + 0111 -> 0112 apply/reverse, CRC before bounce reuse and partition selection', flush=True)
        program = tmp / 'gpt0112-test'
        flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
                 '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        run([compiler, *flags, str(TEST), '-o', str(program)])
        run([str(program)], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
    print('PASS: synthetic GPT CRC32 / entry header validation under ASan+UBSan', flush=True)

if __name__ == '__main__':
    main()
