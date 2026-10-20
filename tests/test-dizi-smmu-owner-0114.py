#!/usr/bin/env python3
"""Offline SMMUv2 ownership audit, against the actual NEW 0114 XNU patch.

No device access or registered MMIO callbacks are invoked. Build synthetic
SMMUv2 evidence only; NEVER infer exclusive ownership from register values.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PATCH=ROOT/'xnu/patches/0114-dizi-smmu-owner-readonly.patch'
OLDER=[ROOT/f'xnu/patches/{name}' for name in (
    '0102-dizi-smmu-dma-foundation.patch',
    '0111-dizi-ufs-gpt-bounds.patch',
    '0112-dizi-ufs-gpt-integrity.patch')]
NAMES=('smmu_owner_0114.h','smmu_owner_0114.c','smmu_owner_0114_ro_xnu.c')

def run(cmd, *, cwd=ROOT, **kwargs):
    subprocess.run(cmd,cwd=cwd,check=True,**kwargs)

def extract(patch,name):
    block=patch.split(f'diff --git a/bsd/dev/{name} b/bsd/dev/{name}\n',1)[1].split('diff --git ',1)[0]
    assert 'new file mode 100644' in block
    return ''.join(x[1:] for x in block.splitlines(True)
                   if x.startswith('+') and not x.startswith('+++'))

def main():
    patch=PATCH.read_text()
    sources={name:extract(patch,name) for name in NAMES}
    for name,text in sources.items():
        assert (ROOT/'ports/dizi'/name).read_text()==text, name
    assert 'dizi_smmu_owner_0114_boot_audit();' in patch
    assert 'bsd/dev/smmu_owner_0114.c' in patch and 'bsd/dev/smmu_owner_0114_ro_xnu.c' in patch
    ro=sources['smmu_owner_0114_ro_xnu.c']
    assert 'dizismmuownerro' in ro and 'dizihw' in ro
    assert 'if (dizi != 1 || observe != 1) return;' in ro
    assert ro.count('dz_0114_read32(base,')==4
    for off in ('0x20u','0x24u','0x00u','0x800u'):
        assert f'dz_0114_read32(base, {off})' in ro
    assert 'dz_0114_read32(base, 0x28' not in ro
    assert 'dz_0114_read32(base, 0xc00' not in ro
    assert 's.id2_known = true' not in ro and 'exclusive_hypervisor_permission' not in ro
    assert 'dz_plan_routes(' not in ro and 'dz_domain_init(' not in ro
    assert 'dizi_smmu_owner_0114_boot_audit();' in patch
    for bad in ('str %', 'msr ', 'writel(', 'writeq(', 'ufs_write_blocks(',
                'dma_map', 'TLBI ', 'dz_plan_routes(', 'dz_domain_map('):
        assert bad not in ro, bad
    # Check FDT/live logs where provided locally, not required in clean CI.
    fdt=ROOT/'backup/dizi/live.dts'
    if fdt.exists():
        body=fdt.read_text()
        assert 'iommus = <0x28 0x416 0x00>;' in body
        assert 'iommus = <0x28 0x403 0x00>;' in body
        assert 'qcom,num-smr-override = <0x78>;' in body
    for filename,value in [('dizi-input-probe12.txt','0000000080000060'),
                           ('dizi-input-probe13.txt','0000000000270406')]:
        log=ROOT/'logs'/filename
        if log.exists(): assert value in log.read_text(), filename
    print('PASS: XNU 0114 mirrors portable sources byte-for-byte; read-only MMIO whitelist and opt-in, no ID2/S2CR read or authority claimed',flush=True)
    with tempfile.TemporaryDirectory(prefix='dizi-smmu-owner0114-') as folder:
        tmp=Path(folder); (tmp/'bsd/dev').mkdir(parents=True)
        source=ROOT/'research/bt0099/xnu/bsd/dev/sweet_ufs.c'
        conf=ROOT/'research/bt0099/xnu/bsd/conf/files'
        if source.exists() and conf.exists():
            shutil.copy2(source,tmp/'bsd/dev/sweet_ufs.c')
            (tmp/'bsd/conf').mkdir(parents=True)
            shutil.copy2(conf,tmp/'bsd/conf/files')
            run(['git','init','-q'],cwd=tmp)
            for old in OLDER:
                run(['git','apply','--check',str(old)],cwd=tmp)
                run(['git','apply',str(old)],cwd=tmp)
            run(['git','apply','--check',str(PATCH)],cwd=tmp)
            run(['git','apply',str(PATCH)],cwd=tmp)
            run(['git','apply','-R','--check',str(PATCH)],cwd=tmp)
            for name in NAMES:
                assert (tmp/'bsd/dev'/name).read_text()==sources[name]
            print('PASS: pristine XNU + 0102/0111/0112 -> 0114 apply and reverse',flush=True)
        else:
            print('SKIP XNU apply: ignored bt0099 tree absent; requires compatible staged checkout',flush=True)
        cc=shutil.which('clang') or shutil.which('cc')
        assert cc
        bin=tmp/'host-test'
        run([cc,'-std=c11','-Wall','-Wextra','-Werror','-Wpedantic',
             '-fsanitize=address,undefined','-fno-omit-frame-pointer',
             '-I',str(ROOT/'ports/dizi'),str(ROOT/'ports/dizi/smmu_owner_0114.c'),
             str(ROOT/'tests/dizi_smmu_owner_0114_test.c'),'-o',str(bin)])
        run([str(bin)],env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1'})
    print('PASS: synthetic owner contracts with ASan+UBSan, NO actual device reads',flush=True)

if __name__=='__main__':main()
