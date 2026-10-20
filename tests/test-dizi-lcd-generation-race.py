#!/usr/bin/env python3
"""Reconstruct 0103 -> 0109 source and compile actual production VSYNC/power fragments
against deterministic parallel host IOLock and framebuffer mocks. No device I/O.
"""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PATCH_0103=ROOT/'xnu/patches/0103-dizi-lcd-power.patch'
PATCH_0109=ROOT/'xnu/patches/0109-dizi-lcd-generation-race.patch'
SRC=ROOT/'research/bt0099/xnu/iokit/Kernel/arm/SweetFramebuffer.cpp'
TEMPLATE=(ROOT/'tests/dizi_lcd_generation_race_host.cpp').read_text()

def run(cmd,cwd=ROOT,**kwargs):
    return subprocess.run(cmd,cwd=cwd,check=True,**kwargs)

def hunk_after(patch: str, header_prefix: str) -> str:
    """Return the post-change lines of one 0109 unified diff hunk."""
    lines = patch.splitlines(True)
    start = next(i for i, line in enumerate(lines) if line.startswith(header_prefix))
    output = []
    for line in lines[start + 1:]:
        if line.startswith(('@@ ', 'diff --git ')):
            break
        if line[:1] in (' ', '+'):
            output.append(line[1:])
    return ''.join(output)


def new_file_in_patch(patch: str, name: str) -> str:
    section = patch.split(f'diff --git a/{name} b/{name}\n', 1)[1].split('diff --git ', 1)[0]
    assert 'new file mode 100644' in section
    return ''.join(line[1:] for line in section.splitlines(True)
                   if line.startswith('+') and not line.startswith('+++'))


def compact_host_fragments(patch0103: str, patch0109: str):
    """CI fallback without ignored XNU: actual 0109 OFF hunk, with unchanged
    VSYNC/present wrapper; the 0103 power fragment has the actual 0109 addition.
    """
    fade = hunk_after(patch0109, '@@ -260,23 +262,39 @@')
    assert 'fFadeEpoch != fadeEpoch' in fade and 'IOLockLock(fb->fLock)' in fade
    vsync = '''void
AppleCLCD::vsyncFired(OSObject *owner, IOTimerEventSource *sender)
{
    AppleCLCD *fb = (AppleCLCD *)owner;
    uint64_t count = ++fb->fVsyncCount;
    uint64_t now = mach_absolute_time();
    (void)now;
    (void)SWEET_FB_NOTIFY_VSYNC;
    IOLockLock(fb->fLock);
    if (fb->fPowerOff) {
''' + fade + '''        return;
    }
    bool flush = fb->fDirty && (count % fb->fFlushTicks) == 0;
    uint8_t *rec = nullptr;
    if (flush) {
        rec = (uint8_t *)IOMallocData(SWEET_FB_SWAP_REC_SIZE);
        if (rec != nullptr) {
            memcpy(rec, fb->fPending, SWEET_FB_SWAP_REC_SIZE);
            fb->fDirty = false;
        }
    }
    IOLockUnlock(fb->fLock);
    if (rec != nullptr) {
        fb->present(rec);
        IOFreeData(rec, SWEET_FB_SWAP_REC_SIZE);
    }
    sender->setTimeoutUS(SWEET_FB_VSYNC_US);
}
'''
    power = hunk_after(patch0103, '@@ -549,13 +576,19 @@')
    power = ('bool off = args->scalarInput[0] == 0;' +
             power.split('bool off = args->scalarInput[0] == 0;',1)[1].split('IOLockUnlock(fFB->fLock);',1)[0] +
             'IOLockUnlock(fFB->fLock);')
    target = 'fFB->fPowerOff = off;'
    epoch = 'fFB->fFadeEpoch++; /* invalidate any unlocked VSYNC OFF tick */'
    assert epoch in hunk_after(patch0109, '@@ -581,6 +599,7 @@')
    assert power.count(target) == 1
    power = power.replace(target, target+'\n'+epoch)
    return vsync,power


def main():
    text=PATCH_0109.read_text()
    assert text.count('diff --git ')==1
    assert 'SweetFramebuffer.cpp' in text
    assert 'fFadeEpoch++' in text and 'fFadeEpoch != fadeEpoch' in text
    assert 'IOLockLock(fb->fLock);' in text and 'IOLockUnlock(fb->fLock);' in text
    assert 'ml_io_map' not in text and 'dwc_wr' not in text
    with tempfile.TemporaryDirectory(prefix='dizi-lcd-race-') as tmp_name:
        tmp=Path(tmp_name); tree=tmp/'xnu'
        patch0103=PATCH_0103.read_text()
        source_model=new_file_in_patch(patch0103,'bsd/dev/sweet_lcd.c')
        source_header=new_file_in_patch(patch0103,'bsd/dev/sweet_lcd.h')
        (tree/'bsd/dev').mkdir(parents=True,exist_ok=True)
        (tree/'bsd/dev/sweet_lcd.c').write_text(source_model)
        (tree/'bsd/dev/sweet_lcd.h').write_text(source_header)
        if SRC.is_file() and (ROOT/'research/bt0099/xnu/bsd/conf/files').is_file():
            for src,rel in [(SRC,'iokit/Kernel/arm/SweetFramebuffer.cpp'),
                            (ROOT/'research/bt0099/xnu/bsd/conf/files','bsd/conf/files')]:
                dest=tree/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
            run(['git','init','-q'],cwd=tmp)
            (tree/'bsd/dev/sweet_lcd.c').unlink()
            (tree/'bsd/dev/sweet_lcd.h').unlink()
            run(['git','apply','--check','--directory=xnu',str(PATCH_0103)],cwd=tmp)
            run(['git','apply','--directory=xnu',str(PATCH_0103)],cwd=tmp)
            run(['git','apply','--check','--directory=xnu',str(PATCH_0109)],cwd=tmp)
            run(['git','apply','--directory=xnu',str(PATCH_0109)],cwd=tmp)
            run(['git','apply','-R','--check','--directory=xnu',str(PATCH_0109)],cwd=tmp)
            source=(tree/'iokit/Kernel/arm/SweetFramebuffer.cpp').read_text()
            assert source.count('fFadeEpoch++')==1
            assert 'fFadeEpoch = 0;' in source
            assert 'if (!fb->fPowerOff || fb->fFadeEpoch != fadeEpoch)' in source
            assert 'for (uint32_t y = 0; y < fb->fHeight; y++) {\n\t\t\t\tIOLockLock(fb->fLock);' in source
            vsync='void\nAppleCLCD::vsyncFired('+source.split('void\nAppleCLCD::vsyncFired(',1)[1].split('\nvoid\nAppleCLCD::addClient(',1)[0]
            power=source.split('case kSweetFBRequestPowerChange:',1)[1].split('case kSweetFBSwapWait:',1)[0]
            power='bool off = args->scalarInput[0] == 0;'+power.split('bool off = args->scalarInput[0] == 0;',1)[1].split('IOLockUnlock(fFB->fLock);',1)[0]+'IOLockUnlock(fFB->fLock);'
            print('PASS: real XNU source 0103 -> 0109 apply/reverse',flush=True)
        else:
            vsync,power=compact_host_fragments(patch0103,text)
            print('PASS: standalone CI patch-fragment fallback (no ignored XNU required)',flush=True)
        emitted=TEMPLATE.replace('/* BEGIN_EXTRACTED_POWER */\n/* END_EXTRACTED_POWER */',power).replace('/* BEGIN_EXTRACTED_VSYNC */\n/* END_EXTRACTED_VSYNC */',vsync)
        assert emitted!=TEMPLATE and 'AppleCLCD::vsyncFired' in emitted
        (tmp/'mock.cpp').write_text(emitted)
        cfile=tree/'bsd/dev/sweet_lcd.c'
        clang=shutil.which('clang') or shutil.which('cc')
        cxx=shutil.which('clang++') or shutil.which('g++')
        assert clang and cxx
        run([clang,'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(tree/'bsd/dev'),'-c',str(cfile),'-o',str(tmp/'model.o')])
        run([cxx,'-std=c++17','-pthread','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(tree/'bsd/dev'),str(tmp/'mock.cpp'),str(tmp/'model.o'),'-o',str(tmp/'run')])
        run([str(tmp/'run')],env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1'})
    print('PASS: 0103 -> 0109 patch apply/reverse + real VSYNC/power fragments adversarial compiled host tests')

if __name__=='__main__':main()
