#!/usr/bin/env python3
"""Independent 0119 NT36532 -> XNU HID audit and offline validation.

Clean git checkout: tests compiled portable code and checks tracked patches.
When the ignored 0106 XNU CI buildtree exists, also applies 0119 to the
actual 0100/0099 baseline, emits ARM64 Mach-O C and syntax-checks real HID
C++ using the original XNU build flags (Apple-only allocator builtin shims).
Neither test is physical SPI/HID/GUI verification.
"""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0119-dizi-novatek-hid-bridge.patch'
HEADER = ROOT / 'ports/dizi/novatek_hid_bridge_0119.h'
TEST = ROOT / 'tests/test_dizi_novatek_hid_bridge_0119.c'


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def added_source(patch, path):
    target = '+++ b/' + path
    assert target in patch, path
    after = patch.split(target, 1)[1].split('diff --git', 1)[0]
    return ''.join(line[1:] for line in after.splitlines(True)
                   if line.startswith('+') and not line.startswith('+++'))


def main():
    patch = PATCH.read_text()
    portable = HEADER.read_text()
    assert added_source(patch,
                        'iokit/Kernel/arm/hid/DiziNovatekHIDBridge0119.h') == portable
    assert 'bool novatekFrame(uint32_t mask' in patch
    assert 'dizi_nvt_hid_plan(&fNovatekState, &frame, fLogicalW, fLogicalH' in patch
    assert '+    dispatchEvent(collection);' in patch
    assert 'dzinovatekhid' not in patch, 'only approved dizinovatekhid boot arg'
    assert 'PE_parse_boot_argn("dizinovatekhid"' in patch
    assert 'fNovatekBridge = fDizi && novatek_hid == 1' in patch
    assert 'dzt.hid_bridge = dizihw == 1 && enabled == 1 && novatek_hid == 1' in patch
    assert 'dzt.hid_verified = true;' in patch
    assert 'dz_nvt_read(0, pkt, sizeof(pkt)) && dz_parse(pkt, x, y, &mask)' in patch
    assert 'dizi_nvt_hid_frame(mask, x, y, ++dzt.hid_sequence, true, false)' in patch
    assert 'dizi_nvt_hid_frame(0, x, y, ++dzt.hid_sequence, false, true)' in patch
    # 0119 must not start a second HID device, supply fake packets, configure
    # SE9 registers or activate GPI/DMA; inherit all physical checks of 0100.
    for unsafe in ('dz_wr(', 'ml_io_map(', 'dz_exchange(', 'dz_nvt_write(',
                   'dz_se_setup(', 'kernel_thread_start(', 'dizi_nvt_fw_upload('):
        assert not any(line.startswith('+') and unsafe in line
                       for line in patch.splitlines()), unsafe

    old_spi = (ROOT / 'xnu/patches/0100-dizi-novatek-spi-touch.patch').read_text()
    old_hid = (ROOT / 'xnu/patches/0099-dizi-keys-and-hid-coordinates.patch').read_text()
    old_firmware = (ROOT / 'xnu/patches/0104-dizi-nt36532-firmware.patch').read_text()
    assert 'dz_parse(const uint8_t *data, int *x, int *y, uint32_t *mask)' in old_spi
    assert 'sum + data[65]' in old_spi
    assert 'trim[3] != 0x32 || trim[4] != 0x65 || trim[5] != 0x03' in old_spi
    assert 'SRAM firmware handshake unavailable, no touch events' in old_spi
    assert 'sweet_hid_touch(i, 1, x[i], y[i])' in old_spi
    old_edge = (ROOT / 'xnu/patches/0071-sweet-touch-edge.patch').read_text()
    assert 'kIOHIDDigitizerEventFromEdgeTip' in old_edge
    assert 'fDizi' in old_hid and 'fLogicalW' in old_hid
    assert 'nt36532_fw.h' in old_firmware and 'Structural validator' in old_firmware
    # 0058 includes binary/legacy source bytes; decode only for its textual
    # IOKit personalities rather than assuming the whole patch is UTF-8.
    hid_catalogue = (ROOT / 'xnu/patches/0058-sweet-hid-event-services.patch').read_text(errors='replace')
    assert "'IOClass'         = SweetHIDTouch;" in hid_catalogue
    assert "'IOProviderClass' = IOResources;" in hid_catalogue
    print('PASS 0119 real tracked 0099/0100/0104 provenance, SPI handshake, default HID delivery, no added MMIO')

    cc = os.environ.get('CLANG', 'clang')
    with tempfile.TemporaryDirectory(prefix='dizi-novatek-hid-0119-') as tmp:
        out = Path(tmp)
        binary = out / 'novatek-hid-policy-test'
        run([cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-pedantic', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
             '-fno-sanitize-recover=all', '-I' + str(HEADER.parent),
             str(TEST), '-o', str(binary)])
        run([str(binary)], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
        print('PASS 0119 host ASan+UBSan synthetic 45000 frame plan')
        arm = out / 'novatek-plan-arm64.c'
        arm.write_text('#include "novatek_hid_bridge_0119.h"\n'
                       'int frame(struct dizi_nvt_hid_state *s, struct dizi_nvt_hid_frame *f,\n'
                       '  struct dizi_nvt_hid_state *n, struct dizi_nvt_hid_plan *p) {\n'
                       '  return dizi_nvt_hid_plan(s,f,1536,2048,n,p);\n}\n')
        run([cc, '--target=aarch64-none-elf', '-ffreestanding', '-std=c11',
             '-O1', '-Wall', '-Wextra', '-Werror', '-pedantic',
             '-I' + str(HEADER.parent), '-c', str(arm),
             '-o', str(out / 'policy-arm64.o')])
        print('PASS 0119 freestanding AArch64 C policy object')

        bt = ROOT / 'research/dizi-ci0106'
        if not (bt / 'xnu/bsd/dev/sweet_touch.c').exists():
            print('SKIP optional ignored XNU 0106 source/buildtree not in checkout')
            return
        stage = out / 'xnu'
        paths = ('bsd/dev/sweet_touch.c', 'iokit/Kernel/arm/hid/SweetHID.cpp')
        for rel in paths:
            dest = stage / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((bt / 'xnu' / rel).read_bytes())
        # Kernel-local private HID headers are not exported via -I.
        for h in (bt / 'xnu/iokit/Kernel/arm/hid').glob('*.h'):
            shutil.copy2(h, stage / 'iokit/Kernel/arm/hid' / h.name)
        run(['git', 'apply', '--check', str(PATCH)], cwd=stage)
        run(['git', 'apply', str(PATCH)], cwd=stage)
        assert (stage / 'iokit/Kernel/arm/hid/DiziNovatekHIDBridge0119.h').read_text() == portable
        kcfg = (bt / 'xnu/iokit/KernelConfigTables.cpp').read_text()
        service = (bt / 'xnu/iokit/Kernel/arm/hid/SweetHID.cpp').read_text()
        queue = (bt / 'xnu/iokit/Kernel/arm/hid/IOHIDEventServiceUserClient.cpp').read_text()
        assert "'IOClass'         = SweetHIDTouch;" in kcfg
        assert 'setProperty("HIDServiceSupport", kOSBooleanTrue)' in service
        assert 'setProperty("IOUserClientClass", "IOHIDEventServiceUserClient")' in service
        assert 'dispatchEvent(IOHIDEvent *event, IOOptionBits options)' in service
        assert '_queue->enqueueEvent(event)' in queue
        print('PASS XNU IOResources->SweetHIDTouch->dispatchEvent->HID service user-client shared-queue route')
        print('PASS 0119 exact CI0106 XNU 0099+0100 sources, applies cleanly')

        options_file = bt / 'build/xnu.obj/DEVELOPMENT_ARM64_SWEET/bsd/DEVELOPMENT/.CFLAGS'
        if not options_file.exists():
            print('SKIP optional genuine XNU buildtree flags unavailable')
            return
        spec = importlib.util.spec_from_file_location('xnu_cc_0119', ROOT / 'tools/xnu-buildtree-cc.py')
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        for path in paths:
            component = path.split('/')[0]
            flags = bt / 'build/xnu.obj/DEVELOPMENT_ARM64_SWEET' / component / 'DEVELOPMENT'
            opts = mod.flags(flags / '.CFLAGS', bt)
            target = stage / path
            if path.endswith('.cpp'):
                opts += mod.flags(flags / '.CXXFLAGS', bt)
                opts += ['-D__builtin_xnu_type_signature(...)=""',
                         '-D__builtin_xnu_type_summary(...)=0',
                         '-D__builtin_xnu_types_compatible(...)=1']
                run([cc, '--target=arm64-apple-macos14.0', '-fsyntax-only',
                     *opts, str(target)], cwd=flags,
                    stderr=subprocess.DEVNULL)
                print('PASS genuine ARM64 HID SweetHID.cpp C++ syntax compatibility (allocator shims)')
            else:
                obj = out / 'sweet_touch_0119.o'
                run([cc, '--target=arm64-apple-macos14.0', '-c', '-o', str(obj),
                     *opts, str(target)], cwd=flags)
                assert obj.stat().st_size > 10000
                nm = shutil.which('llvm-nm')
                if nm:
                    symbols = run([nm, str(obj)], capture_output=True, text=True).stdout
                    assert ' U _dizi_nvt_hid_frame' in symbols
                print('PASS genuine ARM64 Mach-O sweet_touch.c and HID C symbol consumer')


if __name__ == '__main__':
    main()
