#!/usr/bin/env python3
"""Offline 0115 ownership ABI audit + future single-ifnet ownership model.

Uses tracked 0075/0098/0106 patch content in a clean clone. If ignored Apple
IONetworkingFamily-166 sources / XNU kernel image exist, cross-check the
actual Apple private allocation path and linked fake OSMetaClass symbols.
No XNU patch is produced until the real family can own the ONLY interface.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / 'ports/dizi/usb_ifnet_owner_0115.h'
TEST = ROOT / 'tests/test_dizi_usb_ifnet_owner_0115.c'


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    base = (ROOT / 'xnu/patches/0075-sweet-usb-ecm.patch').read_text()
    fake = (ROOT / 'xnu/patches/0098-dizi-usb-network-identity.patch').read_text()
    bridge = (ROOT / 'xnu/patches/0106-dizi-usb-io-networking.patch').read_text()
    assert 'ifnet_allocate_extended(&init, &ud.ifp)' in base
    assert 'ifnet_attach(ud.ifp, NULL)' in base
    assert 'init.name = "ue";' in base and 'init.unit = 0;' in base
    assert 'init.output = ud_if_output;' in base
    assert 'class IONetworkController : public IOService' in fake
    assert 'OSDefineMetaClassAndStructors(IONetworkController, IOService)' in fake
    assert 'sweet-identity-only' in fake
    assert 'dizi_link.attached = true; /* ifnet_attach succeeded above */' in bridge
    assert 'class DiziUSBECMController final : public IOService' in bridge
    assert 'IOBSDName", "ue0"' in bridge
    assert 'ifnet_allocate_extended(&init, &ud.ifp)' not in bridge
    assert 'netid != 0 && dizi != 0 && bridge == 0' in bridge
    print('PASS tracked BSD ue0 sole owner, 0106 companion and fake 0098 class gates')

    apple = ROOT / 'research/ionet-0109/src166'
    if (apple / 'IONetworkInterface.cpp').exists():
        interface = (apple / 'IONetworkInterface.cpp').read_text()
        hdr = (apple / 'IONetworkInterface.h').read_text()
        stack = (apple / 'IONetworkStack.cpp').read_text()
        control = (apple / 'IONetworkController.cpp').read_text()
        assert 'ifnet_allocate_extended(&eparams, &_backingIfnet)' in interface
        assert 'ifnet_attach(_backingIfnet, ll_addr)' in interface
        assert '_backingIfnet;' in hdr
        assert 'netif->attachToDataLinkLayer(0, 0)' in stack
        assert 'OSDefineMetaClassAndAbstractStructors( IONetworkController, IOService )' in control
        for forbidden in ('adoptIfnet(', 'attachExistingIfnet(', 'setBackingIfnet('):
            assert forbidden not in hdr
        print('PASS official Apple-166 source: independent private ifnet, incompatible metaclass, no adopt ABI')
    else:
        print('SKIP optional ignored Apple-166 sources not in clean checkout')

    image = ROOT / 'xnu/out-0111/kernel.development.sweet'
    nm = shutil.which('llvm-nm')
    if image.exists() and nm:
        sym = run([nm, '-g', str(image)], capture_output=True, text=True).stdout
        assert '__ZN19IONetworkController10gMetaClassE' in sym
        assert '__ZTV19IONetworkController' in sym
        assert '__ZN18IONetworkInterface10gMetaClassE' not in sym
        assert '__ZN20IOEthernetController10gMetaClassE' not in sym
        print('PASS actual 0111 Mach-O fake IONetworkController OSMetaClass/vtable; genuine family absent')
    else:
        print('SKIP optional ignored kernel symbol cross-check')

    compiler = os.getenv('CLANG', 'clang')
    with tempfile.TemporaryDirectory(prefix='dizi-usb-0115-') as t:
        td = Path(t)
        exe = td / 'single-owner-test'
        run([compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-pedantic', '-fsanitize=address,undefined',
             '-fno-omit-frame-pointer', '-fno-sanitize-recover=all',
             '-I' + str(PORT.parent), str(TEST), '-o', str(exe)])
        run([str(exe)], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
        print('PASS ASan+UBSan future ownership state transitions')

        probe = td / 'arm64.c'
        probe.write_text('#include "usb_ifnet_owner_0115.h"\n'
                         'int single(struct dizi_usb_owner_state *s, uint64_t e) {\n'
                         '  return dizi_usb_owner_claim(s, 1, DZ_USB_NATIVE_ALL, e);\n}\n')
        run([compiler, '--target=aarch64-none-elf', '-ffreestanding', '-nostdlib',
             '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-pedantic',
             '-I' + str(PORT.parent), '-c', str(probe),
             '-o', str(td / 'single-owner-arm64.o')])
        print('PASS AArch64 freestanding C object')


if __name__ == '__main__':
    main()
