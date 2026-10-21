#!/usr/bin/env python3
"""Validate the actual KC→dizi shim adapter without boot images/device writes."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [ROOT / p for p in (
    'ports/macos27/kc_loader.c', 'ports/macos27/kc_fixups.c',
    'ports/macos27/boot_args.c', 'shim/macos27_kc.c',
)]
SHIM_SOURCES = [ROOT / 'shim' / name for name in (
    'start.S', 'shim.c', 'console.c', 'mmu.c', 'fdt.c', 'loader.c',
    'ufs.c', 'input_diag.c', 'bootlog.c', 'usb_control.c',
    'usb_diag.c', 'macos27_kc.c', 'macos27_kc_probe.c',
)]


def run(*cmd):
    subprocess.run([str(x) for x in cmd], check=True)


def main():
    clang = shutil.which('clang')
    cross = shutil.which('aarch64-linux-gnu-gcc')
    if not clang or not cross:
        raise SystemExit('Requires clang and aarch64-linux-gnu-gcc')
    with tempfile.TemporaryDirectory(prefix='mac27-shim-') as d:
        dest = Path(d)
        exe = dest / 'test'
        run(clang, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            *SOURCES, ROOT / 'tests/test-macos27-shim.c', '-o', exe)
        paths = [ROOT / f'research/macos27-26A434/kernel.{name}.macho/kernelcache.release.{name}.decompressed'
                 for name in ('vma2', 'mac13g')]
        run(exe, *(p for p in paths if p.is_file()))
        probe_exe = dest / 'probe-test'
        run(clang, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            ROOT / 'ports/macos27/kc_loader.c', ROOT / 'ports/macos27/kc_fixups.c',
            ROOT / 'ports/macos27/boot_args.c',
            ROOT / 'shim/macos27_kc_probe.c', ROOT / 'tests/test-macos27-probe.c',
            '-o', probe_exe)
        run(probe_exe)
        for source in [*SOURCES, ROOT / 'shim/macos27_kc_probe.c']:
            obj = dest / (source.stem + '.o')
            run(cross, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
                '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only',
                '-mstrict-align', '-c', source, '-o', obj)
        for mode in ('default', 'preflight'):
            obj = dest / f'shim-{mode}.o'
            flags = ['-DDIZI_MACOS27_PREFLIGHT'] if mode == 'preflight' else []
            run(cross, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
                '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only',
                '-mstrict-align', '-DBOARD_DIZI', *flags, '-c', ROOT / 'shim/shim.c', '-o', obj)
            symbols = subprocess.check_output(['aarch64-linux-gnu-nm', '-u', str(obj)], text=True)
            if mode == 'default':
                assert 'loader_boot' in symbols and 'mac27_dizi_probe_dtb' not in symbols
            else:
                assert 'mac27_dizi_probe_dtb' in symbols and 'loader_boot' not in symbols
                machine = subprocess.check_output(['aarch64-linux-gnu-objdump', '-dr', str(obj)], text=True)
                # The macOS27 diagnostic must NOT fall through to the legacy
                # XNU22 transfer or dizi GIC, MMU, USB and auto-reset sequence.
                section = machine.split('<shim_main>:', 1)[1].split('\n\n', 1)[0]
                for unsafe in ('loader_boot', 'test_gic', 'mmu_enable', 'mmu_off',
                               'usb_diag_run', 'test_ufs', 'reset'):
                    assert unsafe not in section, f'preflight calls {unsafe}'
        # Link the actual dizi start.S / MMU / I/O shim with the new KC modules.
        # No boot.img, payload, flash, fastboot, or device operation is created.
        linker_flags = ['-std=c11', '-O2', '-ffreestanding', '-nostdlib', '-fno-pic',
                        '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only',
                        '-mstrict-align', '-Wall', '-Wextra', '-Werror', '-DBOARD_DIZI',
                        '-DDIZI_MACOS27_PREFLIGHT']
        objects = []
        for index, source in enumerate([*SHIM_SOURCES, *SOURCES[:3]]):
            obj = dest / f'linked-{index}.o'
            run(cross, *linker_flags, '-c', source, '-o', obj)
            objects.append(obj)
        elf = dest / 'mac27-preflight-only.elf'
        run(cross, *linker_flags, '-static', '-T', ROOT / 'shim/shim.ld',
            '-Wl,--build-id=none', '-Wl,--no-warn-rwx-segments', '-Wl,-N',
            *objects, '-o', elf)
        defined = subprocess.check_output(['aarch64-linux-gnu-nm', '-n', str(elf)], text=True)
        assert all(symbol in defined for symbol in
                   ('_start', 'mac27_dizi_probe_dtb', 'mac27_kc_inspect_fixups',
                    'mac27_shim_stage', 'mac27_encode_boot_args'))
        assert not subprocess.check_output(['aarch64-linux-gnu-nm', '-u', str(elf)], text=True).strip()
        print('PASS full AArch64 dizi shim ELF linked with macOS27 KC/ADT/bootargs/fixup adapters; '
              'no boot.img created, legacy default loader preserved')


if __name__ == '__main__':
    main()
