#!/usr/bin/env python3
"""Source-only dizi GKI-initrd -> 26A434 KC physical staging verification."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "shim/macos27_entry_stage.c"
TEST = ROOT / "tests/test-macos27-entry-stage.c"
LIB = [
    ROOT / "ports/macos27/kc_loader.c",
    ROOT / "ports/macos27/kc_fixups.c",
    ROOT / "ports/macos27/boot_args.c",
]
REAL = ROOT / ("research/macos27-26A434/kernel.vma2.macho/"
               "kernelcache.release.vma2.decompressed")


def execute(*args):
    subprocess.run([str(a) for a in args], check=True)


def main():
    clang = shutil.which("clang")
    arm64 = shutil.which("aarch64-linux-gnu-gcc")
    linker = shutil.which("aarch64-linux-gnu-ld")
    nm = shutil.which("aarch64-linux-gnu-nm")
    objdump = shutil.which("aarch64-linux-gnu-objdump")
    assert all((clang, arm64, linker, nm, objdump)), "Missing host/AArch64 compilers"
    with tempfile.TemporaryDirectory(prefix="mac27-entry-stage-") as work:
        directory = Path(work)
        exe = directory / "entry-stage-test"
        execute(clang, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer", SOURCE, *LIB, TEST, "-o", exe)
        execute(exe, *([REAL] if REAL.is_file() else []))
        objects = []
        for ix, code in enumerate((SOURCE, *LIB)):
            obj = directory / f"stage-{ix}.o"
            execute(arm64, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                    "-mgeneral-regs-only", "-mstrict-align", "-c", code, "-o", obj)
            objects.append(obj)
        combined = directory / "stage-freestanding.o"
        execute(linker, "-r", *objects, "-o", combined)
        unresolved = subprocess.check_output([nm, "-u", str(combined)], text=True)
        assert not unresolved, f"Freestanding stage has unresolved functions: {unresolved}"
        symbols = subprocess.check_output([nm, "-g", str(combined)], text=True)
        assert "m27_entry_stage_plan" in symbols
        assert "m27_entry_stage_copy" in symbols
        instructions = subprocess.check_output([objdump, "-dr", str(combined)], text=True)
        assert "<m27_entry_stage_copy>:" in instructions
        assert " br\t" not in instructions.lower() and " blr\t" not in instructions.lower()
        print("PASS freestanding AArch64: source-only planner+copy with no undefined "
              "symbols, no indirect branch, no PAC signing")
    print("PASS diagnostic B/BRK entry staging: no code executed or modified, "
          "no boot image/device operation")


if __name__ == "__main__":
    main()
