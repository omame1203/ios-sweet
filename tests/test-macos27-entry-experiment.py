#!/usr/bin/env python3
"""Offline macOS27 one-genuine-B instruction experiment audit.

This NEVER executes XNU, builds a device image or uses fastboot. Host mocks
test only mathematical exception matching and read-only bounds checking.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "shim/macos27_entry_experiment.c"
ASM = ROOT / "shim/macos27_entry_experiment.S"
HDR = ROOT / "shim/macos27_entry_experiment.h"
TEST = ROOT / "tests/test-macos27-entry-experiment.c"
REAL = (ROOT / "research/macos27-26A434/kernel.vma2.macho/"
        "kernelcache.release.vma2.decompressed")
PINNED = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203"
SIZE = 81444864
ENTRY = 48956544
BOOTSTRAP = 48971888
ARMED = ["-DDIZI_MACOS27_XNU_ENTRY_EXPERIMENT=1",
         "-DMAC27_ENTRY_EXPERIMENT_HANDLER_WIRED=1"]


def run(args: list[str], **kwargs) -> str:
    return subprocess.run(args, check=True, capture_output=True,
                          text=True, **kwargs).stdout


def genuine_source() -> None:
    if not REAL.is_file():
        print("SKIP genuine private KC absent; compile, synthetic rejects still tested")
        return
    assert REAL.stat().st_size == SIZE
    with REAL.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == PINNED
        f.seek(ENTRY)
        assert f.read(4) == bytes.fromhex("fc0e0014")
        f.seek(BOOTSTRAP)
        assert f.read(4) == bytes.fromhex("9f1010d5")
    print("PASS actual 26A434 raw 81,444,864-byte KC SHA256 and entry B/OSLAR words")


def host(tmp: Path) -> None:
    cc = shutil.which("gcc") or shutil.which("clang")
    assert cc, "host C compiler needed"
    binary = tmp / "mac27-host-trap"
    run([cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
         "-pedantic", "-fsanitize=undefined,address", "-fno-omit-frame-pointer",
         "-fno-sanitize-recover=all", str(SRC), str(TEST), "-o", str(binary)])
    print(run([str(binary)]).strip())


def aarch64(tmp: Path) -> None:
    gcc = shutil.which("aarch64-linux-gnu-gcc")
    dump = shutil.which("aarch64-linux-gnu-objdump")
    nm = shutil.which("aarch64-linux-gnu-nm")
    if not gcc or not dump or not nm:
        print("SKIP AArch64 GNU cross compiler/objdump/nm unavailable")
        return
    flags = ["-ffreestanding", "-nostdlib", "-fno-builtin", "-fno-pic",
             "-mstrict-align", "-mgeneral-regs-only", "-fno-stack-protector",
             "-O2", "-Wall", "-Wextra", "-Werror"]
    for macros in ([], [ARMED[0]], [ARMED[1]], ARMED):
        name = "enabled" if len(macros) == 2 else "off" + str(len(macros)) + (
            "x" if macros and macros[0] == ARMED[1] else "")
        cobj = tmp / f"{name}.o"
        sobj = tmp / f"{name}.asm.o"
        run([gcc, *flags, "-std=c11", *macros, "-c", str(SRC), "-o", str(cobj)])
        run([gcc, *macros, "-c", str(ASM), "-o", str(sobj)])
        names = run([nm, "-g", str(sobj)])
        if len(macros) != 2:
            assert "mac27_entry_experiment_trampoline" not in names, names
            assert "mac27_entry_experiment_resume" not in names, names
            assert "mac27_entry_experiment_run" in run([nm, "-g", str(cobj)])
            continue
        assert "mac27_entry_experiment_trampoline" in names
        assert "mac27_entry_experiment_resume" in names
        dis = run([dump, "-dr", str(sobj)])
        # Six instructions: prologue, original KC entry jump, resume & ret.
        instructions = re.findall(r"^\s*[0-9a-f]+:\s*[0-9a-f]{8}\s+([^\n]+)",
                                  dis, flags=re.MULTILINE)
        assert len(instructions) == 6, instructions
        assert sum("br\tx1" in i for i in instructions) == 1, instructions
        assert not any(re.search(r"\b(?:blr|bl|hvc|smc|autda|oslar)\b", i)
                       for i in instructions), instructions
        assert "msr\telr_el1" in run([dump, "-d", str(cobj)]).lower(), (
            "hook must permit exact ELR_EL1 rewrite")
        reloc = run(["aarch64-linux-gnu-readelf", "-r", str(cobj), str(sobj)])
        assert "R_AARCH64_ABS64" not in reloc, reloc
    print("PASS AArch64 dual-opt-in required; one BR x1 to original B; "
          "resume label and guarded ELR_EL1 write; no absolute relocation")


def sources() -> None:
    header = HDR.read_text()
    c = SRC.read_text()
    asm = ASM.read_text()
    assert PINNED == "".join(re.findall(r"0x([0-9a-f]{2})", c[c.index("static const uint8_t pinned"):].split("};", 1)[0]))
    assert "MAC27_EXPERIMENT_ESR" in header
    assert "mac27_entry_experiment_match_brk" in c
    assert "active_trap.armed = 1" in c
    assert "*bootstrap = MAC27_EXPERIMENT_BRK_WORD" in c
    assert "dc cvau" in c and "ic ivau" in c
    assert "br x1" in asm and "mac27_entry_experiment_resume" in asm
    assert "DIZI_MACOS27_XNU_ENTRY_EXPERIMENT" in c and "MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED" in c


if __name__ == "__main__":
    sources()
    genuine_source()
    with tempfile.TemporaryDirectory(prefix="mac27-xnu-first-b-") as td:
        tmp = Path(td)
        host(tmp)
        aarch64(tmp)
    print("PASS source-only macOS27 XNU first-B execution experiment audit; "
          "NO real Apple instruction has been executed by these tests")
