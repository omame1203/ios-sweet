#!/usr/bin/env python3
"""Host-only 26A434 VMAPPLE startup handoff trace and fail-closed guard.

Never executes the Apple KC or touches a device, GPT, MMIO, fastboot, shim,
loader image, boot policy or Apple signatures. Produces no output files in
the working tree. Real KC/disassembly in ignored research/ is OPTIONAL.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
M27 = ROOT / "ports/macos27"
REAL = (ROOT / "research/macos27-26A434/kernel.vma2.macho" /
        "kernelcache.release.vma2.decompressed")
TRACE = ROOT / "research/macos27-26A434/vma2-start-disassembly.txt"
TRACE_TAIL = ROOT / "research/macos27-26A434/vma2-start-tail.txt"
SHA256 = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203"
COMPILE = ("entry_handoff_guard.c", "kc_loader.c", "kc_fixups.c",
           "boot_args.c")
HOST_TEST = ROOT / "tests/test-macos27-entry-handoff.c"


def run(argv, **kwargs):
    subprocess.run(argv, check=True, **kwargs)


def check_tracked_source():
    legacy = (ROOT / "shim/mmu.c").read_text()
    loader = (ROOT / "shim/loader.c").read_text()
    modern = (ROOT / "ports/macos27/boot_args.c").read_text()
    guard = (M27 / "entry_handoff_guard.c").read_text()
    required = ("ttbr0_el1", "tcr_el1", "sctlr_el1", "mmu_off(void)")
    assert all(x in legacy for x in required)
    assert "ttbr1_el1" not in legacy
    assert "sizeof(struct boot_args) == 736" in loader
    assert "offsetof(struct mac27_boot_args, boot_flags) == 0x470" in modern
    assert "M27_ENTRY_ALWAYS_BLOCKED" in guard
    assert "native_jump_allowed" not in guard  # report cleared as a whole
    assert "HVC #0" in guard
    assert "0xd4000002" in guard
    assert "0xdac11841" in guard
    assert "bl __" not in guard
    print("PASS legacy shim physical x0 / 736 bootargs; 26A434 offsets; "
          "separate TTBR0 vs TTBR1 and HVC guard, no entry invocation")


def check_real_trace():
    if not TRACE.is_file() or not TRACE_TAIL.is_file():
        print("SKIP ignored real VMAPPLE entry text unavailable")
        return
    text = TRACE.read_text() + "\n" + TRACE_TAIL.read_text()
    needle = [
        ("0xfffffe0009eb8070:", "oslar_el1"),
        ("0xfffffe0009eb8078:", "mov\tx20, x0"),
        ("0xfffffe0009eb808c:", "[x20, #0x8]"),
        ("0xfffffe0009eb8090:", "[x20, #0x10]"),
        ("0xfffffe0009eb8094:", "[x20, #0x18]"),
        ("0xfffffe0009eb809c:", "[x20, #0x470]"),
        ("0xfffffe0009eb82b0:", "tcr_el1"),
        ("0xfffffe0009eb82cc:", "ttbr1_el1"),
        ("0xfffffe0009eb834c:", "#0xc1000000"),
        ("0xfffffe0009eb8350:", "hvc\t#0"),
        ("0xfffffe0009eb8368:", "sctlr_el1"),
        ("0xfffffe0009eb8438:", "autda"),
    ]
    last = -1
    for address, instruction in needle:
        lines = [ln for ln in text.splitlines() if ln.startswith(address)]
        assert len(lines) == 1, address
        assert instruction in lines[0], (address, lines[0])
        index = text.find(lines[0])
        assert index > last, (address, "not increasing")
        last = index
    assert text.count("ttbr0_el1") == 0  # in the selected start trace
    print("PASS observed 26A434 first-stage order: x20 loads, TCR, TTBR1, "
          "HVC #0 x0=0xc1000000 BEFORE SCTLR, PAC AUTDA")


def check_real_digest():
    if not REAL.is_file():
        print("SKIP genuine decompressed 26A434 KC unavailable in fresh checkout")
        return False
    assert REAL.stat().st_size == 81444864
    with REAL.open("rb") as fd:
        digest = hashlib.file_digest(fd, "sha256").hexdigest()
    assert digest == SHA256, (digest, "unrecognized 26A434 KC")
    print("PASS actual decompressed 26A434 VMAPPLE KC SHA-256 pin, "
          "81,444,864 bytes; hash is NOT IMG4 signature attestation")
    return True


def compile_test(src: Path, clang: str, root: Path, target: str):
    obj = root / (src.stem + "-" + target.replace("-", "_") + ".o")
    run([clang, "--target=" + target, "-std=c11",
         "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
         "-ffreestanding", "-fno-builtin", "-nostdlib",
         "-c", str(src), "-o", str(obj)])
    assert obj.stat().st_size > 700


def real_checks(cc: str, tmp: Path, has_real: bool):
    host = tmp / "test-entry-handoff"
    run([cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
         "-Werror", "-pedantic", "-fsanitize=address,undefined",
         "-fno-omit-frame-pointer", "-fno-sanitize-recover=all",
         *[str(M27 / p) for p in COMPILE],
         str(HOST_TEST), "-o", str(host)])
    run([str(host)] + ([str(REAL)] if has_real else []),
        env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"})
    print("PASS host ASan+UBSan 120k spoof attempts and 14 opcode mutations "
          "(when real KC present), never Apple code execution")
    for target in ("aarch64-none-elf", "arm64-apple-macos14.0"):
        for name in COMPILE:
            compile_test(M27 / name, cc, tmp, target)
        print("PASS freestanding", target,
              "entry policy/KC parser/fixup/bootargs C object compilation")


def clean_checkout(cc: str, tmp: Path):
    # A fresh working tree has no proprietary ignored research/ files, and
    # the tests must fail closed without them, not fabricate a boot candidate.
    checkout = tmp / "clean"
    for f in COMPILE:
        src = M27 / f
        dst = checkout / "ports/macos27" / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    for name in ("entry_handoff_guard.h", "kc_loader.h",
                 "kc_fixups.h", "boot_args.h"):
        shutil.copyfile(M27 / name, checkout / "ports/macos27" / name)
    test = checkout / "tests/test-macos27-entry-handoff.c"
    test.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HOST_TEST, test)
    exe = tmp / "clean-host-test"
    run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
         "-O2", *[str(checkout / "ports/macos27" / n) for n in COMPILE],
         str(test), "-o", str(exe)])
    run([str(exe)])
    print("PASS clean checkout: self-contained C guard without ignored KC, "
          "no Apple binary or fake success")


def main():
    cc = os.environ.get("CLANG", "clang")
    check_tracked_source()
    check_real_trace()
    has_real = check_real_digest()
    with tempfile.TemporaryDirectory(prefix="m27-entry-handoff-offline-") as t:
        root = Path(t)
        real_checks(cc, root, has_real)
        clean_checkout(cc, root)
    print("PASS genuine macOS27 early entry preflight, BLOCKED, "
          "no device access/writes, no native boot claim")


if __name__ == "__main__":
    main()
