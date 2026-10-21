#!/usr/bin/env python3
"""Source-only macOS27 storage boot-gate regression and ARM64 build.

Builds outside the repository. Optional real 26A434 raw APFS images are
examined with a READ-ONLY 4096-byte read; never copied, mounted or modified.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ports/macos27/storage_boot_gate.c"
TEST = ROOT / "tests/test-macos27-storage-boot.c"
INCLUDE = ROOT / "ports/macos27"
REAL_IMAGES = (
    ROOT / "research/macos27-26A434/decrypted-os/043-70867-640.dmg",
    ROOT / "research/macos27-26A434/decrypted-system-cryptex/043-70701-651.dmg",
)


def run(*args: str, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=ROOT, check=True, env=env)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-real-images", action="store_true",
                        help="skip optional saved 26A434 image headers")
    options = parser.parse_args(argv)
    cc = os.environ.get("CC", "clang")
    with tempfile.TemporaryDirectory(prefix="macos27-storage-boot-") as tmp:
        binary = str(Path(tmp) / "test-storage-boot")
        base = ("-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic")
        run(cc, *base, "-O1", "-g", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(INCLUDE),
            str(SOURCE), str(TEST), "-o", binary)
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        run(binary, env=env)

        if not options.no_real_images:
            for path in REAL_IMAGES:
                if path.is_file() and not path.is_symlink():
                    run(binary, str(path), env=env)
                else:
                    print("SKIP absent offline image:", path)

        cross = shutil.which("aarch64-linux-gnu-gcc")
        if cross:
            run(cross, *base, "-O2", "-ffreestanding", "-fno-builtin", "-c",
                "-I", str(INCLUDE), str(SOURCE), "-o",
                str(Path(tmp) / "storage-boot-arm64.o"))
            print("PASS: AArch64 freestanding compile")
        else:
            print("SKIP: aarch64-linux-gnu-gcc not installed")

    print("PASS: macOS27 storage boot gate host sanitizers and offline probes")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as exc:
        print(f"FAIL: command returned {exc.returncode}", file=sys.stderr)
        sys.exit(exc.returncode or 1)
