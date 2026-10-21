#!/usr/bin/env python3
"""Reproducible, source-only GPI 0117 sanitizer/ARM64 checks.

No device access, DMA commands, MMIO, CI mutation, or repository writes.
The test extracts the original 0102 allocator source from its historical
patch, so it does not require a staged XNU checkout.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
PORT = ROOT / "ports/dizi"
PATCHES = ROOT / "xnu/patches"


def patch_new_file(patch: Path, filename: str) -> str:
    """Recover exactly one newly added bsd/dev file without applying a patch."""
    prefix = f"diff --git a/bsd/dev/{filename} b/bsd/dev/{filename}"
    lines = patch.read_text(encoding="utf-8").splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip("\n") == prefix]
    if len(starts) != 1:
        raise AssertionError(f"expected one new file {filename} in {patch}")
    pos = starts[0]
    if lines[pos + 1].strip() != "new file mode 100644":
        raise AssertionError(f"{filename} is not a new source file")
    expected = f"+++ b/bsd/dev/{filename}"
    while pos < len(lines) and lines[pos].strip() != expected:
        pos += 1
    if pos == len(lines):
        raise AssertionError(f"missing new-file header for {filename}")
    pos += 1
    chunks: list[str] = []
    while pos < len(lines) and not lines[pos].startswith("diff --git "):
        line = lines[pos]
        if line.startswith("+"):
            chunks.append(line[1:])
        elif line.startswith(("@@ ", "\\ No newline")):
            pass
        else:
            raise AssertionError(f"unexpected patch record for {filename}: {line!r}")
        pos += 1
    return "".join(chunks)


def execute(argv: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(argv), flush=True)
    subprocess.run(argv, cwd=ROOT, env=env, check=True)


def main() -> None:
    patch0117 = PATCHES / "0117-dizi-gpi-dma-transport.patch"
    with tempfile.TemporaryDirectory(prefix="dizi-gpi-0117-") as temp:
        folder = Path(temp)
        for name in ("dizi_smmu_dma.h", "dizi_smmu_dma.c"):
            source = patch_new_file(PATCHES / "0102-dizi-smmu-dma-foundation.patch", name)
            (folder / name).write_text(source, encoding="utf-8")
        for name in ("gpi_transport_0117.h", "gpi_transport_0117.c"):
            embedded = patch_new_file(patch0117, name)
            local = (PORT / name).read_text(encoding="utf-8")
            if embedded != local:
                raise AssertionError(f"0117 XNU patch and portable {name} differ")

        compiler = os.environ.get("CC", "clang")
        common = [
            "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(folder), "-I", str(PORT),
        ]
        binary = folder / "gpi_0117_test"
        execute([
            compiler, *common, "-g", "-O1", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            str(PORT / "tests/gpi_transport_0117_test.c"),
            str(PORT / "gpi_transport_0117.c"),
            str(PORT / "smmu_owner_0114.c"),
            str(folder / "dizi_smmu_dma.c"),
            "-o", str(binary),
        ])
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        execute([str(binary)], env=env)

        cross = shutil.which("aarch64-linux-gnu-gcc")
        if cross:
            execute([
                cross, *common, "-O2", "-c", str(PORT / "gpi_transport_0117.c"),
                "-o", str(folder / "gpi_transport_0117.aarch64.o"),
            ])
        else:
            print("ARM64 GCC unavailable; native XNU ARM64 build must validate cross target")

    print("PASS: 0117 portable sanitizer tests and XNU patch parity (software only)")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
