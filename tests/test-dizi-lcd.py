#!/usr/bin/env python3
"""Reproducible host-only tests of the actual 0103 dizi LCD patch sources.

Does not access POCO Pad, touch GPIO, backlight, SPI or other device nodes.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "xnu/patches/0103-dizi-lcd-power.patch"
TEST = ROOT / "tests/dizi_lcd_test.c"
SOURCES = {"bsd/dev/sweet_lcd.c", "bsd/dev/sweet_lcd.h"}


def extract_additions(patch):
    result = {name: [] for name in SOURCES}
    current = None
    for line in patch.splitlines(keepends=True):
        if line.startswith("diff --git "):
            current = None
        elif line.startswith("+++ b/"):
            target = line[6:].strip()
            current = target if target in SOURCES else None
        elif current and line.startswith("+") and not line.startswith("+++"):
            result[current].append(line[1:])
        elif current and line.startswith((" ", "-")):
            raise ValueError("LCD implementation no longer added atomically")
    if not all(result.values()):
        raise ValueError("Missing new LCD files")
    return result


def main():
    sources = extract_additions(PATCH.read_text())
    native = "".join("".join(lines) for lines in sources.values())
    for forbidden in ("ml_io_map", "writel(", "GPIO98 =", "fastboot", "gpio_direction_output"):
        assert forbidden not in native, forbidden
    with tempfile.TemporaryDirectory(prefix="dizi-lcd-test-") as d:
        temp = Path(d)
        for name, lines in sources.items():
            (temp / Path(name).name).write_text("".join(lines))
        clang = os.environ.get("CC", "cc")
        subprocess.run([
            clang, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            str(temp / "sweet_lcd.c"), str(TEST), "-I", str(temp),
            "-o", str(temp / "test")
        ], check=True)
        subprocess.run([str(temp / "test")], check=True,
                       env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"})
    print("PASS 0103 LCD state-machine source extracted from real XNU patch")


if __name__ == "__main__":
    main()
