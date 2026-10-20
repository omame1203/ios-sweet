#!/usr/bin/env python3
"""Offline 0116 test: patch applies, BOE source evidence, gated IO mocks."""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCH = ROOT / "xnu/patches/0116-dizi-lcd-backlight-ownership.patch"
PORTABLE = ROOT / "ports/dizi/lcd_backlight_owner_0116.h"
TEST = ROOT / "tests/dizi_lcd_backlight_owner_0116.c"
STAGED = ROOT / "research/dizi-ci0106/xnu"


def run(argv: list[str], cwd: pathlib.Path | None = None) -> None:
    subprocess.run(argv, cwd=cwd, check=True)


def source_evidence() -> None:
    fdt_path = ROOT / "research/ipad5/dizi-live.dts"
    if not fdt_path.exists():
        print("lcd 0116: optional vendor FDT not present (patch mock tests still run)")
        return
    fdt = fdt_path.read_text()
    match = re.search(
        r"qcom,mdss_dsi_n83_35_02_0a_wqxga_video_cphy\s*\{(.*?)"
        r"qcom,mdss-dsi-display-timings\s*\{", fdt, re.S
    )
    assert match, "BOE panel node not in saved FDT"
    node = match.group(1)
    for fact in (
        "qcom,platform-bklight-en-gpio = <0x147 0x39 0x00>",
        "qcom,platform-reset-gpio = <0x147 0x62 0x00>",
        'qcom,mdss-dsi-bl-pmic-control-type = "bl_ctrl_external"',
        "qcom,mdss-dsi-bl-max-level = <0xfff>",
        "qcom,panel-supply-entries = <0x5ef>",
    ):
        assert fact in node, fact
    assert "qcom,supply-name = \"dummy\"" in re.search(
        r"dsi_panel_pwr_supply_sim\s*\{(.*?)\n\s*\};\n\s*dsi_panel_pwr_supply_lcd", fdt, re.S
    ).group(1)
    assert "qcom,dsi-default-panel = <0x5f5>" in fdt
    print("lcd 0116: BOE FDT GPIO57/98, external BL, dummy panel supply verified")


def main() -> None:
    source_evidence()
    assert PATCH.exists() and PORTABLE.exists() and TEST.exists()
    assert STAGED.exists(), "Existing CI source tree needed for XNU patch apply"
    with tempfile.TemporaryDirectory(prefix="dizi-lcd-0116-") as dirname:
        base = pathlib.Path(dirname)
        for rel in (
            "iokit/Kernel/arm/SweetFramebuffer.cpp",
            "bsd/dev/sweet_lcd.c", "bsd/dev/sweet_lcd.h",
        ):
            dest = base / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(STAGED / rel, dest)

        run(["git", "apply", "--check", str(PATCH)], cwd=base)
        run(["git", "apply", str(PATCH)], cwd=base)
        xnu_header = base / "bsd/dev/sweet_lcd_owner_0116.h"
        assert xnu_header.read_bytes() == PORTABLE.read_bytes(), "XNU/host header drift"
        cpp = (base / "iokit/Kernel/arm/SweetFramebuffer.cpp").read_text()
        assert "dizi_lcd_owner_0116_black_frame_done(" in cpp
        assert "dizi_lcd_owner_0116_request(" in cpp
        assert cpp.count("&fb->fDiziLCDOwner, generation, NULL, NULL") == 1
        assert cpp.count("&fFB->fDiziLCDOwner, off, NULL, NULL") == 1
        assert "DiziLCDPhysicalBacklightAvailable\", kOSBooleanFalse" in cpp
        assert "fFB->fFadeEpoch++" in cpp

        exe = base / "test-0116"
        clang = shutil.which("clang")
        assert clang is not None, "host clang missing"
        san = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        run([clang, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             *san, "-I", str(base / "bsd/dev"), "-I", str(PORTABLE.parent),
             str(base / "bsd/dev/sweet_lcd.c"), str(TEST), "-o", str(exe)])
        run([str(exe)])

        # A real ARM64 Apple Mach-O object is possible without needing to
        # emulate a peripheral: compile the same hardware-free C model.
        resource = subprocess.check_output([clang, "-print-resource-dir"], text=True).strip()
        object_file = base / "sweet_lcd_0116.arm64.o"
        run([clang, "-target", "arm64-apple-darwin", "-nostdinc",
             "-isystem", str(pathlib.Path(resource) / "include"), "-std=c11",
             "-Wall", "-Wextra", "-Werror", "-I", str(base / "bsd/dev"),
             "-c", str(base / "bsd/dev/sweet_lcd.c"), "-o", str(object_file)])
        assert "Mach-O" in subprocess.check_output(["file", str(object_file)], text=True)

        # Header and bridge are valid for both ARM64 C and C++ translation units.
        bridge = base / "bridge_0116.c"
        bridge.write_text(
            '#include "sweet_lcd_owner_0116.h"\n'
            'int check(struct dizi_lcd_owner_0116 *o) {\n'
            'return (int)dizi_lcd_owner_0116_missing(o, 0, 0); }\n'
        )
        run([clang, "-target", "arm64-apple-darwin", "-nostdinc",
             "-isystem", str(pathlib.Path(resource) / "include"), "-std=c11",
             "-Wall", "-Wextra", "-Werror", "-I", str(base / "bsd/dev"),
             "-c", str(bridge), "-o", str(base / "bridge_0116.arm64.o")])
        cpp_bridge = base / "bridge_0116.cpp"
        cpp_bridge.write_text(bridge.read_text())
        run([shutil.which("clang++") or "clang++", "-target", "arm64-apple-darwin",
             "-nostdinc", "-isystem", str(pathlib.Path(resource) / "include"),
             "-std=c++17", "-Wall", "-Wextra", "-Werror",
             "-I", str(base / "bsd/dev"), "-c", str(cpp_bridge),
             "-o", str(base / "bridge_0116_cpp.arm64.o")])
    print("lcd 0116: patch applies, XNU hook guarded, ASan/UBSan and ARM64 Mach-O pass")


if __name__ == "__main__":
    main()
