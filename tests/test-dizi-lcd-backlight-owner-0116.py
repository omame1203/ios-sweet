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


def added_file(patch: pathlib.Path, name: str) -> str:
    """Get the complete real XNU newly-added source (no vendor blobs needed)."""
    section = patch.read_text().split(
        f"diff --git a/{name} b/{name}\n", 1
    )[1].split("diff --git ", 1)[0]
    assert "new file mode 100644" in section
    return "".join(line[1:] for line in section.splitlines(keepends=True)
                   if line.startswith("+") and not line.startswith("+++"))


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
    assert "qcom,platform-bklight-en-gpio = <0x147 0x39 0x00>" in re.search(
        r"qcom,mdss_dsi_n83_42_02_0b_wqxga_video_cphy\s*\{(.*?)"
        r"qcom,mdss-dsi-display-timings\s*\{", fdt, re.S
    ).group(1), "alternative CSOT panel has a different BL pin"
    primary = re.search(r"qcom,dsi-display-primary\s*\{(.*?)\n\s*\};", fdt, re.S).group(1)
    for supply in ("extvdd-supply = <0x4af>", "ibb-supply = <0x509>",
                   "vci-supply = <0x2b7>", "vddio-supply = <0x4ab>"):
        assert supply in primary, supply
    for rail, pmic_gpio in (("display_panel_vddio", "0x09"),
                           ("display_panel_avdd", "0x04"),
                           ("display_panel_extvdd", "0x03")):
        match = re.search(
            r'display_gpio_regulator@\d+\s*\{(.*?)regulator-name = "'
            + re.escape(rail) + r'"(.*?)\n\s*\};', fdt, re.S
        )
        assert match and f"gpio = <0x4aa {pmic_gpio} 0x00>" in match.group(2)
    print("lcd 0116: BOE/CSOT FDT GPIO57/98, dummy entry and display rails verified")


def main() -> None:
    source_evidence()
    assert PATCH.exists() and PORTABLE.exists() and TEST.exists()
    with tempfile.TemporaryDirectory(prefix="dizi-lcd-0116-") as dirname:
        base = pathlib.Path(dirname)
        if STAGED.exists():
            for rel in (
                "iokit/Kernel/arm/SweetFramebuffer.cpp",
                "bsd/dev/sweet_lcd.c", "bsd/dev/sweet_lcd.h",
            ):
                dest = base / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(STAGED / rel, dest)
            run(["git", "apply", "--check", str(PATCH)], cwd=base)
            run(["git", "apply", str(PATCH)], cwd=base)
            run(["git", "apply", "-R", "--check", str(PATCH)], cwd=base)
            cpp = (base / "iokit/Kernel/arm/SweetFramebuffer.cpp").read_text()
            print("lcd 0116: XNU 0109->0116 patch applies")
        else:
            # Clean git archive CI has no ignored vendor/CI0106 tree. Check
            # the actual two added 0103 sources and the 0116 patch additions.
            for name in ("bsd/dev/sweet_lcd.c", "bsd/dev/sweet_lcd.h"):
                dest = base / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(added_file(ROOT / "xnu/patches/0103-dizi-lcd-power.patch", name))
            dest = base / "bsd/dev/sweet_lcd_owner_0116.h"
            dest.write_text(added_file(PATCH, "bsd/dev/sweet_lcd_owner_0116.h"))
            cpp = PATCH.read_text()
            print("lcd 0116: isolated patch-source check (no ignored CI XNU tree)")

        xnu_header = base / "bsd/dev/sweet_lcd_owner_0116.h"
        assert xnu_header.read_bytes() == PORTABLE.read_bytes(), "XNU/host header drift"
        assert "dizi_lcd_owner_0116_black_frame_done(" in cpp
        assert "dizi_lcd_owner_0116_request(" in cpp
        assert cpp.count("&fb->fDiziLCDOwner, generation, NULL, NULL") == 1
        assert cpp.count("&fFB->fDiziLCDOwner, off, NULL, NULL") == 1
        assert "DiziLCDPhysicalBacklightAvailable\", kOSBooleanFalse" in cpp
        if STAGED.exists():
            assert "fFB->fFadeEpoch++" in cpp
        else:
            assert "fFB->fFadeEpoch++" in (
                ROOT / "xnu/patches/0109-dizi-lcd-generation-race.patch"
            ).read_text()

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
    print("lcd 0116: guarded XNU hook, ASan/UBSan and ARM64 Mach-O pass")


if __name__ == "__main__":
    main()
