#!/usr/bin/env python3
"""Standalone macOS27/POCO Pad graphics preflight regression test.

No live kernel access, device commands, MMIO, modifications to tracked files,
or claim that macOS27/WindowServer has been installed or booted.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GFX = ROOT / "ports/macos27"


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def basic_audit(root: Path, expect_legacy: bool = True,
                expect_ioframebuffer_missing: bool = True):
    p = run(["python3", str(GFX / "graphics_audit.py"), "--root", str(root),
             "--kernel", "0116"], text=True, capture_output=True)
    result = json.loads(p.stdout)
    assert result["target"] == "macOS 27 Golden Gate on POCO Pad dizi (SM7435)"
    assert result["macos27_boot_claimed"] is False
    assert result["macos27_windowserver_seen"] is False
    assert result["display_candidate"] is False
    assert result["windowserver_candidate"] is False
    assert result["accelerated_candidate"] is False
    assert result["runtime_proof_bitmask"] == 0
    if expect_legacy:
        for feature in ("BOOT_FB", "IOMOBILE_FB", "IOSURFACE_16", "CPU_COPY",
                        "TIMER_VSYNC", "MOBILE_TOUCH", "CONSUMER_KEYS",
                        "SW_BLACK_ONLY"):
            assert feature in result["legacy_implemented"], feature
    if expect_ioframebuffer_missing:
        assert "IOFRAMEBUFFER" in result["desktop_display_missing_source_proofs"]
    assert "IOFB_SERVER" in result["desktop_display_missing_source_proofs"]
    assert "IOSURFACE_27" in result["desktop_display_missing_source_proofs"]
    assert "METAL_DEVICE" in result["accelerated_missing_source_proofs"]
    assert "GPU_DRIVER" in result["accelerated_missing_source_proofs"]
    assert result["nominal_layout_example_only"] == {
        "panel": [1600, 2560], "canvas": [1536, 2048],
        "centered_canvas_origin": [-32, -256],
        "physical_stride": None, "physical_extent": None,
        "source": "0116 XNU source defaults; NOT a measured framebuffer mapping",
    }
    return result


def main():
    compiler = os.environ.get("CLANG", "clang")
    c = GFX / "graphics_readiness.c"
    h = GFX / "graphics_readiness.h"
    py = GFX / "graphics_audit.py"
    test = ROOT / "tests/test-macos27-graphics.c"
    for path in (c, h, py):
        assert path.exists()
    source = c.read_text() + h.read_text()
    for forbidden in ("ml_io_map(", "ioremap(", "volatile uint32_t *",
                      "fastboot ", "adb ", "IOConnectCallMethod(", "writel("):
        assert forbidden not in source
    assert "IOFramebuffer" in source and "IOAccelerator" in source
    assert "M27_GFX_ACCELERATED_REQUIRED" in source
    assert "m27_graphics_copy_plan" in source
    assert "m27_graphics_known_dizi_0116" in source
    real = basic_audit(ROOT)
    print("PASS static 0116 source audit: iOS16 mobile framebuffer/IOSurface "
          "not native macOS27 IOGraphics; no WindowServer/boot claim")

    # Optional actual Mach-O is linked XNU only. Absence of a built-in
    # OSMetaClass doesn't rule out a future dynamically loaded driver.
    symbols = real["linked_kernel_symbols"]
    if symbols["available"]:
        assert symbols["built_in_mobile_framebuffer"] is True
        assert symbols["built_in_core_surface_root"] is True
        assert symbols["built_in_touch_service"] is True
        assert symbols["built_in_desktop_ioframebuffer"] is False
        assert symbols["built_in_ioaccelerator"] is False
        print("PASS optional actual 0116 arm64 Mach-O XNU symbols: mobile "
              "IOService present; desktop IOFramebuffer/IOAccelerator absent")
    else:
        print("SKIP optional ignored 0116 Mach-O symbols absent in clean clone")

    fdt = ROOT / "research/ipad5/dizi-live.dts"
    if fdt.exists():
        assert real["gpu_model_static_fdt"] == "Adreno710v1"
        assert real["gpu_identity_evidence"] == "firmware FDT only"
        print("PASS optional locally observed dizi FDT Qualcomm Adreno710 "
              "(NOT compatible Apple AGX evidence)")
    else:
        print("SKIP optional ignored dizi live FDT absent in clean clone")

    with tempfile.TemporaryDirectory(prefix="macos27-graphics-test-") as tmp:
        t = Path(tmp)
        native = t / "gfx-test"
        run([compiler, "-std=c11", "-O1", "-g",
             "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-fno-sanitize-recover=all", str(c), str(test), "-o", str(native)])
        run([str(native)], env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"})
        print("PASS host ASan+UBSan: 17 independent gates, "
              "stride/crop/OOB guards, 110k hostile rectangles")
        obj = t / "gfx-aarch64.o"
        run([compiler, "--target=aarch64-none-elf", "-ffreestanding",
             "-nostdlib", "-std=c11", "-O2", "-Wall", "-Wextra",
             "-Werror", "-pedantic", "-c", str(c), "-o", str(obj)])
        assert obj.stat().st_size > 1000
        print("PASS freestanding AArch64 graphics policy and mapping object")

        # Emulate a git checkout without any of the ignored 'research' or
        # 'xnu/out-*' files; public tracked patches must suffice.
        clone = t / "clean-checkout"
        patches = (
            "0046-sweet-iosurface-iomfb.patch",
            "0058-sweet-hid-event-services.patch",
            "0116-dizi-lcd-backlight-ownership.patch",
        )
        for name in patches:
            origin = ROOT / "xnu/patches" / name
            target = clone / "xnu/patches" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, target)
        stripped = basic_audit(clone)
        assert stripped["linked_kernel_symbols"]["available"] is False
        assert stripped["gpu_model_static_fdt"] is None
        assert stripped["source_origins"]["framebuffer"] == "tracked source patch"
        assert stripped["source_origins"]["surface"] == "tracked source patch"
        assert stripped["source_origins"]["hid"] == "tracked source patch"
        assert stripped["runtime_proof_bitmask"] == 0
        print("PASS clean-checkout static validation without ignored "
              "vendor files, private tools, firmware or cached Mach-O")

        # No source is not interpreted as a working monitor/GPU either.
        empty = basic_audit(t / "missing-checkout", expect_legacy=False)
        assert empty["source_capabilities"] == []
        assert empty["legacy_implemented"] == []
        assert empty["accelerated_candidate"] is False
        print("PASS missing and incomplete source fails closed")

        # A future developer merely inserting an IOFramebuffer *class name*
        # must not turn into an official runtime WindowServer claim.
        future = clone / "xnu/patches/0046-sweet-iosurface-iomfb.patch"
        fixture = future.read_bytes()
        future.write_bytes(fixture + b"\n+class IOFramebuffer : public IOService {};\n")
        adversarial = basic_audit(clone, expect_ioframebuffer_missing=False)
        assert "IOFRAMEBUFFER" in adversarial["source_capabilities"]
        assert adversarial["runtime_proof_bitmask"] == 0
        assert not adversarial["display_candidate"]
        print("PASS fake/source-only IOFramebuffer definition cannot "
              "be promoted to macOS27 runtime readiness")

    print("PASS macOS27 graphics offline readiness suite: no device access "
          "or writes, no macOS27 boot assertion")

if __name__ == "__main__":
    main()
