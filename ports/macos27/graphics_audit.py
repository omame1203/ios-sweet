#!/usr/bin/env python3
"""Source- and symbol-grounded POCO Pad -> macOS 27 graphics readiness inventory.

Read-only. Does not use MMIO, fastboot, adb, hardware, /dev, kernel loading,
macOS binaries or dynamically execute untrusted extracted kernel code.
The report deliberately distinguishes:
    - source-level iPadOS16 mobile graphics implementation,
    - actual symbols in an optional compiled XNU Mach-O,
    - known Qualcomm hardware identity from a local FDT,
    - completely unproven macOS27 WindowServer/Metal/IOGraphics contracts.
It NEVER reports boot success. Hardware witnesses require separate integration.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

CAPS = (
    "FB_LAYOUT", "SCANOUT_OWNER", "IOFRAMEBUFFER", "IOFB_SERVER",
    "DISPLAY_MODES", "FRAME_COMPLETION", "IOSURFACE_27", "DISPLAY_PIPELINE",
    "WINDOWSERVER", "HID_POINTER", "HID_KEYBOARD", "GPU_DRIVER",
    "IOACCELERATOR", "METAL_DEVICE", "GPU_MEMORY", "GPU_SCHEDULER",
    "POWER_LIFECYCLE",
)
LEGACY = (
    "BOOT_FB", "IOMOBILE_FB", "IOSURFACE_16", "CPU_COPY", "TIMER_VSYNC",
    "MOBILE_TOUCH", "CONSUMER_KEYS", "SW_BLACK_ONLY", "ADRENO_FDT",
)

# Static desktop ABI requirements are chosen conservatively for an
# *accelerated desktop readiness trial*, not claimed to be the only possible
# macOS startup path, nor a claim that every Mac uses a DCP chip.
DESKTOP_BITS = (0, 1, 2, 3, 4, 5, 6, 7, 16)
WINDOWSERVER_BITS = (*DESKTOP_BITS, 8, 9, 10)
ACCELERATED_BITS = (*WINDOWSERVER_BITS, 11, 12, 13, 14, 15)

def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""

def source_or_patch(root: Path, xnu_rel: str, patch_rel: str) -> tuple[str, str]:
    direct = root / "research/dizi-ci0106/xnu" / xnu_rel
    if direct.is_file():
        return read_text(direct), "ignored CI0106 source"
    candidate = root / "xnu/patches" / patch_rel
    return read_text(candidate), "tracked source patch" if candidate.is_file() else "missing"

def check_symbols(root: Path, version: str) -> dict:
    kernel = root / f"xnu/out-{version}/kernel.development.sweet"
    nm = shutil.which("llvm-nm")
    if not kernel.is_file() or not nm:
        return {"available": False, "reason": "optional ignored kernel or llvm-nm missing"}
    try:
        p = subprocess.run([nm, "-g", str(kernel)], text=True,
                           capture_output=True, timeout=20, check=True)
    except (subprocess.SubprocessError, OSError) as exc:
        return {"available": False, "reason": f"symbol audit unavailable: {type(exc).__name__}"}
    symbols = p.stdout
    return {
        "available": True,
        "examined": f"xnu/out-{version}/kernel.development.sweet",
        "built_in_mobile_framebuffer": "__ZN19IOMobileFramebuffer10gMetaClassE" in symbols,
        "built_in_core_surface_root": "__ZN17IOCoreSurfaceRoot10gMetaClassE" in symbols,
        "built_in_touch_service": "__ZN13SweetHIDTouch10gMetaClassE" in symbols,
        "built_in_desktop_ioframebuffer": "__ZN13IOFramebuffer10gMetaClassE" in symbols,
        "built_in_ioaccelerator": "__ZN13IOAccelerator10gMetaClassE" in symbols,
    }

def audit(root: Path, version: str = "0116") -> dict:
    fb, fb_origin = source_or_patch(
        root, "iokit/Kernel/arm/SweetFramebuffer.cpp",
        "0046-sweet-iosurface-iomfb.patch")
    surf, surf_origin = source_or_patch(
        root, "iokit/Kernel/arm/SweetSurface.cpp",
        "0046-sweet-iosurface-iomfb.patch")
    hid, hid_origin = source_or_patch(
        root, "iokit/Kernel/arm/hid/SweetHID.cpp",
        "0058-sweet-hid-event-services.patch")
    power = read_text(root / "xnu/patches/0116-dizi-lcd-backlight-ownership.patch")
    # The 0116 patch is current kernel-only source, not an actual panel
    # ownership witness; no DCP, scanout allocator or GPU driver is added.
    fdt = read_text(root / "research/ipad5/dizi-live.dts")
    if not fdt:
        fdt = read_text(root / "backup/dizi/live.dts")
    detected_adreno = re.search(r'qcom,gpu-model\s*=\s*"([^"]+)"', fdt)
    mobile_fb = "class IOMobileFramebuffer : public IOService" in fb
    surface_root = "class IOCoreSurfaceRoot : public IOService" in surf
    features = {
        "BOOT_FB": "PE_current_console(&video)" in fb and "video.v_rowBytes" in fb,
        "IOMOBILE_FB": mobile_fb and "class AppleCLCD : public IOMobileFramebuffer" in fb,
        "IOSURFACE_16": surface_root and "IOSurfaceRootUserClient" in surf,
        "CPU_COPY": "memcpy((void *)(fPixels +" in fb or "SwapEnd copies" in fb,
        "TIMER_VSYNC": "IOTimerEventSource::timerEventSource" in fb,
        "MOBILE_TOUCH": "class SweetHIDTouch : public IOHIDEventService" in hid,
        "CONSUMER_KEYS": "class SweetHIDButtons : public IOHIDEventService" in hid,
        "SW_BLACK_ONLY": "DiziLCDPhysicalBacklightAvailable" in power and
                         "missing-hardware-witness" in power,
        "ADRENO_FDT": bool(detected_adreno),
    }
    source_bits = ["FB_LAYOUT"] if features["BOOT_FB"] else []
    symbols = check_symbols(root, version)
    # The source reports neither a genuine IOFramebuffer provider nor a
    # separately implemented IOGraphics/IOAccelerator user-client. A mere
    # stub typedef or 'IOMobileFramebuffer' is not source implementation.
    source_ioframebuffer = bool(re.search(r"\bclass\s+IOFramebuffer\s*[:{]", fb))
    source_accelerator = bool(re.search(r"\bclass\s+IOAccelerator\s*[:{]", fb))
    if source_ioframebuffer:
        source_bits.append("IOFRAMEBUFFER")
    if source_accelerator:
        source_bits.append("IOACCELERATOR")
    blockers = {
        "IOGraphics": "0116 implements a private iOS16 IOMobileFramebuffer IOService; "
                      "no source-confirmed desktop IOFramebuffer or IOFBServerConnectType ABI",
        "IOSurface": "0116 IOCoreSurfaceRoot is a reverse-engineered iOS16 subset; "
                     "macOS27 IOSurface user-client lifetime/protocol has not been tested",
        "WindowServer": "no macOS27 WindowServer/CoreDisplay mode, cursor, user-client "
                        "or display-server handshake demonstrated",
        "GPU": "Qualcomm Adreno GPU is listed in the dizi firmware tree but "
               "no proven XNU Adreno driver, IOAccelerator/Metal/VM/fence path; "
               "Apple AGX drivers cannot be assumed compatible",
        "DCP": "Apple-silicon DCP is not the Qualcomm display engine; an "
               "independently verified equivalent macOS desktop scanout path is required",
        "panel": "inherited boot framebuffer and 0116 software blacking are not "
                 "evidence of DSI/rail/backlight/clock ownership, safe modes or actual VSYNC",
        "input": "existing iOS16 digitizer and consumer keys do not establish "
                 "a macOS desktop pointer, keyboard or cursor event driver",
    }
    source_mask = sum(1 << i for i, k in enumerate(CAPS) if k in source_bits)
    legacy_mask = sum(1 << i for i, k in enumerate(LEGACY) if features[k])
    missing_desktop = [CAPS[i] for i in DESKTOP_BITS if CAPS[i] not in source_bits]
    missing_window = [CAPS[i] for i in WINDOWSERVER_BITS if CAPS[i] not in source_bits]
    missing_accel = [CAPS[i] for i in ACCELERATED_BITS if CAPS[i] not in source_bits]
    # There is NO runtime proof collector in this tool. Never use optional
    # iPadOS GUI observations as macOS27 desktop witness or set ready=true.
    return {
        "target": "macOS 27 Golden Gate on POCO Pad dizi (SM7435)",
        "kind": "static source/symbol audit; NOT a macOS boot or runtime test",
        "kernel_examined": version,
        "source_origins": {"framebuffer": fb_origin, "surface": surf_origin,
                           "hid": hid_origin},
        "macos27_boot_claimed": False,
        "macos27_windowserver_seen": False,
        "legacy_implemented": [k for k in LEGACY if features[k]],
        "legacy_bitmask": legacy_mask,
        "source_capabilities": source_bits,
        "source_bitmask": source_mask,
        "runtime_proof_bitmask": 0,
        "display_candidate": False,
        "windowserver_candidate": False,
        "accelerated_candidate": False,
        "desktop_display_missing_source_proofs": missing_desktop,
        "windowserver_missing_source_proofs": missing_window,
        "accelerated_missing_source_proofs": missing_accel,
        "gpu_model_static_fdt": detected_adreno.group(1) if detected_adreno else None,
        "gpu_identity_evidence": "firmware FDT only" if detected_adreno else "not available",
        "nominal_layout_example_only": {
            "panel": [1600, 2560], "canvas": [1536, 2048],
            "centered_canvas_origin": [-32, -256],
            "physical_stride": None, "physical_extent": None,
            "source": "0116 XNU source defaults; NOT a measured framebuffer mapping",
        },
        "linked_kernel_symbols": symbols,
        "blockers": blockers,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2],
                        help="ios-pocopad checkout root; no device access")
    parser.add_argument("--kernel", default="0116",
                        help="optional LOCAL ignored xnu/out-NNNN Mach-O label")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{4}", args.kernel):
        parser.error("--kernel requires exactly four decimal digits")
    print(json.dumps(audit(args.root.resolve(), args.kernel),
                     indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
