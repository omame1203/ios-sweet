#!/usr/bin/env python3
"""Validate patch0106 host-only, including the header as authored in the patch.

No device/fastboot, no tracked XNU edits; compile in a temporary directory.
The existing BSD ue0 packet path must remain single-owned (IONetworkingFamily
is absent from this XNU tree). This tests gate logic and source invariants,
not USB enumeration, Apple networking userland integration or Internet.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "xnu/patches/0106-dizi-usb-io-networking.patch"

def added_file(patch: str, name: str) -> str:
    section = patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("diff --git ", 1)[0]
    assert "new file mode 100644" in section, name
    return "".join(line[1:] for line in section.splitlines(True)
                   if line.startswith("+") and not line.startswith("+++"))

def main() -> None:
    assert PATCH.is_file(), PATCH
    patch = PATCH.read_text()
    header = added_file(patch, "bsd/dev/dizi_usb_link.h")
    iokit = added_file(patch, "iokit/Kernel/arm/DiziUSBEthernet.cpp")
    assert "struct dizi_usb_link" in header and "dizi_usb_link_reset" in header
    assert "s->enabled && s->attached && s->connected && s->configured && s->alt == 1" in header
    assert "class DiziUSBECMController final : public IOService" in iokit
    assert "IONetworkController :" not in iokit
    assert "ifnet_allocate" not in iokit and "ifnet_attach" not in iokit
    assert "ml_io_map(" not in iokit and "dwc_wr(" not in iokit
    assert "DiziUSBECMInternetVerified" in iokit
    assert 'extern "C" bool dizi_usb_ecm_publish' in iokit
    assert 'extern "C" void dizi_usb_ecm_link' in iokit
    assert 'diziusbnet' in patch and 'bridge == 0' in patch
    assert 'dizi_link.enabled = (dizi == 1 && hw == 1 && bridge == 1 && enabled >= 2)' in patch
    assert 'dizi_link.attached = true; /* ifnet_attach succeeded above */' in patch
    assert '__atomic_load_n(&dizi_link_carrier, __ATOMIC_ACQUIRE)' in patch
    assert '__atomic_store_n(&dizi_link_carrier, carrier, __ATOMIC_RELEASE)' in patch
    assert 'dizi_usb_link_reset(&dizi_link)' in patch
    assert 'DiziUSBEthernet.cpp' in patch
    assert patch.count('ifnet_allocate_extended(&init, &ud.ifp)') == 0  # no second DLIL allocation
    print("PASS: offline policy, C ABI, single BSD ifnet, no controller impostor/MMIO")
    compiler = shutil.which("clang") or shutil.which("cc")
    assert compiler, "a host C compiler is needed"
    with tempfile.TemporaryDirectory(prefix="dizi-usbnet-test-") as root:
        tmp = Path(root)
        (tmp / "dizi_usb_link.h").write_text(header)
        source = ROOT / "tests/test-dizi-usb-link.c"
        cmd = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wconversion",
               "-Wpedantic", "-I", str(tmp), str(source), "-o", str(tmp / "test")]
        if "clang" in Path(compiler).name:
            cmd.extend(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])
        subprocess.run(cmd, check=True, cwd=ROOT)
        subprocess.run([str(tmp / "test")], check=True, cwd=ROOT,
                       env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"})
    print("PASS: standalone compiled host C checks")

if __name__ == "__main__":
    main()
