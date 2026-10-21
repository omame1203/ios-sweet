#!/usr/bin/env python3
"""Real 26A434 __PRELINK_INFO and XNU22 dizi IOKit compatibility tests.

This is source-only: no device commands, MMIO, driver loading, KC mutation,
or iPadOS/macOS boot claim. Test fixtures use synthetic metadata only.
"""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m27_iokit_metadata", ROOT / "ports/macos27/iokit_metadata.py")
assert SPEC and SPEC.loader
import sys
sys.path.insert(0, str(ROOT))
meta = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(meta)


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def sample_prelink(entries=None, **overrides):
    if entries is None:
        entries = [{"CFBundleIdentifier": f"org.test.kext.{i:04d}",
                    "IOKitPersonalities": {}} for i in range(100)]
    root = {"OSPrelinkInfoContainsUUIDs": True,
            "_PrelinkInfoDictionary": entries,
            "KMBuildVersion": "KernelManagement_TEST"}
    root.update(overrides)
    return plistlib.dumps(root, fmt=plistlib.FMT_XML)


class MetadataNegative(unittest.TestCase):
    def test_structural_corruption(self):
        raw = sample_prelink()
        self.assertEqual(len(meta.parse_prelink_xml(raw)), 100)
        for payload in [
            b"", b"untrusted", b"<?xml><plist></plist>",
            raw.replace(b"_PrelinkInfoDictionary", b"_PrelinkInfoDictianary"),
            raw[: len(raw)//2],
            raw + raw,   # multiple documents are ambiguous
            sample_prelink([]),
            sample_prelink([{}] * 100),
            sample_prelink([{"CFBundleIdentifier": "x"}] * 100),
            sample_prelink(**{"OSPrelinkInfoContainsUUIDs": False}),
        ]:
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                meta.parse_prelink_xml(payload)

    def test_descriptors_reject_unsupported_matching(self):
        entry = {"CFBundleIdentifier": "com.apple.driver.test"}
        d = {"IOClass": "AppleGPU", "IOProviderClass": "AppleARMIODevice",
             "IONameMatch": ["x", "paravirtualizedgraphics,gpu"],
             "IOPCIPrimaryMatch": "0xAAAA",
             "IOPropertyMatch": {"flag": "value"}}
        got = meta.normalize(entry, "test", d)
        self.assertEqual(got["name_match"], d["IONameMatch"])
        self.assertTrue(got["property_match_present"])
        self.assertIn("IOPCIPrimaryMatch", got["unsupported_match_keys"])
        self.assertFalse(got["attach_authorized"])
        self.assertTrue(got["metadata_only"])
        for attr, val in [("IOProviderClass", None), ("IOClass", []),
                          ("IOProviderClass", ""), ("IOClass", "x" * 200)]:
            v = dict(d); v[attr] = val
            with self.assertRaises(ValueError):
                meta.normalize(entry, "test", v)
        for key, value in [("IONameMatch", 14), ("IONameMatch", ["x"] * 9),
                           ("IOResourceMatch", [1, 2]),
                           ("IOMatchCategory", 0), ("IOPropertyMatch", "abc"),
                           ("IOProbeScore", 2**35)]:
            v = dict(d); v[key] = value
            got = meta.normalize(entry, "test", v)
            self.assertTrue(got["unsupported_match_keys"])
            self.assertFalse(got["attach_authorized"])

    def test_c_escaping_and_untrusted_data(self):
        d = meta.normalize({"CFBundleIdentifier": "org.kext.test"},
                           "P", {"IOClass": "Driver", "IOProviderClass": "IOService",
                                 "IONameMatch": 'name\"; goodbye'})
        source = meta.as_c_catalogue({"personalities": [d]})
        self.assertIn(r'name\"; goodbye', source)
        self.assertIn(".other_unsupported_selectors = false", source)
        d["name_match"] = ["🐞"]
        with self.assertRaises(ValueError):
            meta.as_c_catalogue({"personalities": [d]})


def source_provenance():
    # Check actual named XNU22 provider routes. The original GICv3 is
    # kernel machine code, not a macOS27 IOKit AppleARMIODevice provider.
    path = ROOT / "research/dizi-ci0106/xnu/iokit/KernelConfigTables.cpp"
    if path.is_file():
        txt = path.read_text()
    else:
        # Only patches shipped with a fresh checkout; no ignored
        # research/dizi-ci0106 tree or proprietary artifacts needed.
        txt = "\n".join((ROOT / "xnu/patches" / f).read_text(errors="replace")
                        for f in ("0016-sweet-device-tree-platform-expert.patch",
                                  "0018-sweet-boot-cpu-driver.patch",
                                  "0046-sweet-iosurface-iomfb.patch",
                                  "0058-sweet-hid-event-services.patch"))
    for phrase in ("SweetPlatformExpert", "IOPlatformExpertDevice",
                   "SweetHIDTouch", "IOResources", "AppleCLCD",
                   "IOPlatformDevice"):
        assert phrase in txt, phrase
    if path.is_file():
        for phrase in ("'IONameMatch'     = ('xiaomi,sweet', 'xiaomi,dizi');",
                       "'IONameMatch'     = 'sweet,display';"):
            assert phrase in txt, phrase
    gic = (ROOT / "xnu/patches/0004-sweet-machine-config.patch").read_text()
    assert "GICR_IGROUPR0" in gic
    assert "GICD_CTLR" in gic
    print("PASS source-grounded XNU22 dizi: SweetPlatformExpert, AppleCLCD, "
          "mobile HID, direct GICv3, no AppleARMIODevice registration")


def real_metadata(temporary: Path):
    kc_path = ROOT / "research/macos27-26A434/kernel.vma2.macho/" \
                     "kernelcache.release.vma2.decompressed"
    if not kc_path.is_file():
        print("SKIP genuine 26A434 private KC not present in fresh checkout")
        return
    actual = meta.extract(meta._checked_bytes(kc_path), pinned=True)
    assert actual["product_build"] == "26A434"
    assert actual["darwin"] == "27.0.0"
    assert actual["xnu"] == "xnu-13432.1.9"
    assert actual["cpu_arch"] in ("arm64e", "arm64e.x1")
    assert actual["fileset_entries"] == 216
    assert actual["prelink_bundles"] == 236
    assert actual["kc_sha256"] == meta.EXPECTED_VMA2_SHA256
    assert len(actual["personalities"]) == 11
    assert not actual["shim_contract"]["driver_binding_allowed"]
    assert not actual["shim_contract"]["hardware_claims_made"]
    by_persona = {d["personality"]: d for d in actual["personalities"]}
    for n, provider, names in (
        ("AppleARMGICv3", "AppleARMIODevice", ["ARM,gicv3"]),
        ("AppleARMPE", "IOPlatformExpertDevice", ["AppleARM"]),
        ("AppleVirtualPlatformARMPE", "IOPlatformExpertDevice", ["AppleVirtualPlatformARM"]),
        ("AppleParavirtGPUARM", "AppleARMIODevice", ["paravirtualizedgraphics,gpu"]),
        ("AppleDisplay", "IODisplayConnect", []),
        ("IOHIDEventServiceUserClient", "IOHIDEventService", []),
    ):
        desc = by_persona[n]
        assert desc["provider_class"] == provider, n
        assert desc["name_match"] == names, n
        assert desc["attach_authorized"] is False
    assert by_persona["IODisplayWrangler"]["resource_match"] == "IOKit"
    assert by_persona["IOHIDSystem"]["resource_match"] == "IOBSD"
    print("PASS real 26A434 KC SHA256, arm64e fileset 216 entries, 236 embedded "
          "kext plists, exact 11 provider/personality bindings")

    # Generated catalogue compiles with the same portable resolver that the
    # prime shim may consume. No binary signing, runtime linking or HW.
    c = meta.as_c_catalogue(actual)
    hdr = temporary / "iokit_26a434_extracted.h"
    hdr.write_text(c)
    source = temporary / "iokit_real_bridge_test.c"
    source.write_text(
        '#include "iokit_26a434_extracted.h"\n'
        '#include <assert.h>\n'
        'int main(void) {\n'
        '  assert(m27_26a434_personality_count == 11);\n'
        '  for (size_t i=0; i<m27_26a434_personality_count; i++) {\n'
        '    for (int p=0; p<M27_IOKIT_DIZI_COUNT; p++) {\n'
        '      struct m27_iokit_result r = m27_iokit_resolve(\n'
        '        &m27_26a434_personalities[i],\n'
        '        m27_iokit_dizi_xnu22_provider((enum m27_iokit_dizi_provider_id)p),0);\n'
        '      assert(!r.attach_authorized);\n'
        '    }\n'
        '  }\n'
        '  return 0;\n'
        '}\n')
    cc = os.environ.get("CLANG", "clang")
    exe = temporary / "real-26a434-catalogue-test"
    run([cc, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-pedantic",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         "-I" + str(ROOT / "ports/macos27"),
         "-I" + str(temporary),
         str(ROOT / "ports/macos27/iokit_resolver.c"), str(source),
         "-o", str(exe)])
    run([str(exe)], env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"})
    print("PASS C shim-oriented generated catalogue: exact KC predicates, "
          "11 personalities × 6 legacy provider slots, zero attach approvals")

    # Deliberately corrupt the trusted identity: no false KC provenance.
    raw = kc_path.read_bytes()
    modified = bytearray(raw)
    modified[-1] ^= 1
    with unittest.TestCase().assertRaises(ValueError):
        meta.extract(bytes(modified), pinned=True)
    print("PASS one-byte KC corruption cannot masquerade as trusted 26A434")


def main():
    source_provenance()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MetadataNegative)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print(f"PASS {result.testsRun} negative XML/selector/C injection suites")
    cc = os.environ.get("CLANG", "clang")
    with tempfile.TemporaryDirectory(prefix="macos27-iokit-source-only-") as temp:
        tmp = Path(temp)
        core = ROOT / "ports/macos27/iokit_resolver.c"
        tests = ROOT / "tests/test-macos27-iokit.c"
        exe = tmp / "host-iokit"
        run([cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-pedantic", "-fsanitize=address,undefined",
             "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
             str(core), str(tests), "-o", str(exe)])
        run([str(exe)], env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1"})
        print("PASS host ASan+UBSan 100,000 hostile provider variants")
        elf = tmp / "arm64-iokit.o"
        macho = tmp / "arm64e-iokit.o"
        run([cc, "--target=aarch64-none-elf", "-ffreestanding", "-std=c11",
             "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-c", str(core), "-o", str(elf)])
        run([cc, "--target=arm64-apple-macos14.0", "-ffreestanding", "-std=c11",
             "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-c", str(core), "-o", str(macho)])
        assert elf.stat().st_size > 1000 and macho.stat().st_size > 1000
        print("PASS freestanding AArch64 ELF + Apple arm64 Mach-O compile "
              "(NOT actual arm64e/PAC execution)")
        real_metadata(tmp)
    print("PASS macOS27 IOKit provider compatibility audit; no native boot claim")


if __name__ == "__main__":
    main()
