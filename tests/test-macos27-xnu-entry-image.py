#!/usr/bin/env python3
"""Synthetic AArch64 ELF/Apple KC tests for FIRST-INSTRUCTION-only packager.

No emitted GKI image and NO device/fastboot. All test binaries/files live in
temporary directories outside the source tree, and never use real Apple data.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/macos27-xnu-entry-image.py"
MODULE = importlib.util.spec_from_file_location("macos27_xnu_entry_img", SCRIPT)
assert MODULE and MODULE.loader
pack = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(pack)


ENTRY_OFFSET = 0x40
TARGET_OFFSET = ENTRY_OFFSET + (pack.EXPECTED_TARGET_VA - pack.EXPECTED_ENTRY_VA)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assembly(*, macro: bool = True) -> str:
    # Mirrors worker-9 C/ASM integration boundaries, but the fake run() and
    # fake shim_main do NOTHING useful; never approve its SHA for hardware.
    core = """.section .text.head,"ax"
.globl _head
_head:
  b _start
  .long 0
  .quad 0
  .quad _end
  .quad 0xa
  .quad 0,0,0
  .ascii "ARM\\x64"
  .long 0
.text
.globl _start
_start:
  bl shim_main
1: wfe
   b 1b
.globl shim_main
shim_main:
  bl mac27_entry_experiment_run
  ret
.globl exc_handler
exc_handler:
  bl mac27_entry_experiment_exc_handler
  ret
.globl vectors
vectors:
  nop
.globl mac27_entry_experiment_run
mac27_entry_experiment_run:
  bl mac27_entry_experiment_validate
  bl mac27_entry_experiment_sha256
  movz w2, #0xc4e0
  movk w2, #0xd429, lsl #16
  str w2, [x0, x1] // NEVER execute synthetic stub; models compiled C pattern
  dsb sy
  dc cvau, x1
  dsb ish
  ic ivau, x1
  dsb ish
  isb
  // Deliberately nonfunctional placeholder for native-only staging checks.
  .rept 12
  nop
  .endr
"""
    if macro:
        core += "  bl mac27_entry_experiment_trampoline\n"
    core += """  ret
.globl mac27_entry_experiment_validate
mac27_entry_experiment_validate:
  ret
.globl mac27_entry_experiment_sha256
mac27_entry_experiment_sha256:
  ret
.globl mac27_entry_experiment_match_brk
mac27_entry_experiment_match_brk:
  ret
.globl mac27_entry_experiment_exc_handler
mac27_entry_experiment_exc_handler:
  bl mac27_entry_experiment_match_brk
  ret
"""
    if macro:
        core += """#if !defined(DIZI_MACOS27_XNU_ENTRY_EXPERIMENT) || !defined(MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED)
#error Explicit dual opt-in was not provided
#endif
.globl mac27_entry_experiment_trampoline
mac27_entry_experiment_trampoline:
  stp x29, x30, [sp, #-16]!
  mov x29, sp
  br x1
.globl mac27_entry_experiment_resume
mac27_entry_experiment_resume:
  mov w0, #1
  ldp x29, x30, [sp], #16
  ret
"""
    return core


class EntryImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory(prefix="mac27-brk-test-")
        self.root = Path(self.dir.name)
        self.elf = self.root / "experimental.elf"
        self.kc = self.root / "fileset.raw"
        self.manifest = self.root / "BuildManifest.plist"
        self.output = self.root / "never-emit.img"
        self.manifest.write_bytes(b"synthetic manifest, not Apple signed")
        fake = bytearray(TARGET_OFFSET + 0x100)
        struct.pack_into("<4I", fake, 0, 0xFEEDFACF, 0x0100000C, 0xC0000002, 12)
        struct.pack_into("<I", fake, ENTRY_OFFSET, pack.EXPECTED_ENTRY_BRANCH)
        struct.pack_into("<I", fake, TARGET_OFFSET, pack.EXPECTED_TARGET_ORIGINAL)
        self.kc.write_bytes(fake)
        self.compile_elf()
        self.pins = [
            mock.patch.object(pack, "KC_BYTES", len(fake)),
            mock.patch.object(pack, "KC_SHA256", digest(fake)),
            mock.patch.object(pack, "MANIFEST_SHA256", digest(self.manifest.read_bytes())),
            mock.patch.object(pack, "EXPECTED_ENTRY_OFFSET", ENTRY_OFFSET),
            mock.patch.object(pack, "EXPECTED_TARGET_OFFSET", TARGET_OFFSET),
        ]
        for pin in self.pins:
            pin.start()

    def tearDown(self) -> None:
        for pin in reversed(self.pins):
            pin.stop()
        self.dir.cleanup()

    def compile_elf(self, *, with_marker: bool = True) -> None:
        src = self.root / "fixture.S"
        src.write_text(assembly(macro=with_marker), encoding="utf-8")
        obj = self.root / "fixture.o"
        subprocess.run(["aarch64-linux-gnu-gcc", "-c", "-DDIZI_MACOS27_XNU_ENTRY_EXPERIMENT=1",
                        "-DMAC27_ENTRY_EXPERIMENT_HANDLER_WIRED=1",
                        str(src), "-o", str(obj)], check=True, capture_output=True)
        subprocess.run(["aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie",
                        "-T", str(ROOT / "shim/shim.ld"), "-Wl,--build-id=none",
                        "-Wl,--no-warn-rwx-segments", "-Wl,-N", str(obj),
                        "-o", str(self.elf)], check=True, capture_output=True)

    def verify_elf(self) -> tuple[dict, bytes]:
        return pack.verify_elf(self.elf, digest(self.elf.read_bytes()))

    def test_good_synthetic_elf_trampoline_exact_bytes(self) -> None:
        report, image = self.verify_elf()
        self.assertEqual(report["macro_opt_in"], True)
        self.assertEqual(report["brk_opcode"], "0xd429c4e0")
        self.assertFalse(report["validator_runtime_semantics_verified_by_packager"])
        self.assertEqual(image[56:60], b"ARMd")
        self.assertEqual(struct.unpack_from("<Q", image, 24)[0], 0xA)
        self.assertEqual(struct.unpack_from("<Q", image, 16)[0], len(image))
        addr = report["trampoline_offset"]
        self.assertEqual(struct.unpack_from("<6I", image, addr), pack.TRAMPOLINE)

    def test_synthetic_original_kc_B_is_untouched(self) -> None:
        old = self.kc.read_bytes()
        info = pack.verify_apple(self.kc, self.manifest, expected_kc_digest=digest(old),
                                 expected_kc_size=len(old),
                                 expected_manifest_digest=digest(self.manifest.read_bytes()),
                                 entry_offset=ENTRY_OFFSET, target_offset=TARGET_OFFSET)
        self.assertEqual(info["entry_b_word"], "0x14000efc")
        self.assertEqual(info["bootstrap_target_original_word"], "0xd510109f")
        self.assertFalse(info["raw_kc_modified"])
        self.assertEqual(old, self.kc.read_bytes())

    def test_refuse_missing_dual_optin_assembly_and_unpinned_binary(self) -> None:
        self.compile_elf(with_marker=False)
        with self.assertRaisesRegex(pack.Rejected, "trampoline ABI symbols absent"):
            self.verify_elf()
        self.compile_elf()
        with self.assertRaisesRegex(pack.Rejected, "independent SHA-256 pin"):
            pack.verify_elf(self.elf, "0" * 64)
        with self.assertRaisesRegex(pack.Rejected, "independent SHA-256 pin"):
            pack.verify_elf(self.elf, "XYZ")
        with self.assertRaisesRegex(pack.Rejected, "differs from independent"):
            pack.verify_elf(self.elf, "a" * 64)

    def test_refuse_missing_required_symbols(self) -> None:
        symbols = pack.elf_symbols(self.elf)
        info, image = self.verify_elf()
        self.assertEqual(info["macro_opt_in"], True)
        symbols.pop("mac27_entry_experiment_trampoline")
        with self.assertRaisesRegex(pack.Rejected, "symbols absent"):
            pack.validate_trampoline(image, symbols)

    def test_refuse_mutated_brk_and_cache_flush(self) -> None:
        report, image = self.verify_elf()
        sym = pack.elf_symbols(self.elf)
        trampoline = report["trampoline_offset"]
        for index, value in ((0, 0xD503201F), (1, 0xD503201F),
                             (2, 0xD503201F), (3, 0xD42004E0),
                             (4, 0xD503201F), (5, 0xD503201F)):
            with self.subTest(op=index):
                altered = bytearray(image)
                struct.pack_into("<I", altered, trampoline + index * 4, value)
                with self.assertRaisesRegex(pack.Rejected, "trampoline instruction"):
                    pack.validate_trampoline(altered, sym)

    def test_refuse_removing_real_ELF_trampoline_and_resume(self) -> None:
        _, image = self.verify_elf()
        syms = pack.elf_symbols(self.elf)
        trampoline = syms["mac27_entry_experiment_trampoline"]
        for offset, value in ((0, 0xD503201F), (4, 0xD503201F),
                              (8, 0xD503201F), (12, 0xD503201F)):
            with self.subTest(offset=offset):
                broken = bytearray(image)
                struct.pack_into("<I", broken, trampoline + offset, value)
                with self.assertRaises(pack.Rejected):
                    pack.validate_trampoline(broken, syms)

    def test_refuse_modified_linux_image_header(self) -> None:
        _, image = self.verify_elf()
        syms = pack.elf_symbols(self.elf)
        for off in (0, 8, 16, 24, 56, 60):
            with self.subTest(off=off):
                b = bytearray(image)
                b[off] ^= 1
                with self.assertRaises(pack.Rejected):
                    pack.validate_trampoline(b, syms)

    def test_apple_kc_reject_changed_B_and_target(self) -> None:
        initial = self.kc.read_bytes()
        for off in (ENTRY_OFFSET, TARGET_OFFSET):
            with self.subTest(off=off):
                b = bytearray(initial)
                b[off] ^= 1
                self.kc.write_bytes(b)
                with self.assertRaisesRegex(pack.Rejected, "wrong KC"):
                    pack.verify_apple(self.kc, self.manifest)
                with self.assertRaisesRegex(pack.Rejected, "modified|unchanged"):
                    pack.verify_apple(self.kc, self.manifest,
                                      expected_kc_digest=digest(b),
                                      expected_kc_size=len(b),
                                      expected_manifest_digest=digest(self.manifest.read_bytes()),
                                      entry_offset=ENTRY_OFFSET,
                                      target_offset=TARGET_OFFSET)
        self.kc.write_bytes(initial)

    def test_apple_reject_wrong_manifest_and_elf_macho_subtype(self) -> None:
        with self.assertRaisesRegex(pack.Rejected, "BuildManifest"):
            pack.verify_apple(self.kc, self.manifest,
                              expected_kc_digest=digest(self.kc.read_bytes()),
                              expected_kc_size=self.kc.stat().st_size,
                              expected_manifest_digest="b" * 64,
                              entry_offset=ENTRY_OFFSET, target_offset=TARGET_OFFSET)
        mutated = bytearray(self.kc.read_bytes())
        struct.pack_into("<I", mutated, 8, 0)
        self.kc.write_bytes(mutated)
        with self.assertRaisesRegex(pack.Rejected, "ARM64e"):
            pack.verify_apple(self.kc, self.manifest,
                              expected_kc_digest=digest(mutated),
                              expected_kc_size=len(mutated),
                              expected_manifest_digest=digest(self.manifest.read_bytes()),
                              entry_offset=ENTRY_OFFSET, target_offset=TARGET_OFFSET)

    def test_no_output_without_optin_even_if_elf_valid(self) -> None:
        with self.assertRaisesRegex(pack.Rejected, "opt-in"):
            pack.package(self.elf, self.kc, self.manifest, self.output,
                         digest(self.elf.read_bytes()), opt_in=False, emit=True)
        self.assertFalse(self.output.exists())

    def test_default_dry_run_never_emits_image(self) -> None:
        # Tests must NOT invoke mkbootimg, even when opt-in metadata is set.
        calls = []
        real_run = subprocess.run
        def safe_tool_run(*args, **kwargs):
            calls.append(args[0][0])
            self.assertNotEqual(args[0][0], "mkbootimg")
            self.assertIn(args[0][0], {"aarch64-linux-gnu-nm", "aarch64-linux-gnu-objdump"})
            return real_run(*args, **kwargs)
        with mock.patch.object(pack.subprocess, "run", side_effect=safe_tool_run):
            info = pack.package(self.elf, self.kc, self.manifest, self.output,
                                digest(self.elf.read_bytes()), opt_in=True, emit=False)
        self.assertTrue(calls)
        self.assertEqual(info["native_xnu_boot"], False)
        self.assertFalse(info["true_runtime_staging_validation_performed"])
        self.assertFalse(self.output.exists())
        self.assertFalse(Path(str(self.output) + ".review.json").exists())

    def test_missing_or_symlink_inputs_are_rejected(self) -> None:
        link = self.root / "unsafe-symlink-kc"
        link.symlink_to(self.kc)
        with self.assertRaisesRegex(pack.Rejected, "open failed"):
            pack.sha256_file(link, pack.MAX_BOOT_IMAGE, "KC")
        with self.assertRaisesRegex(pack.Rejected, "offline regular"):
            pack.sha256_file(Path("/dev/null"), pack.MAX_BOOT_IMAGE, "KC")

    def test_size_budget_and_no_overwrite_gate(self) -> None:
        self.assertLess(pack.KC_BYTES + pack.MAX_ELF + pack.PAGE, pack.MAX_BOOT_IMAGE)
        self.output.write_bytes(b"KNOWN VALID IMAGE - KEEP")
        self.assertFalse(self.output.is_symlink())
        with self.assertRaisesRegex(pack.Rejected, "never overwrite"):
            pack.check_destination(self.output, self.elf, self.kc, self.manifest)
        self.assertEqual(self.output.read_bytes(), b"KNOWN VALID IMAGE - KEEP")
        self.output.unlink()
        reviewfile = Path(str(self.output) + ".review.json")
        reviewfile.write_bytes(b"KEEP REVIEW")
        with self.assertRaisesRegex(pack.Rejected, "never overwrite"):
            pack.check_destination(self.output, self.elf, self.kc, self.manifest)
        self.assertEqual(reviewfile.read_bytes(), b"KEEP REVIEW")
        reviewfile.unlink()
        link = self.root / "link.img"
        link.symlink_to(self.kc)
        with self.assertRaisesRegex(pack.Rejected, "never overwrite"):
            pack.check_destination(link, self.elf, self.kc, self.manifest)

    def test_staging_machine_code_brk_and_cache_sync_mutations(self) -> None:
        raw = self.elf.read_bytes()
        for original in (0x52989C02, 0x72BA8522, 0xB8216802,
                         0xD5033F9F, 0xD5033B9F, 0xD50B7B21, 0xD50B7521):
            with self.subTest(original=hex(original)):
                word = struct.pack("<I", original)
                self.assertIn(word, raw)
                corrupted = raw.replace(word, struct.pack("<I", 0xD503201F))
                self.elf.write_bytes(corrupted)
                with self.assertRaisesRegex(pack.Rejected, "BRK|cache"):
                    pack.verify_elf(self.elf, digest(corrupted))
                self.elf.write_bytes(raw)

    def test_cli_disabled_and_reject_preflight_only_elf(self) -> None:
        run = subprocess.run([sys.executable, str(SCRIPT),
                              "--experiment-elf", str(self.elf),
                              "--approved-elf-sha256", digest(self.elf.read_bytes())],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("opt-in", run.stderr)
        prior = ROOT / "shim/out/mac27-readonly-preflight-isRGNgJc/mac27-preflight-only.elf"
        if prior.is_file():
            with self.assertRaisesRegex(pack.Rejected, "trampoline ABI symbols absent"):
                pack.verify_elf(prior, digest(prior.read_bytes()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
