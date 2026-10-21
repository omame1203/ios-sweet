#!/usr/bin/env python3
"""Offline tests for real-but-not-bootable pinned EDK2 build runner."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dizi_cold", ROOT / "tools/dizi-renegade-cold-build.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class ColdBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dizi-build-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name) / "source"
        self.stage.mkdir()
        self.overlay = Path(self.temp.name) / "overlay"
        self.overlay.mkdir()
        self.overlay_file = self.overlay / "Platform/Xiaomi/sm7435/board.dsc"
        self.overlay_file.parent.mkdir(parents=True)
        self.overlay_file.write_text("BOARD=SM7435\n")
        self.staged = self.stage / self.overlay_file.relative_to(self.overlay)
        self.staged.parent.mkdir(parents=True)
        self.staged.write_bytes(self.overlay_file.read_bytes())
        (self.stage / "Common/edk2/BaseTools/Source/C/bin").mkdir(parents=True)
        b = self.stage / "Common/edk2/BaseTools/Source/Python/build/build.py"
        b.parent.mkdir(parents=True)
        b.write_text("source present\n")
        conf = self.stage / "Common/edk2/Conf"
        conf.mkdir(parents=True)
        for name in ("tools_def.txt", "build_rule.txt"):
            (conf / name).write_text("source present\n")
        self.pin_mock = mock.patch.object(m, "check_git")
        self.pin_mock.start()
        self.addCleanup(self.pin_mock.stop)

    def test_audit_reports_candidate_as_untrusted(self):
        report = m.audit(self.stage, self.overlay)
        self.assertFalse(report["bootable"])
        self.assertFalse(report["runtime_ram_ownership_proven"])
        self.assertFalse(report["prepi_entry_abi_proven"])
        self.assertFalse(report["fastboot_performed"])
        self.assertEqual(report["compile_fd_candidate_pa"], "0x90000000")
        self.assertEqual(len(report["source_files_sha256"]), 1)

    def test_modified_or_missing_staged_overlay_refused(self):
        self.staged.write_text("MISMATCH\n")
        with self.assertRaisesRegex(m.Refused, "digest mismatch"):
            m.audit(self.stage, self.overlay)
        self.staged.unlink()
        with self.assertRaisesRegex(m.Refused, "missing copied source"):
            m.audit(self.stage, self.overlay)

    def test_wrong_root_and_missing_public_dependencies_refused(self):
        with self.assertRaisesRegex(m.Refused, "under /tmp"):
            m.audit(ROOT, self.overlay)
        self.pin_mock.stop()
        self.addCleanup(lambda: None)
        with self.assertRaisesRegex(m.Refused, "missing pinned public git"):
            m.audit(self.stage, self.overlay)

    def test_explicit_build_only_in_new_workspace_never_device(self):
        report = m.audit(self.stage, self.overlay)
        calls = []

        def simulate(cmd, **kwargs):
            calls.append((cmd, kwargs))
            self.assertEqual(cmd[:2], ["bash", "-c"])
            self.assertEqual(kwargs["cwd"], self.stage / "Common/edk2")
            self.assertIn("build -p Platform/Xiaomi/sm7435/dizi.dsc", cmd[2])
            for banned in ("fastboot", "--boot", "flash", "installer",
                           "git submodule", "git clean", "rm -rf"):
                self.assertNotIn(banned, cmd[2])
            fd = self.stage / "verify-hosttest/Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd"
            fd.parent.mkdir(parents=True)
            raw = bytearray(m.FD_SIZE)
            raw[32:40] = m.FD_SIZE.to_bytes(8, "little")
            raw[40:44] = b"_FVH"
            fd.write_bytes(raw)
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch.object(m.shutil, "which", return_value="/usr/bin/false"), \
             mock.patch.object(m.subprocess, "run", side_effect=simulate):
            result = m.build(self.stage, report, workspace_name="verify-hosttest")
        self.assertEqual(len(calls), 1)
        self.assertTrue(result["firmware_generated"])
        self.assertFalse(result["bootable"])
        self.assertFalse(result["fastboot_performed"])
        self.assertEqual(result["firmware_bytes"], m.FD_SIZE)
        self.assertTrue(Path(result["build_log"]).is_file())
        with self.assertRaisesRegex(m.Refused, "already exists"):
            m.build(self.stage, report, workspace_name="verify-hosttest")

    def test_invalid_new_workspace_name_refused(self):
        report = m.audit(self.stage, self.overlay)
        for bad in ("/tmp", "../escape", "test", "verify-;fastboot", "verify-a/b"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(m.Refused, "workspace name"):
                    m.build(self.stage, report, workspace_name=bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
