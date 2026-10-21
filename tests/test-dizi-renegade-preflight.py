#!/usr/bin/env python3
"""Host tests for Renegade candidate config/FDT: no binaries or device access."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/dizi-renegade-preflight.py"
spec = importlib.util.spec_from_file_location("dizi_renegade_preflight", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def make_dtb(destination: Path, *, compatible="qcom,parrot",
             extra_reserved="", framebuffer=True, memory_size="0xb0000000"):
    reserved = ('splash_region { reg = <0x0 0xb8000000 0x0 0x2b00000>; };'
                if framebuffer else '')
    dts = f'''
        /dts-v1/;
        / {{
          compatible = "{compatible}";
          #address-cells = <2>;
          #size-cells = <2>;
          memory {{ reg = <0x8 0xc0000000 0x0 {memory_size}>; }};
          reserved-memory {{
            #address-cells = <2>; #size-cells = <2>; ranges;
            {reserved}
            cma_region {{ size = <0x0 0x100000>; alignment = <0x0 0x1000>; }};
            {extra_reserved}
          }};
        }};
    '''
    source = destination.with_suffix('.dts')
    source.write_text(dts)
    subprocess.run(['dtc', '-q', '-I', 'dts', '-O', 'dtb',
                    '-o', str(destination), str(source)], check=True)


class TestRenegadeDizi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = ROOT / 'ports/renegade/dizi.conf'
        cls.board = ROOT / 'boards/dizi.json'
        cls.real_fdt = ROOT / 'backup/dizi/fdt'

    def test_real_dizi_provenance(self):
        if not self.real_fdt.exists():
            self.skipTest('Saved FDT not mounted')
        report = module.analyze(self.board, self.real_fdt, self.config)
        self.assertEqual(report['observed']['ddr_banks'], 7)
        self.assertEqual(report['observed']['fixed_reserved_regions'], 35)
        self.assertEqual(report['observed']['unlocated_reserved_children'], 10)
        self.assertEqual(report['observed']['framebuffer'][1:], [1600, 2560, 6400])
        self.assertTrue(report['observed']['kernel_ram_in_captured_ddr'])
        self.assertFalse(report['uefi_buildable'])
        self.assertFalse(report['renegade_platform_ready'])

    def test_synthetic_and_hostile_fdt(self):
        with tempfile.TemporaryDirectory(prefix='dizi-renegade-') as temp:
            d = Path(temp)
            dtb = d / 'test.dtb'
            make_dtb(dtb)
            report = module.analyze(self.board, dtb, self.config)
            self.assertEqual(report['observed']['ddr_banks'], 1)
            self.assertEqual(report['observed']['unlocated_reserved_children'], 1)
            self.assertEqual(report['observed']['fixed_reserved_regions'], 1)

            make_dtb(dtb, extra_reserved='danger { reg = <0x8 0xc0000000 0x0 0x10000>; };')
            with self.assertRaisesRegex(module.Rejected, 'intersects fixed'):
                module.analyze(self.board, dtb, self.config)

            make_dtb(dtb, framebuffer=False)
            with self.assertRaisesRegex(module.Rejected, 'framebuffer reservation'):
                module.analyze(self.board, dtb, self.config)

            make_dtb(dtb, compatible='qcom,sm7325')
            with self.assertRaisesRegex(module.Rejected, 'incompatible'):
                module.analyze(self.board, dtb, self.config)

            make_dtb(dtb, memory_size='0xa0000000')
            with self.assertRaisesRegex(module.Rejected, 'absent from'):
                module.analyze(self.board, dtb, self.config)

            dtb.write_bytes(b'corrupted-fdt')
            with self.assertRaises(module.Rejected):
                module.analyze(self.board, dtb, self.config)

    def test_wrong_board_and_fake_config(self):
        with tempfile.TemporaryDirectory(prefix='dizi-renegade-') as temp:
            d = Path(temp)
            source = json.loads(self.board.read_text())
            board = d / 'board.json'
            source['soc'] = 'SM7325'
            board.write_text(json.dumps(source))
            with self.assertRaisesRegex(module.Rejected, 'not an observed dizi'):
                module.analyze(board, self.real_fdt, self.config)
            source['soc'] = 'SM7435'
            board.write_text(json.dumps(source))
            conf = d / 'dizi.conf'
            conf.write_text('SOC_PLATFORM="SM7325"\nPLATFORM_NAME="dizi"\n')
            with self.assertRaisesRegex(module.Rejected, 'candidate missing'):
                module.analyze(board, self.real_fdt, conf)


if __name__ == '__main__':
    unittest.main(verbosity=2)
