from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from retrolarium_disassembler.snes.analysis import analyze_snes
from retrolarium_disassembler.snes.emit import emit_project
from retrolarium_disassembler.snes.pointers import detect_pointer_candidates
from retrolarium_disassembler.snes.symbols import generate_symbols
from snes.builders import probe_image


class SnesEmitTests(unittest.TestCase):
    def test_emits_modular_exact_first_projects_for_both_mappings(self) -> None:
        expected_units = {"lorom": 4, "hirom": 2}
        for mapping in ("lorom", "hirom"):
            image = probe_image(mapping)
            analysis = analyze_snes(image)
            pointers = detect_pointer_candidates(image, analysis)
            symbols = generate_symbols(image, analysis, pointers)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result = emit_project(
                    root, image, analysis, pointers, symbols
                )
                main = (root / "main.asm").read_text(encoding="utf-8")
                sources = "\n".join(
                    (root / unit).read_text(encoding="utf-8")
                    for unit in result.bank_units
                )
                header = (root / "src/header.asm").read_text(encoding="utf-8")

                self.assertEqual(expected_units[mapping], len(result.bank_units))
                self.assertEqual(len(image.data), (
                    result.instruction_bytes
                    + result.instruction_fallback_bytes
                    + result.pointer_bytes
                    + result.header_bytes
                    + result.raw_bytes
                ))
                self.assertEqual(0, result.instruction_fallback_bytes)
                self.assertNotIn(".incbin", sources.lower())
                self.assertNotIn(".incbin", main.lower())
                self.assertIn("jsr .loword(Sub_SNES_00901B)", sources)
                self.assertIn("jsl Sub_SNES_009023", sources)
                self.assertIn(".faraddr Entry_SNES_009000", sources)
                self.assertIn(".lobytes Entry_SNES_009000", sources)
                self.assertIn("native nmi", header)
                self.assertTrue((root / "linker.cfg").is_file())
                self.assertTrue((root / "Makefile").is_file())


if __name__ == "__main__":
    unittest.main()
