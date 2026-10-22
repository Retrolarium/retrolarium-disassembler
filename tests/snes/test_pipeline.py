from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from retrolarium_disassembler.snes.pipeline import disassemble_snes
from snes.builders import probe_image


class SnesPipelineTests(unittest.TestCase):
    def test_writes_portable_complete_project_without_oracle_input(self) -> None:
        image = probe_image("lorom")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom = root / "probe.sfc"
            output = root / "project"
            rom.write_bytes(image.container_data)
            manifest = disassemble_snes(rom, output)

            self.assertEqual("retrolarium.snes.disassembly", manifest["schema"])
            self.assertEqual("blind", manifest["mode"])
            self.assertIsNone(manifest["input"]["source"])
            self.assertEqual(len(image.data), manifest["source"]["coverage"]["rom_bytes"])
            self.assertFalse(manifest["source"]["whole_rom_fallback"])
            self.assertEqual(
                "generated/emission.json",
                manifest["source"]["emission"]["path"],
            )
            self.assertEqual("not-run", manifest["verification"]["status"])
            self.assertTrue((output / "retrolarium-project.json").is_file())
            self.assertTrue((output / "analysis/pointers.json").is_file())
            self.assertTrue((output / "analysis/cross-cpu-evidence.json").is_file())
            self.assertEqual(1, manifest["cross_cpu_evidence"]["edge_count"])
            analysis = __import__("json").loads((output / "analysis/analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(2, len(analysis["programs"]))
            self.assertEqual("extracted", analysis["programs"][1]["status"])
            self.assertEqual("spc700-program", manifest["assets"]["items"][0]["kind"])
            self.assertTrue((output / "generated/main.asm").is_file())


if __name__ == "__main__":
    unittest.main()
