from __future__ import annotations

import json
import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_core.contracts import ContractError, load_disassembly_manifest
from retrolarium_disassembler.snes.pipeline import disassemble_snes
from snes.builders import probe_image


class SnesContractTests(unittest.TestCase):
    def write_project(self, root: Path) -> Path:
        rom = root / "probe.sfc"
        rom.write_bytes(probe_image("lorom").container_data)
        output = root / "project"
        disassemble_snes(rom, output)
        return output / "retrolarium-project.json"

    def test_contract_loads_multi_program_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.write_project(Path(directory))
            loaded = load_disassembly_manifest(manifest, verify_rebuilt=False)
            self.assertEqual("retrolarium.snes.disassembly", loaded["schema"])
            self.assertEqual(2, loaded["analysis"]["program_count"])
            self.assertEqual(1, loaded["cross_cpu_evidence"]["edge_count"])

    def test_contract_rejects_tampered_spc700_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.write_project(Path(directory))
            root = manifest.parent
            payload = root / "analysis/spc700/program00/analysis-input.bin"
            payload.write_bytes(b"tampered")
            with self.assertRaises(ContractError):
                load_disassembly_manifest(manifest, verify_rebuilt=False)

    def test_contract_rejects_cross_platform_launch_machine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.write_project(Path(directory))
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["operations"]["launch"]["supported_machines"] = ["genesis"]
            manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ContractError):
                load_disassembly_manifest(manifest, verify_rebuilt=False)


if __name__ == "__main__":
    unittest.main()
