from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.ghidra import run_megadrive_analysis, run_nes_analysis


class GhidraBackendTests(unittest.TestCase):
    @staticmethod
    def fake_layout(root: Path) -> tuple[Path, Path, Path]:
        image = root / "probe.bin"
        image.write_bytes(b"probe")
        ghidra_home = root / "ghidra"
        support = ghidra_home / "support"
        support.mkdir(parents=True)
        headless_name = (
            "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        )
        (support / headless_name).write_text("headless", encoding="utf-8")
        scripts = root / "scripts"
        scripts.mkdir()
        return image, ghidra_home, scripts

    def test_nes_vectors_are_seeded_before_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"

            def complete(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {
                            "language": "6502:LE:16:default",
                            "compiler": "default",
                        }
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_nes_analysis(image, workspace, ghidra_home, scripts)

            command = run.call_args.args[0]
            seed_index = command.index("-preScript")
            self.assertEqual("SeedNesVectors.java", command[seed_index + 1])
            self.assertLess(seed_index, command.index("-postScript"))

    def test_megadrive_uses_explicit_raw_68000_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"

            def complete(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {
                            "language": "68000:BE:32:default",
                            "compiler": "default",
                        }
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_megadrive_analysis(
                    image, workspace, ghidra_home, scripts
                )

            command = run.call_args.args[0]
            self.assertEqual(
                ["-loader", "BinaryLoader"],
                command[command.index("-loader"):command.index("-loader") + 2],
            )
            self.assertEqual(
                "68000:BE:32:default", command[command.index("-processor") + 1]
            )
            self.assertEqual("ROM", command[command.index("-loader-blockName") + 1])
            self.assertEqual("0", command[command.index("-loader-baseAddr") + 1])
            self.assertEqual(
                "SeedMegaDriveVectors.java", command[command.index("-preScript") + 1]
            )
            facts_index = command.index("ExportInstructionFacts.java")
            self.assertEqual("ROM", command[facts_index + 2])


if __name__ == "__main__":
    unittest.main()
