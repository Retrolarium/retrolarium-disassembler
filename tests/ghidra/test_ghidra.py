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

from retrolarium_kit.ghidra import (
    GhidraError,
    run_megadrive_analysis,
    run_nes_analysis,
    run_spc700_analysis,
    run_snes_bank_analysis,
    run_z80_analysis,
)


class GhidraBackendTests(unittest.TestCase):
    def test_nonzero_z80_base_survives_hex_loader_parsing(self) -> None:
        def interpret_loader_address(*args, import_arguments, **kwargs):
            index = import_arguments.index("-loader-baseAddr")
            return int(import_arguments[index + 1], 16)

        with patch("retrolarium_kit.ghidra._run_analysis", side_effect=interpret_loader_address):
            decoded_base = run_z80_analysis(Path("payload.bin"), Path("output"), Path("ghidra"), Path("scripts"), base_address=0x1C00)
        self.assertEqual(0x1C00, decoded_base)

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

    def test_nes_entry_seed_plan_reaches_vector_script(self) -> None:
        from retrolarium_kit.pipeline import _run_seeded_nes_analysis

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            seed_plan = root / "entry-seeds.txt"
            seed_plan.write_text("8000\nC123\n", encoding="utf-8")

            def complete(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {"language": "6502:LE:16:default", "compiler": "default"}
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                _run_seeded_nes_analysis(
                    image, workspace, ghidra_home, scripts, seed_plan
                )

            command = run.call_args.args[0]
            seed_index = command.index("SeedNesVectors.java")
            self.assertEqual("-preScript", command[seed_index - 1])
            self.assertEqual(str(seed_plan.resolve()), command[seed_index + 1])
            self.assertEqual("-postScript", command[seed_index + 2])

        # The script must consume that single argument as a hex address plan.
        source = (
            Path(__file__).resolve().parents[1]
            / "src" / "retrolarium_kit" / "ghidra_scripts" / "SeedNesVectors.java"
        ).read_text(encoding="utf-8")
        self.assertIn("getScriptArgs()", source)
        self.assertIn("args.length > 1", source)
        self.assertIn("[0-9A-Fa-f]{1,4}", source)
        self.assertIn("Long.parseLong(line, 16)", source)
        self.assertIn("isExecutable(memory, target)", source)

    def test_script_error_is_fatal_even_when_ghidra_returns_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            result = subprocess.CompletedProcess(
                [], 0, "ERROR REPORT SCRIPT ERROR: seed failed"
            )

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", return_value=result
            ):
                with self.assertRaisesRegex(GhidraError, "script error"):
                    run_nes_analysis(image, workspace, ghidra_home, scripts)

            self.assertIn(
                "REPORT SCRIPT ERROR", (workspace / "headless.log").read_text()
            )

    def test_megadrive_uses_explicit_raw_68000_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            seed_plan = root / "seeds.txt"
            seed_plan.write_text("", encoding="ascii")

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
                    image, workspace, ghidra_home, scripts,
                    seed_plan=seed_plan,
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

    def test_megadrive_passes_python_seed_plan_to_decoder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            seed_plan = root / "seeds.txt"
            seed_plan.write_text("000B5A\n", encoding="ascii")

            def complete(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps({
                        "language": "68000:BE:32:default",
                        "compiler": "default",
                    }),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_megadrive_analysis(
                    image,
                    workspace,
                    ghidra_home,
                    scripts,
                    seed_plan=seed_plan,
                )

            command = run.call_args.args[0]
            script_index = command.index("SeedMegaDriveVectors.java")
            self.assertEqual(str(seed_plan.resolve()), command[script_index + 1])

    def test_z80_uses_independent_program_and_address_space(self) -> None:
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
                        {"language": "z80:LE:16:default", "compiler": "default"}
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_z80_analysis(image, workspace, ghidra_home, scripts)

            command = run.call_args.args[0]
            self.assertEqual(
                "z80:LE:16:default", command[command.index("-processor") + 1]
            )
            self.assertEqual(
                "Z80_RAM", command[command.index("-loader-blockName") + 1]
            )
            self.assertEqual(
                "SeedZ80Entry.java", command[command.index("-preScript") + 1]
            )
            facts_index = command.index("ExportInstructionFacts.java")
            self.assertEqual("Z80_RAM", command[facts_index + 2])
            plan = root / "dispatch-seeds.txt"
            plan.write_text("T 0080 0088\nS 00A0\n", encoding="ascii")
            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_z80_analysis(
                    image, workspace, ghidra_home, scripts, seed_plan=plan
                )
            command = run.call_args.args[0]
            self.assertEqual(
                str(plan.resolve()),
                command[command.index("SeedZ80Entry.java") + 1],
            )

    def test_snes_uses_pinned_24_bit_language_and_context_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            context = root / "context.tsv"
            context.write_text("009000\t009001\t1\t1\t1\n", encoding="utf-8")

            def complete(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {"language": "65816:LE:24:snes", "compiler": "default"}
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_snes_bank_analysis(
                    image,
                    root / "analysis",
                    ghidra_home,
                    scripts,
                    base_address=0x009000,
                    entry_address=0x009000,
                    context_plan=context,
                )

            command = run.call_args.args[0]
            self.assertEqual(
                "65816:LE:24:snes", command[command.index("-processor") + 1]
            )
            seed = command.index("SeedSnesBank.java")
            self.assertEqual("SNES_ROM", command[seed + 1])
            self.assertEqual("009000", command[seed + 2])
            self.assertEqual(str(context.resolve()), command[seed + 3])

    def test_spc700_uses_independent_program_and_address_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)

            def complete(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {"language": "SPC700:LE:16:default", "compiler": "default"}
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch(
                "retrolarium_kit.ghidra.subprocess.run", side_effect=complete
            ) as run:
                run_spc700_analysis(
                    image,
                    root / "analysis",
                    ghidra_home,
                    scripts,
                    base_address=0x0200,
                )

            command = run.call_args.args[0]
            self.assertEqual(
                "SPC700:LE:16:default", command[command.index("-processor") + 1]
            )
            self.assertEqual(
                "SPC700_RAM", command[command.index("-loader-blockName") + 1]
            )
            self.assertEqual("0x0200", command[command.index("-loader-baseAddr") + 1])
            self.assertEqual(
                "SeedSpc700Entry.java", command[command.index("-preScript") + 1]
            )
            facts_index = command.index("ExportInstructionFacts.java")
            self.assertEqual("SPC700_RAM", command[facts_index + 2])


if __name__ == "__main__":
    unittest.main()
