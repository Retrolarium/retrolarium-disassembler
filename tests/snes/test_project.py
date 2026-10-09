"""A disassembled SNES project builds and launches through the kit's project runner."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from helpers import KIT, needs_kit
from retrolarium_disasm.snes.pipeline import disassemble_snes
from test_snes_pointers import probe_image

if KIT:
    from retrolarium_kit.core.project import build_project, launch_plan, verify_project


@needs_kit
class SnesProjectTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "bundled PE smoke runs on Windows")
    def test_bundled_runner_builds_generated_snes_without_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom = root / "probe.sfc"
            rom.write_bytes(probe_image("lorom").container_data)
            project = root / "project"
            disassemble_snes(rom, project)

            result = build_project(
                project / "retrolarium-project.json",
                toolchain_cache=root / "toolchains",
            )

            self.assertEqual("retrolarium-kit", result["runner"]["kind"])
            self.assertEqual("ca65-ld65-v1", result["runner"]["recipe"])
            rebuilt = project / "generated/build/rebuilt.sfc"
            self.assertEqual(rom.read_bytes(), rebuilt.read_bytes())
            self.assertEqual(
                "exact",
                verify_project(project / "retrolarium-project.json")["status"],
            )

    def test_snes_launch_plan_uses_declared_machine_and_explicit_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom = root / "probe.sfc"
            rom.write_bytes(probe_image("lorom").container_data)
            project = root / "project"
            disassemble_snes(rom, project)
            rebuilt = project / "generated/build/rebuilt.sfc"
            rebuilt.parent.mkdir(parents=True, exist_ok=True)
            rebuilt.write_bytes(rom.read_bytes())
            mame = root / "consoles.exe"
            mame.write_bytes(b"mame")
            plan = launch_plan(
                project / "retrolarium-project.json",
                mame=mame,
                machine="snespal",
            )
            self.assertEqual("snes", plan["platform"])
            self.assertEqual("snespal", plan["arguments"][0])
            self.assertEqual("-cart", plan["arguments"][1])
            self.assertEqual(str(rebuilt), plan["arguments"][2])


if __name__ == "__main__":
    unittest.main()
