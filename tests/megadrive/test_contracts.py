from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.contracts import (
    ContractError,
    load_disassembly_manifest,
    validate_megadrive_disassembly_manifest,
)
from retrolarium_kit.project import build_project, launch_plan, verify_project


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_megadrive_project(root: Path) -> Path:
    rom = bytearray(0x200)
    rom[0x100:0x110] = b"SEGA MEGA DRIVE "
    rom[0x1F0:0x1F3] = b"JUE"
    rom = bytes(rom)
    input_sha256 = digest(rom)
    analysis_root = root / "analysis"
    program_files = {
        "m68k/analysis-input.bin": rom,
        "m68k/instructions.json": b"{}",
        "m68k/instructions.tsv": b"address\tbytes\n",
        "m68k/program.json": b"{}",
    }
    for relative, payload in program_files.items():
        path = analysis_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    program = {
        "cpu_id": "m68k",
        "address_space": "m68k",
        "byte_order": "big",
        "language": "68000:BE:32:default",
        "analysis_input": "m68k/analysis-input.bin",
        "analysis_input_sha256": input_sha256,
        "instructions": "m68k/instructions.json",
        "instructions_sha256": digest(program_files["m68k/instructions.json"]),
        "raw_facts": "m68k/instructions.tsv",
        "raw_facts_sha256": digest(program_files["m68k/instructions.tsv"]),
        "report": "m68k/program.json",
        "report_sha256": digest(program_files["m68k/program.json"]),
    }
    documents = {
        "analysis.json": {
            "schema": "retrolarium.megadrive.analysis",
            "schema_version": 1,
            "task": "megadrive.analyze",
            "input": {"sha256": input_sha256, "size": len(rom)},
            "programs": [program],
        },
        "pointers.json": {
            "schema": "retrolarium.megadrive.pointers",
            "schema_version": 1,
            "input_sha256": input_sha256,
            "candidates": [],
        },
        "symbols.json": {
            "schema": "retrolarium.symbols",
            "schema_version": 1,
            "input_sha256": input_sha256,
            "symbols": [],
        },
        "cross-cpu-evidence.json": {
            "schema": "retrolarium.cross-cpu-evidence",
            "schema_version": 1,
            "platform": "megadrive",
            "input_sha256": input_sha256,
            "edges": [],
        },
    }
    for name, document in documents.items():
        (analysis_root / name).write_text(json.dumps(document), encoding="utf-8")

    generated = root / "generated"
    (generated / "assets").mkdir(parents=True)
    (generated / "src").mkdir()
    (generated / "assets/header.bin").write_bytes(rom[0x100:0x200])
    (generated / "src/vectors.68k").write_text("    dc.l $00000000\n")
    (generated / "main.68k").write_text('    include "src/vectors.68k"\n')
    (generated / "rebuilt.bin").write_bytes(rom)
    manifest = {
        "schema": "retrolarium.megadrive.disassembly",
        "schema_version": 1,
        "task": "megadrive.disassemble",
        "mode": "blind",
        "input": {
            "schema": "retrolarium.megadrive.image",
            "schema_version": 1,
            "sha256": input_sha256,
            "size": len(rom),
            "byte_order": "big",
            "cpu": "m68000",
        },
        "analysis": {
            "path": "analysis/analysis.json",
            "sha256": digest((analysis_root / "analysis.json").read_bytes()),
            "program_count": 1,
        },
        "pointers": {
            "path": "analysis/pointers.json",
            "sha256": digest((analysis_root / "pointers.json").read_bytes()),
        },
        "symbols": {
            "path": "analysis/symbols.json",
            "sha256": digest((analysis_root / "symbols.json").read_bytes()),
        },
        "cross_cpu_evidence": {
            "path": "analysis/cross-cpu-evidence.json",
            "sha256": digest((analysis_root / "cross-cpu-evidence.json").read_bytes()),
        },
        "assets": {
            "schema": "retrolarium.assets",
            "schema_version": 1,
            "items": [{
                "id": "megadrive.cartridge.header",
                "kind": "container_header",
                "path": "generated/assets/header.bin",
                "rom_file_offset": 0x100,
                "size": 0x100,
                "sha256": digest(rom[0x100:0x200]),
            }],
        },
        "source": {
            "dialect": "asm68k-exact-first",
            "units": ["generated/main.68k", "generated/src/vectors.68k"],
            "coverage": {
                "rom_bytes": len(rom),
                "vector_bytes": 0x100,
                "instruction_bytes": 0,
                "pointer_bytes": 0,
                "asset_bytes": 0x100,
                "raw_bytes": 0,
            },
        },
        "operations": {
            "build": {
                "id": "retrolarium.project.build",
                "runner": "docker",
                "default_container": "asm68k:test",
                "project_directory": "generated",
                "argv": ["asm68k", "/p", "main.68k,rebuilt.bin"],
                "output": "generated/rebuilt.bin",
            },
            "verify": {
                "id": "retrolarium.project.verify",
                "artifact": "generated/rebuilt.bin",
                "expected_sha256": input_sha256,
                "expected_size": len(rom),
            },
            "launch": {
                "id": "retrolarium.project.launch",
                "platform": "megadrive",
                "artifact": "generated/rebuilt.bin",
                "default_machine": "genesis",
                "supported_machines": ["genesis", "megadriv"],
                "supported_modes": ["interactive-plan", "smoke"],
            },
        },
        "verification": {
            "status": "exact",
            "original_sha256": input_sha256,
            "rebuilt_sha256": input_sha256,
        },
    }
    path = root / "retrolarium-project.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class MegaDriveContractTests(unittest.TestCase):
    def test_contract_loads_exact_portable_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_megadrive_project(Path(directory))
            manifest = load_disassembly_manifest(path)
            self.assertEqual("retrolarium.megadrive.disassembly", manifest["schema"])
            self.assertNotIn("source", manifest["input"])

    def test_contract_rejects_tampered_analysis_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_megadrive_project(root)
            manifest = json.loads(path.read_text())
            (root / "analysis/m68k/analysis-input.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ContractError, "SHA-256"):
                validate_megadrive_disassembly_manifest(manifest, root)

    def test_operations_use_declared_argv_and_megadrive_machine_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_megadrive_project(root)
            completed = subprocess.CompletedProcess([], 0)
            with patch("retrolarium_kit.project.subprocess.run", return_value=completed) as run:
                self.assertEqual("built", build_project(path)["status"])
            self.assertEqual(
                ["asm68k", "/p", "main.68k,rebuilt.bin"],
                run.call_args.args[0][-3:],
            )
            self.assertEqual("exact", verify_project(path)["status"])
            mame = root / "consoles.exe"
            mame.write_bytes(b"mame")
            plan = launch_plan(path, mame=mame, machine="megadriv")
            self.assertEqual("megadrive", plan["platform"])
            self.assertEqual("megadriv", plan["arguments"][0])
            with self.assertRaisesRegex(Exception, "unsupported megadrive"):
                launch_plan(path, mame=mame, machine="nes")


if __name__ == "__main__":
    unittest.main()
