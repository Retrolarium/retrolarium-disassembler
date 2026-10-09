from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_core.contracts import (
    ContractError,
    load_disassembly_manifest,
    validate_megadrive_disassembly_manifest,
)
from helpers import KIT, needs_kit

if KIT:
    from retrolarium_kit.core.project import build_project, launch_plan, verify_project


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
    @unittest.skipUnless(os.name == "nt", "bundled PE smoke runs on Windows")
    @needs_kit
    def test_bundled_runner_builds_as_source_without_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_megadrive_project(root)
            generated = root / "generated"
            expected = (generated / "rebuilt.bin").read_bytes()
            lines = ["    org     $000000"]
            for offset in range(0, len(expected), 16):
                values = ", ".join(
                    f"${value:02X}" for value in expected[offset:offset + 16]
                )
                lines.append(f"    dc.b    {values}")
            (generated / "main.68k").write_text(
                "\n".join(lines) + "\n", encoding="ascii", newline="\n"
            )
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["operations"]["build"].update(
                {
                    "runner": "retrolarium-kit",
                    "toolchain_suite": "megadrive",
                    "recipe": "asl-p2bin-v1",
                    "source": "main.68k",
                    "object": "build/main.p",
                }
            )
            path.write_text(json.dumps(manifest), encoding="utf-8")
            (generated / "rebuilt.bin").unlink()

            result = build_project(path, toolchain_cache=root / "toolchains")

            self.assertEqual("retrolarium-kit", result["runner"]["kind"])
            self.assertEqual("asl-p2bin-v1", result["runner"]["recipe"])
            self.assertEqual(expected, (generated / "rebuilt.bin").read_bytes())
            self.assertEqual("exact", verify_project(path)["status"])

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

    @needs_kit
    def test_operations_use_declared_argv_and_megadrive_machine_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_megadrive_project(root)
            completed = subprocess.CompletedProcess([], 0)
            with patch("retrolarium_kit.core.project.subprocess.run", return_value=completed) as run:
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


class MegaDriveDisassemblyMetadataTests(unittest.TestCase):
    def test_cached_emission_rejects_another_rom_and_tampered_facts(self) -> None:
        from retrolarium_disassembler.megadrive import pipeline
        from retrolarium_disassembler.megadrive.emit import MegaDriveEmitError
        from test_megadrive import cartridge

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = cartridge(size=0x800)
            rom = root / "rom.bin"
            rom.write_bytes(data)
            analysis = root / "out" / "analysis"
            analysis.mkdir(parents=True)
            artifact = analysis / "facts.tsv"
            artifact.write_bytes(b"changed")
            record = {
                "schema": "retrolarium.megadrive.analysis",
                "input": {"sha256": "0" * 64, "size": len(data)},
                "programs": [{"raw_facts": "facts.tsv", "raw_facts_sha256": digest(b"original")}],
            }
            with patch.object(pipeline, "emit_project") as emit:
                for expected in ("different ROM", "artifact changed"):
                    (analysis / "analysis.json").write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(MegaDriveEmitError, expected):
                        pipeline.emit_analyzed_megadrive(rom, root / "out")
                    record["input"]["sha256"] = digest(data)
                emit.assert_not_called()

    def _disassemble(self, root: Path, *, build_container: str | None):
        from retrolarium_disassembler.megadrive import pipeline
        from retrolarium_disassembler.z80.dispatch import Z80DispatchTable

        analysis = root / "out" / "analysis"
        (analysis / "m68k").mkdir(parents=True)
        (analysis / "z80" / "program00").mkdir(parents=True)
        for name in (
            "analysis.json", "pointers.json", "symbols.json",
            "cross-cpu-evidence.json",
        ):
            (analysis / name).write_text("{}", encoding="utf-8")
        (analysis / "m68k" / "abstract-analysis.json").write_text(
            json.dumps({
                "control_flow": {"indirect_edges": []},
                "decoder_seed_addresses": [],
            }),
            encoding="utf-8",
        )
        (analysis / "m68k" / "instructions.json").write_text(
            json.dumps({"instructions": []}), encoding="utf-8",
        )
        (analysis / "z80" / "program00" / "dispatch-tables.json").write_text(
            json.dumps({
                "schema": "retrolarium.z80.dispatch-tables",
                "schema_version": 1,
                "tables": [{
                    "logical_start": 2,
                    "logical_end": 6,
                    "dispatch_address": 0,
                    "dispatch_addresses": [0],
                    "lookup_address": 2,
                    "targets": [0, 1],
                }],
            }),
            encoding="utf-8",
        )
        data = bytes(0x800)
        (analysis / "analysis.json").write_text(json.dumps({
            "schema": "retrolarium.megadrive.analysis",
            "input": {"sha256": digest(data), "size": len(data)},
            "programs": [{
                "cpu_id": "m68k",
                "instructions": "m68k/instructions.json",
            }],
        }), encoding="utf-8")
        image = SimpleNamespace(
            data=data,
            sha256=digest(data),
            header=SimpleNamespace(rom_start=0),
            actual_rom_end=0x7FF,
            checksum_status="valid",
        )
        copy = SimpleNamespace(
            edge_id="copy.00", source_start=0x400, source_end=0x405,
            target_start=0, target_end=5, size=6,
            payload_sha256=digest(bytes(6)),
        )
        emitted = SimpleNamespace(
            source_units=("src/main.s",),
            assets=(),
            z80_builds=(),
            instruction_bytes=0,
            symbolic_instruction_bytes=0,
            pointer_bytes=0,
            asset_bytes=0,
            raw_bytes=0,
            padding_bytes=0,
        )
        rebuilt = root / "out" / "generated" / "rebuilt.bin"
        with patch.object(pipeline, "load_megadrive", return_value=image), \
                patch.object(pipeline, "analyze_megadrive",
                             return_value={"programs": []}), \
                patch.object(pipeline, "load_megadrive_ghidra_facts",
                             return_value={}), \
                patch.object(pipeline, "retain_trusted_instruction_facts",
                             return_value={}), \
                patch.object(pipeline, "detect_pointer_candidates",
                             return_value=()), \
                patch.object(pipeline, "detect_z80_copies",
                             return_value=(copy,)), \
                patch.object(pipeline, "load_z80_ghidra_facts",
                             return_value={}), \
                patch.object(pipeline, "generate_symbols", return_value=()), \
                patch.object(pipeline, "image_manifest", return_value={}), \
                patch.object(pipeline, "emit_project",
                             return_value=emitted) as emit, \
                patch.object(pipeline, "validate_megadrive_disassembly_manifest"), \
                patch.object(pipeline, "_build_emitted_project",
                             return_value=rebuilt) as build, \
                patch("retrolarium_disassembler.verify.verify_exact",
                      return_value={"status": "exact"}):
            manifest = pipeline.disassemble_megadrive(
                root / "rom.bin", root / "out", root / "ghidra",
                build_container=build_container,
            )
        expected_tables = ((Z80DispatchTable(
            logical_start=2, logical_end=6, dispatch_address=0,
            lookup_address=2, targets=(0, 1), dispatch_addresses=(0,),
        ),),)
        return manifest, emit, build, expected_tables

    def test_metadata_describes_asl_and_is_unverified_without_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, emit, build, tables = self._disassemble(
                Path(directory), build_container=None
            )
        build.assert_not_called()
        self.assertEqual(tables, emit.call_args.args[7])
        source = manifest["source"]
        operation = manifest["operations"]["build"]
        self.assertEqual("asl-exact-first", source["dialect"])
        self.assertEqual(
            "unverified-mnemonics-with-exact-byte-fallback",
            source["instruction_encoding"],
        )
        self.assertEqual("asl-p2bin-v1", operation["recipe"])
        self.assertEqual("retrolarium-kit", operation["runner"])
        self.assertEqual("build/main.p", operation["object"])
        self.assertNotIn("argv", operation)
        self.assertEqual({"status": "not-run"}, manifest["verification"])

    def test_instruction_encoding_is_verified_after_exact_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, _, build, _ = self._disassemble(
                Path(directory), build_container="asl:latest"
            )
        build.assert_called_once()
        self.assertEqual("exact", manifest["verification"]["status"])
        self.assertEqual(
            "verified-mnemonics-with-exact-byte-fallback",
            manifest["source"]["instruction_encoding"],
        )
        operation = manifest["operations"]["build"]
        self.assertEqual("docker", operation["runner"])
        self.assertEqual("sh", operation["argv"][0])
        self.assertIn("asl -xx", operation["argv"][2])


if __name__ == "__main__":
    unittest.main()
