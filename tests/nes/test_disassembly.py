from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_disassembler.nes.ca65 import emit_project, prg_source
from retrolarium_disassembler.nes import pipeline
from retrolarium_disassembler.facts import load_ghidra_facts
from retrolarium_disassembler.ghidra import GhidraArtifacts
from retrolarium_core.ines import InesError, parse_ines
from retrolarium_disassembler.nes.pipeline import (
    asset_manifest,
    disassemble_nrom,
)
from retrolarium_disassembler.verify import VerificationError, verify_exact
from retrolarium_disassembler.nes.pointers import detect_banked_pointer_candidates
from helpers import KIT, needs_kit, nrom16_image, write_facts

if KIT:
    from retrolarium_kit.core.build_toolchains import materialize_build_toolchain
    from retrolarium_kit.core.project import _ca65_build


class DisassemblyTests(unittest.TestCase):
    def test_banked_emitter_uses_independent_segments_and_symbols(self) -> None:
        header = b"NES\x1a" + bytes((8, 4, 0x20, 0x40)) + bytes(8)
        banks = []
        for bank_number in range(4):
            bank = bytearray(0x8000)
            bank[0] = 0x60
            bank[1] = bank_number
            bank[-6:] = bytes.fromhex("00 80 00 80 00 80")
            banks.append(bank)
        image = parse_ines(header + b"".join(banks) + bytes(4 * 0x2000))
        candidates = detect_banked_pointer_candidates(image, {})
        assets = asset_manifest(image)["items"]

        vectors = [
            candidate
            for candidate in candidates
            if candidate.schema_id == "nes.interrupt_vectors"
        ]
        self.assertEqual([0, 1, 2, 3], [candidate.bank for candidate in vectors])
        chr_assets = [asset for asset in assets if asset["kind"] == "chr_bank"]
        self.assertEqual(4, len(chr_assets))
        self.assertEqual(0x6000, chr_assets[3]["asset_file_offset"])
        self.assertEqual(
            [0x7FFA, 0xFFFA, 0x17FFA, 0x1FFFA],
            [candidate.physical_start for candidate in vectors],
        )
        self.assertEqual(
            [f"InterruptVectors_B{bank:02d}_FFFA" for bank in range(4)],
            [candidate.candidate_id for candidate in vectors],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(root, image, {}, candidates)
            bank_two = (root / "src/prg-bank02.asm").read_text(encoding="utf-8")
            linker = (root / "linker.cfg").read_text(encoding="utf-8")
            main = (root / "main.asm").read_text(encoding="utf-8")
            symbols = json.loads(
                (root / "symbols.json").read_text(encoding="utf-8")
            )

        self.assertIn("Func_B02_8000:", bank_two)
        self.assertIn("NmiVector_B02:", bank_two)
        self.assertIn('.segment "PRG02"', bank_two)
        self.assertIn("PRG00: start = $8000", linker)
        self.assertIn("PRG03: start = $8000", linker)
        self.assertIn('.include "src/prg-bank03.asm"', main)
        bank_two_symbols = [
            symbol
            for symbol in symbols["symbols"]
            if symbol["bank"] == 2 and symbol["cpu_address"] == 0x8000
        ]
        self.assertEqual("Func_B02_8000", bank_two_symbols[0]["symbol_id"])
        self.assertEqual(0x10000, bank_two_symbols[0]["physical_offset"])
        self.assertEqual("src/prg-bank02.asm", bank_two_symbols[0]["source_unit"])
        self.assertEqual(len(image.prg), result.raw_bytes + result.pointer_bytes)

    def test_fact_import_uses_explicit_prg_bank_context(self) -> None:
        header = b"NES\x1a" + bytes((8, 0, 0x20, 0x40)) + bytes(8)
        prg = bytearray(4 * 0x8000)
        prg[2 * 0x8000] = 0x60
        image = parse_ines(header + prg)
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "PRG0\tPRG0\t8000\t1\t60\tRTS\t\t\tTERMINATOR\t\tFUN_PRG0__8000\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_ghidra_facts(facts_path, image, bank=2)

        fact = facts[0x10000]
        self.assertEqual(2, fact.bank)
        self.assertEqual(0x10000, fact.physical_offset)

    def test_banked_mapper_is_rejected_before_external_toolchain_check(self) -> None:
        header = b"NES\x1a" + bytes((2, 1, 0x30, 0)) + bytes(8)
        image = header + bytes(0x8000 + 0x2000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom = root / "cnrom.nes"
            rom.write_bytes(image)
            with self.assertRaisesRegex(InesError, "NROM profile requires mapper 0"):
                disassemble_nrom(rom, root / "output", root / "missing-ghidra")

    def test_facts_map_to_physical_prg_and_emitter_covers_every_byte(self) -> None:
        image = parse_ines(nrom16_image())
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            write_facts(facts_path)
            facts = load_ghidra_facts(facts_path, image)
            source, result = prg_source(image, facts)

        self.assertEqual(3, result.instruction_count)
        self.assertEqual(6, result.instruction_bytes)
        self.assertEqual(6, result.pointer_bytes)
        self.assertEqual(len(image.prg), result.instruction_bytes + result.pointer_bytes + result.raw_bytes)
        self.assertIn("Func_B00_C000:", source)
        self.assertIn("BPL Func_B00_C000", source)
        self.assertIn("BIT a:$2002", source)
        self.assertIn("NmiVector:", source)
        self.assertIn(".addr Func_B00_C000", source)

    @needs_kit
    def test_project_externalizes_container_and_chr(self) -> None:
        image = parse_ines(nrom16_image())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            facts_path = root / "facts.tsv"
            write_facts(facts_path)
            facts = load_ghidra_facts(facts_path, image)
            emit_project(root / "generated", image, facts)
            self.assertEqual(image.header, (root / "generated/assets/header.bin").read_bytes())
            self.assertEqual(image.chr, (root / "generated/assets/chr.bin").read_bytes())
            self.assertIn('.include "src/prg.asm"', (root / "generated/main.asm").read_text())
            if os.name == "nt":
                project = root / "generated"
                suite = materialize_build_toolchain(
                    "nes", cache_root=root / "toolchains"
                )
                rebuilt = project / "build/rebuilt.nes"
                _ca65_build(
                    {
                        "source": "main.asm",
                        "linker_config": "linker.cfg",
                        "object": "build/main.o",
                        "map": "build/rebuilt.map",
                    },
                    project,
                    rebuilt,
                    suite,
                )
                self.assertEqual(image.data, rebuilt.read_bytes())

    def test_branch_into_instruction_uses_relocatable_expression(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:19] = bytes.fromhex("B0 FF 60")
        image = parse_ines(bytes(rom))
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "PRG0\tPRG0\tC000\t2\tB0 FF\tBCS\t0xc001\tPRG0::c001\tCONDITIONAL_JUMP\t\tFUN_PRG0__c000\n"
                "PRG0\tPRG0\tC002\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_ghidra_facts(facts_path, image)
            source, result = prg_source(image, facts)

        self.assertIn("BCS * + 1", source)
        self.assertIn("; $C000: B0 FF", source)
        self.assertIn(
            "bank 00 control target $C001 falls inside an instruction; kept numeric",
            result.diagnostics,
        )

    def test_three_byte_zero_page_address_is_forced_absolute(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:20] = bytes.fromhex("8D 57 00 60")
        image = parse_ines(bytes(rom))
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "PRG0\tPRG0\tC000\t3\t8D 57 00\tSTA\t0x0057\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
                "PRG0\tPRG0\tC003\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_ghidra_facts(facts_path, image)
            source, _ = prg_source(image, facts)

        self.assertIn("STA a:$57", source)

    def test_vector_target_inside_vector_block_remains_numeric(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16 + 0x4000 - 6:16 + 0x4000] = b"\xff" * 6
        image = parse_ines(bytes(rom))

        source, result = prg_source(image, {})

        self.assertEqual(3, source.count("    .addr $FFFF"))
        self.assertNotIn("Func_B00_FFFF", source)
        self.assertFalse(
            any(symbol.cpu_address == 0xFFFF for symbol in result.symbols)
        )

    def test_rts_dispatch_targets_feed_one_bounded_seeded_pass(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:25] = bytes.fromhex("BD 44 C1 48 BD 40 C1 48 60")
        for address in (0xC010, 0xC020, 0xC030, 0xC040):
            rom[16 + address - 0xC000] = 0x60
        rom[16 + 0x140:16 + 0x148] = bytes.fromhex("1F 0F 3F 2F C0 C0 C0 C0")
        image = parse_ines(bytes(rom))
        header = (
            "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
        )
        dispatch_rows = (
            "PRG0\tPRG0\tC000\t3\tBD 44 C1\tLDA\t0xc144,X\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
            "PRG0\tPRG0\tC003\t1\t48\tPHA\t\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC004\t3\tBD 40 C1\tLDA\t0xc140,X\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC007\t1\t48\tPHA\t\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC008\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n"
        )
        seed_plans: list[str] = []

        def write_artifacts(workspace: Path, rows: str) -> GhidraArtifacts:
            workspace.mkdir(parents=True, exist_ok=True)
            facts_path = workspace / "instructions.tsv"
            facts_path.write_text(header + rows, encoding="utf-8", newline="\n")
            report = workspace / "program.json"
            report.write_text(
                json.dumps({"language": "6502:LE:16:default", "compiler": "default"}),
                encoding="utf-8",
            )
            return GhidraArtifacts(
                facts=facts_path, report=report, log=workspace / "headless.log"
            )

        def first_pass(image_path, workspace, ghidra_home, scripts):
            return write_artifacts(workspace, dispatch_rows)

        def seeded_pass(image_path, workspace, ghidra_home, scripts, plan):
            text = plan.read_text(encoding="utf-8")
            seed_plans.append(text)
            rows = "".join(
                f"PRG0\tPRG0\t{line}\t1\t60\tRTS\t\t\tTERMINATOR\t\tFUN_PRG0__{line.lower()}\n"
                for line in text.split()
            )
            return write_artifacts(workspace, dispatch_rows + rows)

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            pipeline, "toolchain_status"
        ), mock.patch.object(
            pipeline, "run_nes_analysis", side_effect=first_pass
        ), mock.patch.object(
            pipeline, "_run_seeded_nes_analysis", side_effect=seeded_pass
        ) as seeded:
            facts, banks, _, candidates = pipeline._analyze_with_dispatch_passes(
                image, Path(directory), Path(directory) / "ghidra"
            )

        self.assertEqual(1, seeded.call_count)
        self.assertEqual(["C010\nC020\nC030\nC040\n"], seed_plans)
        for offset in (0x10, 0x20, 0x30, 0x40):
            self.assertIn(offset, facts)
        self.assertEqual(
            {"pass": 2, "requested": 4, "decoded": 4},
            {
                key: value
                for key, value in banks[0]["entry_seed_pass"].items()
                if key != "plan"
            },
        )
        table = next(
            candidate
            for candidate in candidates
            if candidate.schema_id == "nes.split_lo_hi.rts_minus_one"
        )
        self.assertEqual("accepted", table.status)
        self.assertEqual({}, pipeline.dispatch_entry_seeds(image, facts, candidates))

    def test_exact_verification_reports_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory) / "left.nes"
            right = Path(directory) / "right.nes"
            left.write_bytes(nrom16_image())
            right.write_bytes(nrom16_image()[:-1] + b"x")
            with self.assertRaises(VerificationError):
                verify_exact(left, right)


if __name__ == "__main__":
    unittest.main()
