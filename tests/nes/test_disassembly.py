from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.ca65 import emit_project, prg_source
from retrolarium_kit.facts import load_ghidra_facts
from retrolarium_kit.ines import parse_ines
from retrolarium_kit.pipeline import PipelineError, verify_exact
from helpers import nrom16_image, write_facts


class DisassemblyTests(unittest.TestCase):
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
            "control target $C001 falls inside an instruction; kept numeric",
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

    def test_exact_verification_reports_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory) / "left.nes"
            right = Path(directory) / "right.nes"
            left.write_bytes(nrom16_image())
            right.write_bytes(nrom16_image()[:-1] + b"x")
            with self.assertRaises(PipelineError):
                verify_exact(left, right)


if __name__ == "__main__":
    unittest.main()
