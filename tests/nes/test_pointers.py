from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_disassembler.nes.ca65 import prg_source
from retrolarium_disassembler.facts import load_ghidra_facts
from retrolarium_core.ines import parse_ines
from retrolarium_disassembler.nes.pointers import (
    accepted_code_entry_tables,
    accepted_pointer_tables,
    accepted_u16le,
    detect_pointer_candidates,
    pointer_report,
)
from helpers import nrom16_image


class PointerDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:23] = bytes.fromhex("AD 00 C1 AD 20 C1 60")
        table = bytes.fromhex("00 C2 10 C2 20 C2 30 C2")
        rejected = bytes.fromhex("00 C3 00 C2 00 C4 00 C1")
        rom[16 + 0x100:16 + 0x108] = table
        rom[16 + 0x120:16 + 0x128] = rejected
        self.image = parse_ines(bytes(rom))

    def facts(self, root: Path):
        facts_path = root / "facts.tsv"
        facts_path.write_text(
            "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
            "PRG0\tPRG0\tC000\t3\tAD 00 C1\tLDA\t0xc100\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
            "PRG0\tPRG0\tC003\t3\tAD 20 C1\tLDA\t0xc120\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC006\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
            encoding="utf-8",
            newline="\n",
        )
        return load_ghidra_facts(facts_path, self.image)

    def test_accepts_compact_monotonic_table_and_rejects_lookalike(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            facts = self.facts(Path(directory))
            candidates = detect_pointer_candidates(self.image, facts)

        accepted = accepted_u16le(candidates)
        self.assertEqual([0xC100], [candidate.cpu_start for candidate in accepted])
        self.assertIn(
            "table_start_referenced_by_instruction", accepted[0].evidence
        )
        rejected = next(
            candidate
            for candidate in candidates
            if candidate.schema_id == "nes.u16le" and candidate.cpu_start == 0xC120
        )
        self.assertEqual("rejected", rejected.status)
        self.assertIn("targets_not_strictly_increasing", rejected.contradictions)

        report = pointer_report(self.image, candidates)
        self.assertEqual(1, report["schema_version"])
        self.assertEqual(self.image.sha256, report["input_sha256"])
        self.assertEqual(5, len(report["registry"]))

    def test_accepted_table_is_emitted_as_relocatable_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            facts = self.facts(Path(directory))
            candidates = detect_pointer_candidates(self.image, facts)
            source, result = prg_source(self.image, facts, candidates)

        self.assertIn("PtrTable_B00_C100:", source)
        self.assertIn("LDA a:PtrTable_B00_C100", source)
        self.assertIn(".addr Data_B00_C200", source)
        self.assertIn("Data_B00_C200:", source)
        self.assertEqual(14, result.pointer_bytes)
        self.assertEqual(
            len(self.image.prg),
            result.instruction_bytes + result.pointer_bytes + result.raw_bytes,
        )

    def test_adjacent_referenced_low_high_arrays_are_promoted(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:23] = bytes.fromhex("BD 40 C1 BD 44 C1 60")
        rom[16 + 0x140:16 + 0x148] = bytes.fromhex("00 10 20 30 C2 C2 C2 C2")
        image = parse_ines(bytes(rom))
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "PRG0\tPRG0\tC000\t3\tBD 40 C1\tLDA\t0xc140,X\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
                "PRG0\tPRG0\tC003\t3\tBD 44 C1\tLDA\t0xc144,X\t\tFALL_THROUGH\t\t\n"
                "PRG0\tPRG0\tC006\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_ghidra_facts(facts_path, image)
            candidates = detect_pointer_candidates(image, facts)
            source, result = prg_source(image, facts, candidates)

        split = [
            candidate
            for candidate in accepted_pointer_tables(candidates)
            if candidate.schema_id == "nes.split_lo_hi"
        ]
        self.assertEqual(1, len(split))
        self.assertEqual(0xC140, split[0].cpu_start)
        self.assertIn("PtrTable_B00_C140:", source)
        self.assertIn("PtrTableHi_B00_C144:", source)
        self.assertIn(".byte .lobyte(Data_B00_C200)", source)
        self.assertIn(".byte .hibyte(Data_B00_C200)", source)
        self.assertEqual(14, result.pointer_bytes)

    def test_mirrored_nrom_reference_is_compared_by_physical_offset(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:20] = bytes.fromhex("AD 00 81 60")
        rom[16 + 0x100:16 + 0x108] = bytes.fromhex(
            "00 C2 10 C2 20 C2 30 C2"
        )
        image = parse_ines(bytes(rom))
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "PRG0\tPRG0\tC000\t3\tAD 00 81\tLDA\t0x8100\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
                "PRG0\tPRG0\tC003\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_ghidra_facts(facts_path, image)
            candidates = detect_pointer_candidates(image, facts)

        accepted = accepted_u16le(candidates)
        self.assertEqual([0xC100], [candidate.cpu_start for candidate in accepted])
        self.assertIn("table_start_referenced_by_instruction", accepted[0].evidence)

    def test_anchored_record_and_interleaved_lanes_recover_nonmonotonic_tables(self) -> None:
        rom = bytearray(nrom16_image())
        rom[16:20] = bytes.fromhex("AD 00 C1 60")
        rom[16 + 0x100:16 + 0x108] = bytes.fromhex(
            "00 C2 00 C3 00 C4 00 C5"
        )
        rom[16 + 0x200:16 + 0x208] = bytes.fromhex(
            "70 08 C2 10 C2 10 C2 00"
        )
        rom[16 + 0x300:16 + 0x30C] = bytes.fromhex(
            "10 C3 10 C4 20 C3 20 C4 30 C3 30 C4"
        )
        image = parse_ines(bytes(rom))
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "PRG0\tPRG0\tC000\t3\tAD 00 C1\tLDA\t0xc100\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
                "PRG0\tPRG0\tC003\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_ghidra_facts(facts_path, image)
            candidates = detect_pointer_candidates(image, facts)
            source, _ = prg_source(image, facts, candidates)

        accepted = {
            candidate.cpu_start: candidate
            for candidate in accepted_pointer_tables(candidates)
        }
        self.assertIn(0xC201, accepted)
        self.assertIn(0xC300, accepted)
        self.assertTrue(
            any(item.startswith("anchored_record_start=") for item in accepted[0xC201].evidence)
        )
        self.assertIn(
            "two_interleaved_strictly_increasing_lanes",
            accepted[0xC300].evidence,
        )
        weaker_overlap = next(
            candidate for candidate in candidates if candidate.cpu_start == 0xC302
        )
        self.assertEqual("rejected", weaker_overlap.status)
        self.assertIn("overlaps_stronger_candidate", weaker_overlap.contradictions)
        self.assertIn("PtrTable_B00_C201:", source)
        self.assertIn("PtrTable_B00_C300:", source)

    HANDLER_FACTS = (
        "PRG0\tPRG0\tC010\t1\t60\tRTS\t\t\tTERMINATOR\t\tFUN_PRG0__c010\n"
        "PRG0\tPRG0\tC020\t1\t60\tRTS\t\t\tTERMINATOR\t\tFUN_PRG0__c020\n"
        "PRG0\tPRG0\tC030\t1\t60\tRTS\t\t\tTERMINATOR\t\tFUN_PRG0__c030\n"
        "PRG0\tPRG0\tC040\t1\t60\tRTS\t\t\tTERMINATOR\t\tFUN_PRG0__c040\n"
    )

    def _dispatch_image(self, code: str, tables: dict[int, str]):
        rom = bytearray(nrom16_image())
        code_bytes = bytes.fromhex(code)
        rom[16:16 + len(code_bytes)] = code_bytes
        for address in (0xC010, 0xC020, 0xC030, 0xC040):
            rom[16 + address - 0xC000] = 0x60
        for offset, payload in tables.items():
            data = bytes.fromhex(payload)
            rom[16 + offset:16 + offset + len(data)] = data
        return parse_ines(bytes(rom))

    def _load(self, image, rows: str):
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            facts_path.write_text(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                + rows
                + self.HANDLER_FACTS,
                encoding="utf-8",
                newline="\n",
            )
            return load_ghidra_facts(facts_path, image)

    def test_unordered_table_with_indirect_jump_dispatch_is_accepted(self) -> None:
        image = self._dispatch_image(
            "BD 00 C1 85 00 BD 01 C1 85 01 6C 00 00",
            {0x100: "30 C0 10 C0 40 C0 20 C0"},
        )
        facts = self._load(
            image,
            "PRG0\tPRG0\tC000\t3\tBD 00 C1\tLDA\t0xc100,X\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
            "PRG0\tPRG0\tC003\t2\t85 00\tSTA\t0x0000\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC005\t3\tBD 01 C1\tLDA\t0xc101,X\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC008\t2\t85 01\tSTA\t0x0001\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC00A\t3\t6C 00 00\tJMP\t(0x0000)\t\tCOMPUTED_JUMP\t\t\n",
        )
        candidates = detect_pointer_candidates(image, facts)

        table = next(
            candidate
            for candidate in candidates
            if candidate.schema_id == "nes.u16le" and candidate.cpu_start == 0xC100
        )
        self.assertEqual("accepted", table.status)
        self.assertEqual((), table.contradictions)
        self.assertIn("dispatch_reference=jmp_indirect", table.evidence)
        self.assertIn("targets_unordered_under_dispatch", table.evidence)
        self.assertEqual(
            [0xC030, 0xC010, 0xC040, 0xC020],
            [entry.target for entry in table.entries],
        )
        self.assertIn(table, accepted_code_entry_tables(candidates))

    def test_split_rts_dispatch_uses_target_minus_one(self) -> None:
        image = self._dispatch_image(
            "BD 44 C1 48 BD 40 C1 48 60",
            {0x140: "1F 0F 3F 2F C0 C0 C0 C0"},
        )
        facts = self._load(
            image,
            "PRG0\tPRG0\tC000\t3\tBD 44 C1\tLDA\t0xc144,X\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
            "PRG0\tPRG0\tC003\t1\t48\tPHA\t\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC004\t3\tBD 40 C1\tLDA\t0xc140,X\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC007\t1\t48\tPHA\t\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC008\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
        )
        candidates = detect_pointer_candidates(image, facts)

        table = next(
            candidate
            for candidate in candidates
            if candidate.schema_id == "nes.split_lo_hi.rts_minus_one"
        )
        self.assertEqual("accepted", table.status)
        self.assertEqual((0xC140, 0xC144), (table.cpu_start, table.entries[0].high_cpu_address))
        self.assertIn("dispatch_reference=rts", table.evidence)
        self.assertIn("stored_values_are_target_minus_one", table.evidence)
        self.assertEqual(
            [0xC020, 0xC010, 0xC040, 0xC030],
            [entry.target for entry in table.entries],
        )
        self.assertIn(table, accepted_code_entry_tables(candidates))
        # The emitter only knows plain schemas; RTS tables stay raw bytes.
        self.assertNotIn(table, accepted_pointer_tables(candidates))

    def test_u16le_rts_dispatch_uses_target_minus_one(self) -> None:
        image = self._dispatch_image(
            "BD 01 C1 48 BD 00 C1 48 60",
            {0x100: "2F C0 0F C0 3F C0 1F C0"},
        )
        facts = self._load(
            image,
            "PRG0\tPRG0\tC000\t3\tBD 01 C1\tLDA\t0xc101,X\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
            "PRG0\tPRG0\tC003\t1\t48\tPHA\t\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC004\t3\tBD 00 C1\tLDA\t0xc100,X\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC007\t1\t48\tPHA\t\t\tFALL_THROUGH\t\t\n"
            "PRG0\tPRG0\tC008\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
        )
        candidates = detect_pointer_candidates(image, facts)

        table = next(
            candidate
            for candidate in candidates
            if candidate.schema_id == "nes.u16le.rts_minus_one"
        )
        self.assertEqual("accepted", table.status)
        self.assertEqual("PtrTableRts_B00_C100", table.candidate_id)
        self.assertEqual(
            [0xC030, 0xC010, 0xC040, 0xC020],
            [entry.target for entry in table.entries],
        )
        self.assertNotIn("target_inside_instruction", table.contradictions)


if __name__ == "__main__":
    unittest.main()
