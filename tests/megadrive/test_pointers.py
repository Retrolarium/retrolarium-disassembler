from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.facts import InstructionFact, InstructionReference
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_pointers import detect_pointer_candidates
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class MegaDrivePointerTests(unittest.TestCase):
    def test_recovers_counted_animation_offsets_into_ram_copy(self) -> None:
        data = bytearray(cartridge(size=0x1200))
        data[0x220:0x23C] = bytes.fromhex(
            "41 F9 00 00 04 00 43 F9 00 FF 00 00 "
            "30 3C 02 FF 22 D8 51 C8 FF FC 4E F9 00 FF 00 00"
        )
        data[0x500:0x50A] = bytes.fromhex(
            "00 00 05 04 02 03 06 00 06 08"
        )
        image = parse_megadrive(bytes(data))
        facts = {
            0x280: replace(
                fact(0x280, "MOVEA.L", "(0x8,A0)|A1"), length=4
            ),
            0x284: replace(
                fact(0x284, "MOVEA.L", "(0x0,A1,D0w*0x1)|A1"), length=4
            ),
            0x288: replace(
                fact(0x288, "MOVEQ", "-0x1|D1"), length=2
            ),
            0x28A: replace(
                fact(0x28A, "MOVE.W", "(0x2,A1,D0w*0x1)|D1w"), length=4
            ),
            0x290: replace(
                fact(0x290, "MOVE.L", "#0x500|(0x8,A0)"), length=6
            ),
        }

        accepted = {
            (item.schema_id, item.physical_start): item
            for item in detect_pointer_candidates(image, facts)
            if item.status == "accepted"
        }

        root = accepted[("megadrive.u32be.absolute", 0x500)]
        sequence = accepted[
            ("megadrive.counted-u16be.ram-copy-offset", 0x504)
        ]
        self.assertEqual((0x504,), tuple(entry.target for entry in root.entries))
        self.assertEqual((0xA00, 0xA08), tuple(
            entry.target for entry in sequence.entries
        ))
        self.assertEqual(0x400, sequence.entries[0].base_address)

    def test_accepts_loader_proven_counted_ram_trampoline_table(self) -> None:
        data = bytearray(cartridge(size=0x500))
        data[0x220:0x238] = bytes.fromhex(
            "41 FA 00 3E 43 F8 FF 00 30 18 32 FC 4E F9 "
            "72 00 32 18 22 C1 51 C8 FF F4"
        )
        targets = (0x280, 0x290, 0x2A0, 0x2B0)
        data[0x260:0x26A] = (
            (len(targets) - 1).to_bytes(2, "big")
            + b"".join(target.to_bytes(2, "big") for target in targets)
        )
        image = parse_megadrive(bytes(data))
        facts = {target: fact(target, "RTS", "") for target in targets}

        candidates = detect_pointer_candidates(image, facts)
        counted = next(
            item for item in candidates
            if item.schema_id == "megadrive.counted-u16be.absolute"
        )

        self.assertEqual("accepted", counted.status)
        self.assertEqual((0x260, 0x26A), (
            counted.physical_start, counted.physical_end
        ))
        self.assertEqual(targets, tuple(entry.target for entry in counted.entries))

    def test_accepts_absolute_and_table_relative_oracle_tables(self) -> None:
        data = bytearray(cartridge())
        targets = (0x200, 0x206, 0x23C, 0x23E)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in targets
        )
        data[0x250:0x258] = b"".join(
            (target - 0x250).to_bytes(2, "big", signed=True)
            for target in targets
        )
        image = parse_megadrive(bytes(data))
        table_references = (
            InstructionReference(0x240, "DATA", 0),
            InstructionReference(0x250, "DATA", 1),
        )
        facts: dict[int, InstructionFact] = {
            target: fact(target, "RTS", "") for target in targets
        }
        facts[0x200] = replace(
            facts[0x200], references=table_references
        )

        candidates = detect_pointer_candidates(image, facts)
        accepted = {
            (item.schema_id, item.physical_start): item
            for item in candidates
            if item.status == "accepted"
        }

        absolute = accepted[("megadrive.u32be.absolute", 0x240)]
        relative = accepted[("megadrive.s16be.target-table_base", 0x250)]
        self.assertEqual(targets, tuple(entry.target for entry in absolute.entries))
        self.assertEqual(targets, tuple(entry.target for entry in relative.entries))
        self.assertEqual(0x250, relative.entries[-1].base_address)
        self.assertIn(
            ("megadrive.m68k-vectors.u32be-masked24", 4), accepted
        )

    def test_unreferenced_code_looking_table_remains_candidate(self) -> None:
        data = bytearray(cartridge())
        targets = (0x200, 0x206, 0x23C, 0x23E)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in targets
        )
        image = parse_megadrive(bytes(data))
        facts = {target: fact(target, "RTS", "") for target in targets}

        candidates = detect_pointer_candidates(image, facts)
        table = next(
            item for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.physical_start == 0x240
        )

        self.assertEqual("candidate", table.status)
        self.assertIn("scan_only_no_table_reference", table.evidence)

    def test_accepts_forward_data_pointers_read_by_indexed_long_moves(self) -> None:
        data = bytearray(cartridge())
        first_targets = (0x300, 0x310, 0x320, 0x330)
        second_targets = (0x340, 0x350, 0x360, 0x370)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in first_targets
        )
        data[0x250:0x260] = b"".join(
            target.to_bytes(4, "big") for target in second_targets
        )
        image = parse_megadrive(bytes(data))
        facts = {
            0x200: replace(
                fact(0x200, "MOVE.L", "(0x240,PC,D0w*0x1)|D1"),
                references=(InstructionReference(0x240, "DATA", 0),),
            ),
            0x202: replace(
                fact(0x202, "MOVE.L", "(0x250,PC,D0w*0x1)|D1"),
                references=(InstructionReference(0x250, "DATA", 0),),
            ),
        }

        candidates = detect_pointer_candidates(image, facts)
        accepted = {
            item.physical_start: item
            for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.status == "accepted"
        }

        self.assertEqual({0x240, 0x250}, accepted.keys())
        self.assertEqual(first_targets, tuple(
            entry.target for entry in accepted[0x240].entries
        ))
        self.assertIn(
            "table_read_by_indexed_move_l", accepted[0x240].evidence
        )

    def test_indexed_long_numeric_values_before_table_stay_candidate(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x290] = b"".join(
            value.to_bytes(4, "big") for value in (0x100, 0x120, 0x140, 0x160)
        )
        image = parse_megadrive(bytes(data))
        source = replace(
            fact(0x200, "MOVE.L", "(0x280,PC,D0w*0x1)|D1"),
            references=(InstructionReference(0x280, "DATA", 0),),
        )

        candidates = detect_pointer_candidates(image, {0x200: source})
        table = next(
            item for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.physical_start == 0x280
        )

        self.assertEqual("candidate", table.status)
        self.assertNotIn("all_targets_follow_table", table.evidence)

    def test_mapped_looking_words_are_not_auto_accepted(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x288] = bytes.fromhex("02 00 02 20 02 40 02 60")
        image = parse_megadrive(bytes(data))
        facts = {0x200: fact(0x200, "RTS", "")}

        accepted_ranges = {
            (item.physical_start, item.physical_end)
            for item in detect_pointer_candidates(image, facts)
            if item.status == "accepted"
        }

        self.assertNotIn((0x280, 0x288), accepted_ranges)

    def test_referenced_mixed_descriptor_stays_a_candidate(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x288] = bytes.fromhex("02 00 00 02 02 20 00 04")
        image = parse_megadrive(bytes(data))
        reference = InstructionReference(0x280, "DATA", 0)
        source = replace(
            fact(0x200, "LEA", "(0x7c,PC)|A0"), references=(reference,)
        )
        facts = {
            0x200: source,
            0x220: fact(0x220, "RTS", ""),
        }

        candidates = detect_pointer_candidates(image, facts)
        matching = [
            item
            for item in candidates
            if item.schema_id == "megadrive.u16be.absolute"
            and item.physical_start == 0x280
        ]

        self.assertTrue(matching)
        self.assertEqual("candidate", matching[0].status)


if __name__ == "__main__":
    unittest.main()
