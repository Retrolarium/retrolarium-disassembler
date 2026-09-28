from __future__ import annotations

import json
import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from source_benchmark import (
    compare_z80_program,
    instruction_quality,
    read_listing,
    same_instruction,
    z80_instruction_comparison,
)


def listing_line(address: int, encoded: str, source: str, column: int) -> str:
    return f"   1/{address:8X} : {encoded.ljust(column)}{source}"


class SourceBenchmarkTests(unittest.TestCase):
    def test_instruction_quality_reports_recall_precision_and_f1(self) -> None:
        self.assertEqual(
            {
                "instruction_recall_percentage": 80.0,
                "instruction_precision_percentage": 88.89,
                "instruction_f1_percentage": 84.21,
            },
            instruction_quality(80, 100, 90),
        )

    def test_empty_instruction_sets_are_perfect(self) -> None:
        self.assertEqual(
            {
                "instruction_recall_percentage": 100.0,
                "instruction_precision_percentage": 100.0,
                "instruction_f1_percentage": 100.0,
            },
            instruction_quality(0, 0, 0),
        )

    def test_truncated_listing_recovers_length_from_next_line(self) -> None:
        rom = bytes.fromhex("33FC 0001 00A1 1100 4E75 4EB9 0000")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "main.lst"
            path.write_text("\n".join([
                listing_line(0, "33FC 0001 00A1", "move.w #1,($A11100).l", 21),
                listing_line(8, "4E75", "rts", 21),
                listing_line(10, "4EB9 0000", "jsr (Target).l", 21),
            ]) + "\n", encoding="utf-8")
            known, open_ended = read_listing(path, rom)

        self.assertEqual(rom[:8], known[0])
        self.assertEqual(frozenset(), open_ended)
        self.assertTrue(same_instruction(known[0], rom[:8]))
        # A six-byte shared prefix must not match a different length.
        self.assertFalse(same_instruction(known[0], rom[:6]))
        self.assertFalse(same_instruction(known[0], rom[:8] + b"\0\0"))

    def test_unbounded_truncated_listing_stays_open_ended(self) -> None:
        rom = bytes.fromhex("33FC 0001 00A1 1100")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "main.lst"
            path.write_text(
                listing_line(0, "33FC 0001 00A1", "move.w #1,($A11100).l", 21) + "\n",
                encoding="utf-8",
            )
            known, open_ended = read_listing(path, rom)

        self.assertEqual(frozenset({0}), open_ended)
        self.assertTrue(same_instruction(known[0], rom, expected_open=True))
        self.assertFalse(same_instruction(known[0], rom))

    def test_absolute_jump_does_not_absorb_gap_before_data(self) -> None:
        rom = bytes.fromhex("4EF9 0001 865E 000E 8D92 0001")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "main.lst"
            path.write_text("\n".join([
                listing_line(0, "4EF9 0001 865E", "jmp Target", 21),
                listing_line(10, "0001", "dc.w 1", 21),
            ]) + "\n", encoding="utf-8")
            known, open_ended = read_listing(path, rom)
        self.assertEqual(rom[:6], known[0])
        self.assertEqual(frozenset(), open_ended)

    def test_short_listing_requires_exact_length(self) -> None:
        self.assertTrue(same_instruction(b"\x4e\x75", b"\x4e\x75"))
        self.assertFalse(same_instruction(b"\x4e\x75", b"\x4e\x75\x00\x00"))

    def test_z80_program_only_owns_reference_bytes_it_contains(self) -> None:
        known = {0x0000: b"\x3e\x01", 0x1000: b"\xc9", 0x1001: b"\x00"}
        result = compare_z80_program(
            known, 0x1000, b"\xc9\xaf", {0x1000: b"\xc9", 0x1001: b"\xaf"}
        )

        self.assertEqual(1, result["reference_instructions"])
        self.assertEqual(1, result["matching_instruction_starts"])
        self.assertEqual(1, result["other_generated_instructions"])

    def test_z80_comparison_includes_every_program(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "project" / "source"
            output = root / "comparison"
            (output / "reference").mkdir(parents=True)
            (output / "reference" / "z80_driver.lst").write_text("\n".join([
                listing_line(0x0000, "3E 01", "ld a,1", 36),
                listing_line(0x0002, "C9", "ret", 36),
                listing_line(0x1000, "AF", "xor a", 36),
                listing_line(0x1001, "C9", "ret", 36),
            ]) + "\n", encoding="utf-8")
            (generated / "build").mkdir(parents=True)
            programs = {
                "program00": (0x0000, bytes.fromhex("3E01C9"), [(0, "3E 01"), (2, "C9")]),
                "program01": (0x1000, bytes.fromhex("AFC9"), [(0, "AF"), (1, "C9")]),
            }
            for name, (base, payload, facts) in programs.items():
                (generated / "build" / f"z80-{name}.bin").write_bytes(payload)
                facts_root = generated.parent / "analysis" / "z80" / name
                facts_root.mkdir(parents=True)
                (facts_root / "instructions.json").write_text(json.dumps({
                    "instructions": [
                        {"physical_offset": offset, "logical_address": base + offset,
                         "bytes": raw}
                        for offset, raw in facts
                    ]
                }), encoding="utf-8")
            report = z80_instruction_comparison(root / "reference", generated, output)

        assert report is not None
        self.assertEqual(2, len(report["programs"]))
        self.assertEqual(4, report["reference_instructions"])
        self.assertEqual(4, report["matching_instruction_starts"])
        self.assertEqual(100.0, report["matching_instruction_percentage"])
        self.assertEqual(0, report["unattributed_reference_instructions"])


if __name__ == "__main__":
    unittest.main()
