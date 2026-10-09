from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.reports.flicky_discrepancy_groups import (
    difference_segments,
    group_segments,
    instruction_groups,
    semantic_kind,
    source_spans,
)
from tools.reports.flicky_html_diff import SourceAtAddress


class FlickyDiscrepancyGroupTests(unittest.TestCase):
    def test_text_and_symbolic_pointer_kinds_are_preserved(self) -> None:
        text = SourceAtAddress(lines=['Message: dc.b "READY",0'])
        pointer = SourceAtAddress(lines=["Table: dc.l Target"])
        numeric = SourceAtAddress(lines=["Values: dc.w $ABCD, $10"])

        self.assertEqual("text", semantic_kind(text))
        self.assertEqual("dc.l.symbolic", semantic_kind(pointer))
        self.assertEqual("dc.w.numeric", semantic_kind(numeric))

    def test_adjacent_word_and_long_losses_form_one_rom_group(self) -> None:
        reference = {
            0x100: SourceAtAddress(lines=["Words: dc.w 1,2"], encoded=["0001 0002"]),
            0x104: SourceAtAddress(lines=["Ptrs: dc.l Target"], encoded=["0000 0200"]),
            0x108: SourceAtAddress(lines=["Target: rts"], encoded=["4E75"]),
        }
        generated = {
            0x100: SourceAtAddress(
                lines=["off_M68K_000100: dc.b $00,$01,$00,$02,$00,$00,$02,$00"],
                encoded=["0001 0002"],
            ),
            0x108: SourceAtAddress(lines=["loc_M68K_000108: rts"], encoded=["4E75"]),
        }

        segments = difference_segments(source_spans(reference), source_spans(generated))
        groups = group_segments(segments, reference, generated)

        self.assertEqual(1, len(groups))
        self.assertEqual("000100", groups[0]["start"])
        self.assertEqual("000108", groups[0]["end_exclusive"])
        self.assertEqual({"word-data": 4, "long-data": 4}, groups[0]["categories"])

    def test_instruction_gaps_are_grouped_by_encoded_adjacency(self) -> None:
        instructions = {0x10: b"\x00\x01", 0x12: b"\x02", 0x20: b"\x03"}

        groups = instruction_groups(set(instructions), instructions, "CPU-MISSED")

        self.assertEqual(2, len(groups))
        self.assertEqual(2, groups[0]["instruction_count"])
        self.assertEqual("0013", groups[0]["end_exclusive"])

    def test_numeric_words_promoted_to_symbols_are_false_pointers(self) -> None:
        reference = {
            0x100: SourceAtAddress(lines=["Data: dc.w $1234"], encoded=["1234"]),
            0x102: SourceAtAddress(lines=["After: rts"], encoded=["4E75"]),
        }
        generated = {
            0x100: SourceAtAddress(lines=["Table: dc.w Target-*"], encoded=["1234"]),
            0x102: SourceAtAddress(lines=["After: rts"], encoded=["4E75"]),
        }

        segments = difference_segments(source_spans(reference), source_spans(generated))

        self.assertEqual("false-pointer", segments[0].category)


if __name__ == "__main__":
    unittest.main()
