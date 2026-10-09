"""Compare the indexed scan to the original deliberately exhaustive scanner."""
from dataclasses import replace
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_disasm.m68k.instructions import instruction_sets
from retrolarium_disasm.megadrive import pointers
from retrolarium_disasm.facts import InstructionReference
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_z80 import fact


def exhaustive_relative(image, facts, policy):
    occupied, interiors, starts = instruction_sets(facts)
    references = pointers._referenced_addresses(facts)
    indexed = pointers._indexed_word_read_addresses(facts)
    result = []
    for start in range(0x200, max(0x200, len(image.data) - 5), 2):
        entries = []
        offset = start
        while offset + 2 <= len(image.data) and len(entries) < pointers.MAX_ENTRIES:
            if offset in occupied or offset + 1 in occupied:
                break
            if entries and image.header.rom_start + offset in references:
                break
            raw = int.from_bytes(image.data[offset:offset + 2], "big")
            signed = int.from_bytes(image.data[offset:offset + 2], "big", signed=True)
            base = image.header.rom_start + (start if policy == "table_base" else offset)
            if not pointers._mapped(image, base + signed):
                break
            entries.append(pointers.PointerEntry(offset, image.header.rom_start + offset,
                                                 raw, base + signed, base))
            offset += 2
        if len(entries) >= pointers.MIN_ENTRIES:
            candidate = pointers._evaluate(image, f"megadrive.s16be.target-{policy}",
                                           tuple(entries), 2, interiors, starts, references, indexed)
            if candidate is not None:
                result.append(candidate)
    return result


def fixture(words, *, table=0x300, targets=(0x500, 0x510, 0x520, 0x530),
            references=(), size=0x800, origin=0, length=2):
    data = bytearray(cartridge(size=size))
    data[0x200:] = b"\xFF" * (size - 0x200)
    data[0x1A0:0x1A4] = origin.to_bytes(4, "big")
    data[0x1A4:0x1A8] = (origin + size - 1).to_bytes(4, "big")
    data[4:8] = (origin + 0x200).to_bytes(4, "big")
    data[table:table + len(words) * 2] = b"".join((word & 0xFFFF).to_bytes(2, "big") for word in words)
    items = [replace(fact(target, "NOP", ""), cpu_address=origin + target, length=length)
             for target in targets]
    items.append(replace(fact(0x220, "MOVE.W", "(0x300,PC,D0w*0x1)|D0w"),
                         cpu_address=origin + 0x220,
                         references=tuple(InstructionReference(origin + address, "READ", 0)
                                          for address in references)))
    return parse_megadrive(bytes(data)), {item.physical_offset: item for item in items}


class RelativePointerScanEquivalenceTests(unittest.TestCase):
    def assert_same(self, image, facts):
        for policy in ("table_base", "entry_address"):
            with self.subTest(policy=policy):
                self.assertEqual(exhaustive_relative(image, facts, policy),
                                 pointers._relative_candidates(image, facts, policy))

    def test_repeated_words_and_overlapping_windows_keep_every_candidate(self):
        image, facts = fixture([0x200] * 90, targets=tuple(range(0x500, 0x5B4, 2)),
                               references=(0x300, 0x330))
        self.assert_same(image, facts)
        entry_tables = pointers._relative_candidates(image, facts, "entry_address")
        overlapping = [item for item in entry_tables if 0x330 <= item.physical_start < 0x338]
        self.assertEqual([0x330, 0x332, 0x334, 0x336], [item.physical_start for item in overlapping])
        self.assertEqual(64, len(overlapping[0].entries))

    def test_references_split_tables_but_odd_references_do_not(self):
        image, facts = fixture([0x200, 0x20E, 0x21C, 0x22A] * 2,
                               references=(0x300, 0x305, 0x308))
        self.assert_same(image, facts)
        table = next(item for item in pointers._relative_candidates(image, facts, "entry_address")
                     if item.physical_start == 0x300)
        self.assertEqual((0x308, "accepted"), (table.physical_end, table.status))

    def test_instruction_interior_targets_still_produce_rejected_candidate(self):
        image, facts = fixture([0x202, 0x20E, 0x21C, 0x22A], references=(0x300,), length=4)
        self.assert_same(image, facts)
        table = next(item for item in pointers._relative_candidates(image, facts, "entry_address")
                     if item.physical_start == 0x300)
        self.assertEqual("rejected", table.status)
        self.assertIn("target_inside_instruction", table.contradictions)

    def test_scan_only_exact_three_quarter_hit_threshold(self):
        image, facts = fixture([0x200, 0x20E, 0x21C, 0x23A], references=())
        self.assert_same(image, facts)
        table = next(item for item in pointers._relative_candidates(image, facts, "entry_address")
                     if item.physical_start == 0x300)
        self.assertEqual("candidate", table.status)
        _, fewer = fixture([0x200, 0x20E, 0x21C, 0x23A], targets=(0x500, 0x510), references=())
        self.assert_same(image, fewer)
        self.assertFalse(any(item.physical_start == 0x300
                             for item in pointers._relative_candidates(image, fewer, "entry_address")))

    def test_signed_limits_nonzero_origin_and_odd_file_length(self):
        image, facts = fixture([0x8000, 0x7FFE, 0xFFFE, 0, 2, 4], table=0x8100,
                               targets=(0x100, 0x80FE, 0x8104, 0x100FE), references=(0x8100,),
                               size=0x10201, origin=0x100000)
        self.assert_same(image, facts)

    def test_referenced_data_table_survives_without_nearby_code(self):
        image, facts = fixture([8, 10, 12, 14], table=0x9000, targets=(),
                               references=(0x9000,), size=0xA000)
        self.assert_same(image, facts)
        tables = pointers._relative_candidates(image, facts, "table_base")
        self.assertEqual("accepted", next(x for x in tables if x.physical_start == 0x9000).status)

    def test_occupied_entry_and_mapped_rom_end_cut_runs(self):
        image, facts = fixture([0x200] * 8, targets=(0x308, 0x500, 0x502, 0x504, 0x506),
                               references=(0x300,), size=0x508)
        self.assert_same(image, facts)
        for policy in ("table_base", "entry_address"):
            table = next(x for x in pointers._relative_candidates(image, facts, policy)
                         if x.physical_start == 0x300)
            self.assertEqual(0x308, table.physical_end)

    def test_randomized_signed_windows_match_exhaustive_scan(self):
        rng = random.Random(68000)
        for case in range(12):
            words = [rng.choice((rng.randrange(-0x200, 0x600, 2), 0, 2, 0x200, 0x201, -2))
                     for _ in range(95)]
            image, facts = fixture(words, targets=tuple(range(0x500, 0x700, 8)),
                                   references=(0x300, 0x30D, 0x320 + case * 2),
                                   origin=case * 0x10000)
            with self.subTest(case=case):
                self.assert_same(image, facts)


if __name__ == "__main__":
    unittest.main()
