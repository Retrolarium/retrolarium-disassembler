from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_disassembler.facts import FactError, InstructionFact, InstructionReference, load_z80_ghidra_facts
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.z80 import (
    CrossCpuCopy, detect_z80_copies, fragment_z80_facts,
    group_z80_copies, z80_im1_handler_seed,
)
from megadrive.builders import cartridge
from megadrive.builders import fact


COPY_ROUTINE = (
    fact(0x200, "MOVEM.L", "{ A0 D0 D1}|-(SP)"),
    fact(0x204, "LEA", "(0xa00000).l|A1"),
    fact(0x206, "ADDA.W", "D1w|A1"),
    fact(0x208, "MOVE.B", "(A0)+|D1b"),
    fact(0x20A, "MOVE.B", "D1b|(A1)"),
    fact(0x20C, "ADDQ.W", "0x1|A1"),
    fact(0x20E, "DBF", "D0w|0x00000208", flows=(0x208,)),
)


class MegaDriveZ80Tests(unittest.TestCase):
    def test_unrooted_z80_copy_may_have_no_instructions(self) -> None:
        header = "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
        with tempfile.TemporaryDirectory() as temporary:
            listing = Path(temporary) / "instructions.tsv"
            listing.write_text(header, encoding="utf-8")
            self.assertEqual({}, load_z80_ghidra_facts(listing, b"\xFF" * 16, base_address=0x1C00))
            with self.assertRaisesRegex(FactError, "no instructions"):
                load_z80_ghidra_facts(listing, b"\xFF" * 16)

    def test_unrooted_copy_still_rejects_corrupt_instruction_bytes(self) -> None:
        text = ("block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
                "Z80_RAM\tram\t1C00\t1\t00\tNOP\t\t\tFALL_THROUGH\t\t\n")
        with tempfile.TemporaryDirectory() as temporary:
            listing = Path(temporary) / "instructions.tsv"
            listing.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(FactError, "bytes disagree"):
                load_z80_ghidra_facts(listing, b"\xFF", base_address=0x1C00)

    def test_adjacent_fragments_form_one_logical_image(self) -> None:
        first = CrossCpuCopy(
            edge_id="first", schema_id="test", source_cpu_id="m68k",
            source_space="m68k", source_start=0x280, source_end=0x283,
            target_cpu_id="z80.00", target_space="z80", target_start=0,
            target_end=3, size=4, payload_sha256="0" * 64,
            evidence_addresses=(), confidence="proven-static-copy",
        )
        second = replace(
            first, edge_id="second", source_start=0x290,
            source_end=0x293, target_start=4, target_end=7,
        )
        logical, = group_z80_copies((second, first))
        self.assertEqual(("first", "second"), tuple(
            copy.edge_id for copy in logical.fragments
        ))
        facts = {
            3: fact(3, "JP", "0x0004"),
            4: fact(4, "RET", ""),
        }
        self.assertEqual({}, fragment_z80_facts(logical, facts, first))
        sliced = fragment_z80_facts(logical, facts, second)
        self.assertEqual([0], list(sliced))
        self.assertEqual(4, sliced[0].cpu_address)

    def test_gaps_and_overlaps_stay_separate(self) -> None:
        first = CrossCpuCopy(
            edge_id="first", schema_id="test", source_cpu_id="m68k",
            source_space="m68k", source_start=0x280, source_end=0x283,
            target_cpu_id="z80.00", target_space="z80", target_start=0,
            target_end=3, size=4, payload_sha256="0" * 64,
            evidence_addresses=(), confidence="proven-static-copy",
        )
        gap = replace(
            first, edge_id="gap", source_start=0x290, source_end=0x293,
            target_start=8, target_end=11,
        )
        overlap = replace(
            first, edge_id="overlap", source_start=0x2A0,
            source_end=0x2A3, target_start=2, target_end=5,
        )
        self.assertEqual(2, len(group_z80_copies((first, gap))))
        self.assertEqual(2, len(group_z80_copies((first, overlap))))

    def test_copy_length_from_end_minus_source_addresses(self) -> None:
        # Compiled C: n = end - src; while (n--) *dst++ = *src++;
        image = parse_megadrive(cartridge())
        sequence = (
            fact(0x200, "LEA", "(0x280).l|A0"),
            fact(0x206, "LEA", "(0x2c0).l|A1"),
            fact(0x20C, "MOVE.L", "A1|D0"),
            fact(0x20E, "SUB.L", "A0|D0"),
            fact(0x210, "SUBQ.W", "0x1|D0w"),
            fact(0x212, "LEA", "(0xa00000).l|A1"),
            fact(0x218, "MOVE.B", "(A0)+|(A1)+"),
            fact(0x21A, "DBF", "D0w|0x00000218", flows=(0x218,)),
        )
        copy, = detect_z80_copies(image, {item.physical_offset: item for item in sequence})
        self.assertEqual((0x280, 0x2BF, 0, 0x40),
                         (copy.source_start, copy.source_end, copy.target_start, copy.size))
        # The subtracted register must be the copy source.
        broken = tuple(replace(item, operands="A2|D0") if item.cpu_address == 0x20E else item
                       for item in sequence)
        self.assertEqual((), detect_z80_copies(image, {item.physical_offset: item for item in broken}))

    def test_a_later_write_of_the_source_register_is_not_skipped(self) -> None:
        # A0 is set again by the MOVEA after its LEA: the copy reads from
        # $400, which the LEA does not prove.
        image = parse_megadrive(cartridge())
        sequence = (
            fact(0x200, "LEA", "(0x300).l|A0"),
            fact(0x206, "LEA", "(0x400).l|A2"),
            fact(0x20C, "MOVEA.L", "A2|A0"),
            fact(0x20E, "LEA", "(0xa00000).l|A1"),
            fact(0x214, "MOVE.W", "#0x1f|D0w"),
            fact(0x218, "MOVE.B", "(A0)+|(A1)+"),
            fact(0x21A, "DBF", "D0w|0x00000218", flows=(0x218,)),
        )
        self.assertEqual((), detect_z80_copies(image, {item.physical_offset: item for item in sequence}))

    def test_recovers_driver_passed_to_shared_z80_copy_subroutine(self) -> None:
        image = parse_megadrive(cartridge())
        sequence = (
            fact(0x200, "MOVEM.L", "{ A0 D0 D1}|-(SP)"),
            fact(0x204, "LEA", "(0xa00000).l|A1"),
            fact(0x206, "ADDA.W", "D1w|A1"),
            fact(0x208, "MOVE.B", "(A0)+|D1b"),
            fact(0x20A, "MOVE.B", "D1b|(A1)"),
            fact(0x20C, "ADDQ.W", "0x1|A1"),
            fact(0x20E, "DBF", "D0w|0x00000208", flows=(0x208,)),
            fact(0x240, "MOVE.W", "#0x3f|D0w"),
            fact(0x244, "MOVEQ", "0x0|D1"),
            fact(0x246, "LEA", "(0x38,PC)|A0",
                 references=(InstructionReference(0x280, "DATA", 0),)),
            fact(0x24A, "BSR.W", "0x00000200", flows=(0x200,)),
        )
        copy, = detect_z80_copies(image, {item.physical_offset: item for item in sequence})

        self.assertEqual((0x280, 0x2BF), (copy.source_start, copy.source_end))
        self.assertEqual((0, 63), (copy.target_start, copy.target_end))
        self.assertEqual("megadrive.m68k-z80.subroutine-copy", copy.schema_id)

    def test_subroutine_copy_accepts_any_setup_order_and_nonzero_destination(self) -> None:
        image = parse_megadrive(cartridge())
        sequence = (
            *COPY_ROUTINE,
            fact(0x240, "LEA", "(0x38,PC)|A0",
                 references=(InstructionReference(0x280, "DATA", 0),)),
            fact(0x244, "MOVE.W", "#0x3f|D0w"),
            fact(0x248, "MOVE.W", "#0x1000|D1w"),
            fact(0x24C, "BSR.W", "0x00000200", flows=(0x200,)),
        )
        copy, = detect_z80_copies(image, {item.physical_offset: item for item in sequence})

        self.assertEqual((0x280, 0x2BF), (copy.source_start, copy.source_end))
        self.assertEqual((0x1000, 0x103F), (copy.target_start, copy.target_end))
        self.assertEqual("megadrive.cross.m68k-z80.000280.1000", copy.edge_id)

    def test_subroutine_copy_rejects_clobbered_parameter_and_ram_overflow(self) -> None:
        image = parse_megadrive(cartridge())
        clobbered = (
            *COPY_ROUTINE,
            fact(0x240, "MOVE.W", "#0x3f|D0w"),
            fact(0x244, "MOVEQ", "0x0|D1"),
            fact(0x246, "LEA", "(0x38,PC)|A0",
                 references=(InstructionReference(0x280, "DATA", 0),)),
            fact(0x24A, "MOVE.W", "D2w|D0w"),
            fact(0x24C, "BSR.W", "0x00000200", flows=(0x200,)),
        )
        overflow = (
            *COPY_ROUTINE,
            fact(0x240, "MOVE.W", "#0x3f|D0w"),
            fact(0x244, "MOVE.W", "#0x1fe0|D1w"),
            fact(0x248, "LEA", "(0x38,PC)|A0",
                 references=(InstructionReference(0x280, "DATA", 0),)),
            fact(0x24C, "BSR.W", "0x00000200", flows=(0x200,)),
        )
        for sequence in (clobbered, overflow):
            self.assertEqual((), detect_z80_copies(
                image, {item.physical_offset: item for item in sequence}))

    def test_dbf_counter_skips_intervening_hardware_register_write(self) -> None:
        image = parse_megadrive(cartridge())
        sequence = (
            fact(0x206, "LEA", "(0x40,PC)|A0",
                 references=(InstructionReference(0x258, "DATA", 0),)),
            fact(0x20A, "LEA", "(0xa00000).l|A1"),
            fact(0x210, "MOVE.W", "#0xa|D0w"),
            fact(0x214, "MOVE.W", "#0x100|(0xa11100).l"),
            fact(0x21C, "MOVE.B", "(A0)+|(A1)+"),
            fact(0x21E, "DBF", "D0w|0x0000021c", flows=(0x21C,)),
        )
        copy, = detect_z80_copies(image, {item.physical_offset: item for item in sequence})

        self.assertEqual(11, copy.size)
        self.assertEqual((0x206, 0x20A, 0x210, 0x21C, 0x21E), copy.evidence_addresses)

    def test_im1_handler_is_seeded_only_with_im1_and_ei(self) -> None:
        def z80(address: int, raw: bytes) -> InstructionFact:
            return replace(fact(address, "?", ""), raw=raw, length=len(raw))

        both = {0: z80(0, b"\xf3"), 1: z80(1, b"\xed\x56"), 3: z80(3, b"\xfb")}
        self.assertEqual(0x38, z80_im1_handler_seed(both, 0, 0x2000))
        self.assertIsNone(z80_im1_handler_seed(both, 0x1000, 0x100))
        self.assertIsNone(z80_im1_handler_seed(
            {1: z80(1, b"\xed\x56")}, 0, 0x2000))
        self.assertIsNone(z80_im1_handler_seed(
            {1: z80(1, b"\xed\x5e"), 3: z80(3, b"\xfb")}, 0, 0x2000))

    def test_recovers_a_proven_postincrement_dbf_copy(self) -> None:
        image = parse_megadrive(cartridge())
        sequence = (
            fact(
                0x206,
                "LEA",
                "(0x40,PC)|A0",
                references=(InstructionReference(0x258, "DATA", 0),),
            ),
            fact(0x20A, "LEA", "(0xa00000).l|A1"),
            fact(0x210, "MOVE.W", "#0xa|D0w"),
            fact(0x214, "MOVE.B", "(A0)+|(A1)+"),
            fact(0x216, "DBF", "D0w|0x00000214", flows=(0x214,)),
        )
        copy, = detect_z80_copies(
            image, {item.physical_offset: item for item in sequence}
        )

        self.assertEqual((0x258, 0x262), (copy.source_start, copy.source_end))
        self.assertEqual((0, 10), (copy.target_start, copy.target_end))
        self.assertEqual(11, copy.size)
        self.assertEqual("proven-static-copy", copy.confidence)
        self.assertEqual(
            (0x206, 0x20A, 0x210, 0x214, 0x216), copy.evidence_addresses
        )

    def test_rejects_copy_without_loop_or_outside_z80_ram(self) -> None:
        image = parse_megadrive(cartridge())
        sequence = (
            fact(
                0x206,
                "LEA",
                "(0x40,PC)|A0",
                references=(InstructionReference(0x258, "DATA", 0),),
            ),
            fact(0x20A, "LEA", "(0xff0000).l|A1"),
            fact(0x210, "MOVE.W", "#0xa|D0w"),
            fact(0x214, "MOVE.B", "(A0)+|(A1)+"),
        )

        self.assertEqual(
            (),
            detect_z80_copies(
                image, {item.physical_offset: item for item in sequence}
            ),
        )


if __name__ == "__main__":
    unittest.main()
