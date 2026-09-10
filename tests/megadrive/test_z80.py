from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.facts import InstructionFact, InstructionReference
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_z80 import detect_z80_copies
from test_megadrive import cartridge


def fact(
    address: int,
    mnemonic: str,
    operands: str,
    *,
    flows: tuple[int, ...] = (),
    references: tuple[InstructionReference, ...] = (),
) -> InstructionFact:
    return InstructionFact(
        physical_offset=address,
        bank=0,
        cpu_address=address,
        length=2,
        raw=b"\0\0",
        mnemonic=mnemonic,
        operands=operands,
        flows=flows,
        flow_type="FALL_THROUGH",
        backend_space="ram",
        backend_block="ROM",
        backend_symbol="",
        backend_function="",
        references=references,
    )


class MegaDriveZ80Tests(unittest.TestCase):
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
