from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_disassembler.facts import InstructionReference
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.emit import _standard_boot_setup_lines
from retrolarium_disassembler.megadrive.structures import (
    discover_long_ff_padding,
    discover_standard_boot_setups,
)
from retrolarium_disassembler.megadrive.symbols import generate_symbols
from megadrive.builders import cartridge
from megadrive.builders import fact


def boot_fixture() -> tuple[bytes, dict]:
    data = bytearray(cartridge())
    setup = bytearray()
    setup.extend(bytes.fromhex("80 00 3F FF 01 00"))
    setup.extend(b"".join(
        value.to_bytes(4, "big")
        for value in (0xA00000, 0xA11100, 0xA11200, 0xC00000, 0xC00004)
    ))
    setup.extend(bytes(range(24)))
    setup.extend((0x40000080).to_bytes(4, "big"))
    setup.extend(bytes(range(38)))
    setup.extend(b"".join(
        value.to_bytes(4, "big")
        for value in (0x81048F02, 0xC0000000, 0x40000010)
    ))
    setup.extend(bytes.fromhex("9F BF DF FF"))
    data[0x294:0x300] = setup

    reference = InstructionReference(0x294, "DATA", 0)
    sequence = (
        replace(fact(0x216, "LEA", "(0x7c,PC)|A5"), references=(reference,)),
        fact(0x21A, "MOVEM.W", "(A5)+|{ D5 D6 D7}"),
        fact(0x21E, "MOVEM.L", "(A5)+|{ A0 A1 A2 A3 A4}"),
        fact(0x23E, "MOVE.B", "(A5)+|D5b"),
        fact(0x248, "MOVE.L", "(A5)+|(A4)"),
        fact(0x256, "MOVE.B", "(A5)+|(A0)+"),
        fact(0x268, "MOVE.L", "(A5)+|(A4)"),
        fact(0x26A, "MOVE.L", "(A5)+|(A4)"),
        fact(0x274, "MOVE.L", "(A5)+|(A4)"),
        fact(0x280, "MOVE.B", "(A5)+|(0x11,A3)"),
        replace(
            fact(0x292, "BRA.B", "0x300", flows=(0x300,)),
            flow_type="UNCONDITIONAL_JUMP",
        ),
    )
    return bytes(data), {item.physical_offset: item for item in sequence}


class MegaDriveStructureTests(unittest.TestCase):
    def test_discovers_uninterrupted_ff_padding(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x340] = b"\xFF" * 0xC0
        image = parse_megadrive(bytes(data))

        self.assertIn((0x280, 0x340), discover_long_ff_padding(image, {}))
        self.assertNotIn(
            (0x280, 0x340),
            discover_long_ff_padding(image, {0x300: fact(0x300, "NOP", "")}),
        )

    def test_discovers_and_renders_standard_boot_setup(self) -> None:
        data, facts = boot_fixture()
        image = parse_megadrive(data)

        setups = discover_standard_boot_setups(image, facts)

        self.assertEqual(1, len(setups))
        self.assertEqual((0x294, 0x300), (
            setups[0].physical_start, setups[0].physical_end
        ))
        lines = _standard_boot_setup_lines(setups[0], image)
        self.assertEqual("                dc.w    $8000", lines[0])
        self.assertIn("                dc.l    Io_A00000", lines)
        self.assertIn("                dc.l    $40000080", lines)
        self.assertEqual("                dc.b    $9F, $BF, $DF, $FF", lines[-1])

        symbols = generate_symbols(image, facts, ())
        setup_symbol = next(
            symbol for symbol in symbols if symbol.logical_address == 0x294
        )
        self.assertEqual("tbl_M68K_000294", setup_symbol.name)

    def test_rejects_boot_stream_with_wrong_hardware_layout(self) -> None:
        data, facts = boot_fixture()
        broken = bytearray(data)
        broken[0x29D] ^= 1

        self.assertEqual((), discover_standard_boot_setups(
            parse_megadrive(bytes(broken)), facts
        ))


if __name__ == "__main__":
    unittest.main()
