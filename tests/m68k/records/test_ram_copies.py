from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_kit.m68k_ram_copies import discover_descriptor_ram_code_seeds
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_z80 import fact


def descriptor_fixture():
    data = bytearray(cartridge(size=0x1000))
    data[28 * 4:29 * 4] = (0xFFEE00).to_bytes(4, "big")
    data[0x400:0x404] = (0x300).to_bytes(4, "big")
    data[0x480:0x48A] = bytes.fromhex("00 00 00 00 05 00 EE 00 FF FF")
    data[0x500:0x512] = bytes.fromhex("00 10") + bytes.fromhex("4E 71") * 7 + bytes.fromhex("4E 73")
    items = []

    def add(address, mnemonic, operands, length=2, flow="FALL_THROUGH", flows=(), raw=None):
        items.append(replace(fact(address, mnemonic, operands, flows=flows), length=length,
                             flow_type=flow, raw=bytes(length) if raw is None else raw))

    add(0x200, "LEA", "(0x480).l|A3", 6)
    add(0x206, "NOP", "")
    add(0x208, "JSR", "0x00000280.l", 6, "UNCONDITIONAL_CALL", (0x280,))
    add(0x280, "MOVE.W", "(A3)+|D4w")
    add(0x282, "BMI.W", "0x00000292", 4, "CONDITIONAL_JUMP", (0x292,))
    add(0x286, "LSL.W", "#0x2|D4w")
    add(0x288, "MOVEA.L", "(0x400,PC,D4w*0x1)|A6", 4)
    add(0x28C, "JSR", "(A6)", flow="COMPUTED_CALL")
    add(0x28E, "BRA.W", "0x00000280", 4, "UNCONDITIONAL_JUMP", (0x280,))
    add(0x292, "RTS", "", flow="TERMINATOR")
    for address, mnemonic, operands in (
        (0x300, "MOVEA.L", "(A3)+|A4"), (0x302, "MOVEQ", "-0x1|D5"),
        (0x304, "MOVE.W", "(A3)+|D5w"), (0x306, "MOVEA.L", "D5|A2"),
        (0x308, "MOVE.W", "(A4)+|D1w"), (0x30A, "LSR.W", "#0x2|D1w"),
        (0x30C, "SUBQ.W", "0x1|D1w"), (0x30E, "MOVE.L", "(A4)+|(A2)+"),
    ):
        add(address, mnemonic, operands)
    add(0x310, "DBF", "D1w|0x0000030e", 4, "CONDITIONAL_JUMP", (0x30E,))
    add(0x314, "RTS", "", flow="TERMINATOR")
    return data, {item.cpu_address: item for item in items}


class DescriptorRamCopyTests(unittest.TestCase):
    def test_follows_loader_to_ram_interrupt_code_with_renamed_registers(self):
        data, facts = descriptor_fixture()
        seeds = discover_descriptor_ram_code_seeds(parse_megadrive(bytes(data)), facts)
        self.assertEqual((0x502,), tuple(seed.address for seed in seeds))
        self.assertEqual("proven", seeds[0].confidence)
        self.assertIn("16 bytes", seeds[0].evidence)
        self.assertEqual(0x208, seeds[0].source_address)

    def test_accepts_pc_relative_descriptor_pointer(self):
        data, facts = descriptor_fixture()
        facts.pop(0x206)
        facts[0x200] = replace(facts[0x200], operands="(0x27e,PC)|A3", length=4,
                              raw=bytes.fromhex("47 FA 02 7E"))
        facts[0x204] = replace(facts[0x208], cpu_address=0x204, physical_offset=0x204)
        self.assertEqual((0x502,), tuple(seed.address for seed in
                         discover_descriptor_ram_code_seeds(parse_megadrive(bytes(data)), facts)))

    def test_copy_to_ordinary_data_buffer_does_not_become_code(self):
        data, facts = descriptor_fixture()
        data[0x486:0x488] = bytes.fromhex("EC 00")
        self.assertEqual((), discover_descriptor_ram_code_seeds(parse_megadrive(bytes(data)), facts))

    def test_rejects_wrong_loader_loop_selector_or_overrunning_count(self):
        for address, operands in ((0x30A, "#0x1|D1w"), (0x30E, "(A4)+|(A2)"),
                                  (0x310, "D5w|0x0000030e"), (0x286, "#0x1|D4w")):
            with self.subTest(operands=operands):
                data, facts = descriptor_fixture()
                facts[address] = replace(facts[address], operands=operands)
                self.assertEqual((), discover_descriptor_ram_code_seeds(parse_megadrive(bytes(data)), facts))
        for length in (0, 3, 0xFFFF, 0xC00):
            data, facts = descriptor_fixture()
            data[0x500:0x502] = length.to_bytes(2, "big")
            self.assertEqual((), discover_descriptor_ram_code_seeds(parse_megadrive(bytes(data)), facts))


if __name__ == "__main__":
    unittest.main()
