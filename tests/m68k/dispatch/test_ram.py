from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.dispatch.ram import discover_ram_stub_dispatch_seeds, discover_inline_trap_calls
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from megadrive.builders import fact


class RamStubDispatchTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(cartridge(size=0x800))
        for i, target in enumerate((0x400, 0x420, 0x440)):
            self.data[0x300 + i * 4:0x304 + i * 4] = target.to_bytes(4, "big")
            self.data[target:target + 2] = bytes.fromhex("7001")
        self.items = [
            replace(fact(0x200, "LEA", "(0xfe,PC)|A6"), length=4, raw=bytes.fromhex("4dfa00fe")),
            replace(fact(0x204, "MOVEA.L", "(0x0,A6,D7w*0x1)|A6"), length=4),
            replace(fact(0x208, "MOVE.W", "#0x4ef9|(0x00ff3910).l"), length=8),
            replace(fact(0x210, "MOVE.L", "A6|(0x00ff3912).l"), length=6),
            replace(fact(0x216, "MOVEA.L", "(0x00ff390c).l|A6"), length=6),
            replace(fact(0x21C, "JMP", "0x00ff3910.l"), flows=(0xFF3910,), flow_type="UNCONDITIONAL_JUMP"),
            fact(0x400, "MOVEQ", "0x1|D0"),
        ]

    def seeds(self):
        return discover_ram_stub_dispatch_seeds(parse_megadrive(bytes(self.data)),
                                                {f.cpu_address: f for f in self.items})

    def test_restored_register_after_store_does_not_lose_table(self):
        self.assertEqual([0x400, 0x420, 0x440], [s.address for s in self.seeds()])

    def test_requires_matching_opcode_operand_and_invoked_ram_stub(self):
        for at, changes in ((0x208, {"operands": "#0x4e75|(0x00ff3910).l"}),
                            (0x210, {"operands": "A6|(0x00ff3914).l"}),
                            (0x21C, {"flows": (0xFF3900,)}),
                            (0x210, {"operands": "A5|(0x00ff3912).l"})):
            old = self.items[:]
            self.items = [replace(f, **changes) if f.cpu_address == at else f for f in old]
            self.assertFalse(self.seeds())
            self.items = old

    def test_clobbered_pointer_and_unmapped_target_rejected(self):
        self.items[2] = replace(self.items[2], mnemonic="MOVEQ", operands="0x0|A6")
        self.assertFalse(self.seeds())
        self.setUp()
        self.data[0x304:0x308] = (0xFF4000).to_bytes(4, "big")
        self.assertFalse(self.seeds())

    def inline(self):
        self.data[33 * 4:34 * 4] = (0x200).to_bytes(4, "big")
        self.items = [replace(f, cpu_address=f.cpu_address + 12,
                              physical_offset=f.physical_offset + 12,
                              raw=bytes.fromhex("4dfa00f2") if f.cpu_address == 0x200 else f.raw)
                      if f.cpu_address < 0x400 else f for f in self.items]
        self.items[0] = replace(self.items[0], operands="(0xf2,PC)|A6")
        self.items += [
            replace(fact(0x200, "ADDA.L", "#0x2|SP"), length=6),
            fact(0x206, "MOVEA.L", "(SP)|A6"),
            fact(0x208, "MOVE.W", "(A6)+|D7w"),
            fact(0x20A, "MOVE.L", "A6|(SP)"),
            replace(fact(0x500, "TRAP", "0x1"), raw=bytes.fromhex("4e41")),
        ]
        self.data[0x502:0x504] = (4).to_bytes(2, "big")
        return discover_inline_trap_calls(parse_megadrive(bytes(self.data)),
                                         {f.cpu_address: f for f in self.items})

    def test_inline_selector_advances_pc_only_for_proven_trap_abi(self):
        result = self.inline()
        self.assertEqual(1, len(result))
        self.assertEqual((0x502, 0x504, 0x420),
                         (result[0].data_address, result[0].continuation, result[0].target))
        self.items = [replace(f, operands="A5|(SP)") if f.cpu_address == 0x20A else f for f in self.items]
        self.assertFalse(discover_inline_trap_calls(parse_megadrive(bytes(self.data)),
                                                  {f.cpu_address: f for f in self.items}))


if __name__ == "__main__":
    unittest.main()
