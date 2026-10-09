from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_disasm.m68k.dispatch.ram_record import discover_ram_record_dispatch_seeds
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_m68k_unused import instruction


class RamRecordDispatchTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            0x200: instruction(0x200, "6100001e", "BSR.W", "0x220", "UNCONDITIONAL_CALL", (0x220,)),
            0x204: instruction(0x204, "21c8ec94", "MOVE.L", "A0|(0xffffec94).w"),
            0x220: instruction(0x220, "661e", "BNE.B", "0x240", "CONDITIONAL_JUMP", (0x240,)),
            0x222: instruction(0x222, "7e00", "MOVEQ", "0x0|D7"),
            0x224: instruction(0x224, "3e38ec92", "MOVE.W", "(0xffffec92).w|D7w"),
            0x228: instruction(0x228, "e24f", "LSR.W", "#0x1|D7w"),
            0x22A: instruction(0x22A, "41fa00d4", "LEA", "(0xd4,PC)|A0"),
            0x22E: instruction(0x22E, "3e307000", "MOVE.W", "(0x0,A0,D7w*0x1)|D7w"),
            0x232: instruction(0x232, "d1c7", "ADDA.L", "D7|A0"),
            0x234: instruction(0x234, "4e75", "RTS", flow="TERMINATOR"),
            0x240: instruction(0x240, "41fa010e", "LEA", "(0x10e,PC)|A0"),
            0x244: instruction(0x244, "4e75", "RTS", flow="TERMINATOR"),
            0x260: instruction(0x260, "2078ec94", "MOVEA.L", "(0xffffec94).w|A0"),
            0x264: instruction(0x264, "3038ec92", "MOVE.W", "(0xffffec92).w|D0w"),
            0x268: instruction(0x268, "e748", "LSL.W", "#0x3|D0w"),
            0x26A: instruction(0x26A, "41f00000", "LEA", "(0x0,A0,D0w*0x1)|A0"),
            0x26E: instruction(0x26E, "20680004", "MOVEA.L", "(0x4,A0)|A0"),
            0x272: instruction(0x272, "4ed0", "JMP", "(A0)", "COMPUTED_JUMP"),
            0x400: instruction(0x400, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.targets = (0x400, 0x420, 0x440)

    def discover(self):
        data = bytearray(cartridge(size=0x800))
        for fact in self.facts.values():
            data[fact.cpu_address:fact.cpu_address+fact.length] = fact.raw
        data[0x300:0x304] = bytes.fromhex("00200050")
        for base in (0x320, 0x350):
            for i, target in enumerate(self.targets):
                data[base+i*8:base+i*8+8] = bytes.fromhex("07040715") + target.to_bytes(4, "big")
                data[target:target+2] = bytes.fromhex("4e75")
        return discover_ram_record_dispatch_seeds(parse_megadrive(bytes(data)), self.facts)

    def test_relative_and_direct_returned_groups_saved_in_ram(self):
        self.assertEqual(list(self.targets), [s.address for s in self.discover()])

    def test_every_return_must_establish_a_rom_base(self):
        self.facts[0x240] = replace(self.facts[0x240], mnemonic="MOVEA.L", operands="(A1)|A0")
        self.assertFalse(self.discover())

    def test_unsigned_long_add_requires_zero_upper_index(self):
        self.facts[0x222] = replace(self.facts[0x222], operands="-0x1|D7")
        self.assertFalse(self.discover())

    def test_register_exchange_invalidates_return_proof(self):
        self.facts[0x228] = replace(self.facts[0x228], mnemonic="EXG", operands="D7|A1")
        self.assertFalse(self.discover())

    def test_ram_slot_stride_and_executed_field_must_agree(self):
        for address, operand in [(0x260, "(0xffffec90).w|A0"), (0x268, "#0x1|D0w"),
                                 (0x26A, "(0x0,A0,D1w*0x1)|A0"), (0x272, "(A1)")]:
            self.setUp()
            self.facts[address] = replace(self.facts[address], operands=operand)
            self.assertFalse(self.discover())

    def test_records_require_multiple_targets_and_decoded_corroboration(self):
        self.targets = (0x400, 0x400, 0x400)
        self.assertFalse(self.discover())
        self.targets = (0x400, 0x420, 0x440)
        del self.facts[0x400]
        self.assertFalse(self.discover())

    def test_index_read_must_not_advance_the_record_base(self):
        self.facts[0x264] = replace(self.facts[0x264], operands="(A0)+|D0w")
        self.assertFalse(self.discover())

    def test_callee_postincrement_invalidates_relative_base(self):
        self.facts[0x22E] = replace(self.facts[0x22E], operands="(A0)+|D7w")
        self.assertFalse(self.discover())

    def test_stack_alias_invalidates_normal_return_of_record_base(self):
        self.facts[0x244] = instruction(0x244, "344f", "MOVEA.W", "A7w|A2")
        self.facts[0x246] = instruction(0x246, "5892", "ADDQ.L", "0x4|(A2)")
        self.facts[0x248] = instruction(0x248, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.discover())


if __name__ == "__main__":
    unittest.main()
