from dataclasses import replace
import unittest
from m68k.repair import test_variable_traps as fixture
from m68k.builders import instruction
from retrolarium_disassembler.m68k.repair.variable_traps import discover_variable_inline_trap_calls
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge


class TrapCallbackTests(unittest.TestCase):
    def setUp(self):
        fixture.VariableTrapTests.setUp(self)

    def callback_setup(self):
        self.items.update(
            {
                0x400: instruction(0x400, "201e", "MOVE.L", "(A6)+|D0"),
                0x402: instruction(0x402, "58af003e", "ADDQ.L", "0x4|(0x3e,SP)"),
                0x406: instruction(0x406, "7e07", "MOVEQ", "0x7|D7"),
                0x408: instruction(0x408, "41f8defa", "LEA", "(-0x2106).w|A0"),
                0x40C: instruction(0x40C, "4241", "CLR.W", "D1w"),
                0x40E: instruction(0x40E, "4a98", "TST.L", "(A0)+"),
                0x410: instruction(0x410, "670a", "BEQ.B", "0x41c", "CONDITIONAL_JUMP", (0x41C,)),
                0x412: instruction(0x412, "5241", "ADDQ.W", "0x1|D1w"),
                0x414: instruction(0x414, "51cffff8", "DBF", "D7w|0x40e", "CONDITIONAL_JUMP", (0x40E,)),
                0x418: instruction(0x418, "60000066", "BRA.W", "0x480", "UNCONDITIONAL_JUMP", (0x480,)),
                0x41C: instruction(0x41C, "2100", "MOVE.L", "D0|-(A0)"),
                0x41E: instruction(0x41E, "03f8def8", "BSET.B", "D1|(0xffffdef8).w"),
                0x422: instruction(0x422, "6000005c", "BRA.W", "0x480", "UNCONDITIONAL_JUMP", (0x480,)),
                0x480: instruction(0x480, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6"),
                0x484: instruction(0x484, "4e73", "RTE", flow="TERMINATOR"),
                0x600: instruction(0x600, "41f8defa", "LEA", "(-0x2106).w|A0"),
                0x604: instruction(0x604, "7e07", "MOVEQ", "0x7|D7"),
                0x606: instruction(0x606, "4246", "CLR.W", "D6w"),
                0x608: instruction(0x608, "2018", "MOVE.L", "(A0)+|D0"),
                0x60A: instruction(0x60A, "0d38def8", "BTST.B", "D6|(0xffffdef8).w"),
                0x60E: instruction(0x60E, "670c", "BEQ.B", "0x61c", "CONDITIONAL_JUMP", (0x61C,)),
                0x610: instruction(0x610, "48e7fffe", "MOVEM.L", "D0-A6|-(SP)"),
                0x614: instruction(0x614, "2040", "MOVEA.L", "D0|A0"),
                0x616: instruction(0x616, "4e90", "JSR", "(A0)", "COMPUTED_CALL"),
                0x618: instruction(0x618, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6"),
                0x61C: instruction(0x61C, "5246", "ADDQ.W", "0x1|D6w"),
                0x61E: instruction(0x61E, "51cfffE8", "DBF", "D7w|0x608", "CONDITIONAL_JUMP", (0x608,)),
            }
        )
        del self.items[0x404], self.items[0x40A]

    def callback_discover(self, pointer=0x700):
        data = bytearray(cartridge(size=0x800))
        data[41 * 4 : 42 * 4] = (0x200).to_bytes(4, "big")
        for fact in self.items.values():
            data[fact.cpu_address : fact.cpu_address + fact.length] = fact.raw
        data[0x218:0x21C] = bytes.fromhex("00e801e8")
        data[0x502:0x504] = bytes.fromhex("0000")
        data[0x512:0x518] = bytes.fromhex("0001") + pointer.to_bytes(4, "big")
        data[0x700:0x702] = bytes.fromhex("4e75")
        return discover_variable_inline_trap_calls(parse_megadrive(bytes(data)), self.items)[1]

    def test_parameter_is_code_only_when_same_array_is_executed(self):
        self.callback_setup()
        self.assertEqual(0x700, self.callback_discover().target)
        self.items[0x600] = replace(self.items[0x600], operands="(-0x2102).w|A0")
        self.assertIsNone(self.callback_discover().target)

    def test_count_flag_and_cursor_preservation_must_match(self):
        for address, operand in [
            (0x604, "0x6|D7"),
            (0x60A, "D6|(0xffffdef9).w"),
            (0x618, "(SP)+|D0-A5"),
            (0x414, "D6w|0x40e"),
        ]:
            self.setUp()
            self.callback_setup()
            self.items[address] = replace(self.items[address], operands=operand)
            self.assertIsNone(self.callback_discover().target)

    def test_parameter_in_unmapped_rom_or_instruction_interior_rejects(self):
        self.callback_setup()
        self.assertIsNone(self.callback_discover(0xFF1234).target)
        self.assertIsNone(self.callback_discover(0x602).target)
