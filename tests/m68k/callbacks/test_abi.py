from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from retrolarium_kit.m68k_callback_abi import discover_callback_abi_seeds
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.facts import InstructionReference
from test_megadrive import cartridge
from test_m68k_unused import instruction


class CallbackAbiTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            0x200: instruction(0x200, "22680004", "MOVEA.L", "(0x4,A0)|A1"),
            0x204: instruction(0x204, "4e91", "JSR", "(A1)", "COMPUTED_CALL"),
            0x220: instruction(0x220, "43f900000400", "LEA", "(0x400).l|A1"),
            0x226: instruction(0x226, "610000d8", "BSR.W", "0x300", "UNCONDITIONAL_CALL", (0x300,)),
            0x300: instruction(0x300, "6100001e", "BSR.W", "0x320", "UNCONDITIONAL_CALL", (0x320,)),
            0x320: instruction(0x320, "4a40", "TST.W", "D0w"),
            0x322: instruction(0x322, "6704", "BEQ.B", "0x328", "CONDITIONAL_JUMP", (0x328,)),
            0x324: instruction(0x324, "4e75", "RTS", flow="TERMINATOR"),
            0x328: instruction(0x328, "21490004", "MOVE.L", "A1|(0x4,A0)"),
            0x32C: instruction(0x32C, "4e75", "RTS", flow="TERMINATOR"),
        }

    def discover(self):
        data = bytearray(cartridge(size=0x800))
        for fact in self.facts.values():
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        data[0x400:0x404] = bytes.fromhex("70014e75")
        return {s.address: s for s in discover_callback_abi_seeds(parse_megadrive(bytes(data)), self.facts)}

    def test_parameter_reaches_executed_field_through_nested_allocator(self):
        self.assertEqual("callback_parameter", self.discover()[0x400].kind)

    def test_unknown_call_clobbered_parameter_or_different_field_reject(self):
        original = self.facts[0x320]
        self.facts[0x320] = instruction(0x320, "2240", "MOVEA.L", "D0|A1")
        self.assertNotIn(0x400, self.discover())
        self.facts[0x320] = original
        self.facts[0x328] = replace(self.facts[0x328], operands="A1|(0x8,A0)")
        self.assertNotIn(0x400, self.discover())
        self.facts[0x300] = replace(self.facts[0x300], flows=(0x350,))
        self.assertNotIn(0x400, self.discover())

    def test_bookmark_saves_call_continuation_for_later_execution(self):
        self.facts[0x300] = instruction(0x300, "215f0004", "MOVE.L", "(SP)+|(0x4,A0)")
        self.facts[0x304] = instruction(0x304, "4e75", "RTS", flow="TERMINATOR")
        self.facts[0x22A] = instruction(0x22A, "7001", "MOVEQ", "0x1|D0")
        self.assertEqual("callback_bookmark", self.discover()[0x22A].kind)
        self.facts[0x300] = instruction(0x300, "3f00", "MOVE.W", "D0w|-(SP)")
        self.facts[0x302] = instruction(0x302, "215f0004", "MOVE.L", "(SP)+|(0x4,A0)")
        self.facts[0x306] = instruction(0x306, "4e75", "RTS", flow="TERMINATOR")
        self.assertNotIn(0x22A, self.discover())

    def test_asset_pointer_and_movem_clobber_are_not_callback_arguments(self):
        self.facts[0x324] = replace(self.facts[0x324], references=(InstructionReference(0x400, "READ", 0),))
        self.assertNotIn(0x400, self.discover())
        self.facts[0x324] = replace(self.facts[0x324], references=())
        self.facts[0x320] = instruction(0x320, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6")
        self.assertNotIn(0x400, self.discover())

    def test_stack_alias_cannot_change_saved_callback_return_pc(self):
        self.facts[0x300] = instruction(0x300, "324f", "MOVEA.W", "A7w|A1")
        self.facts[0x302] = instruction(0x302, "5891", "ADDQ.L", "0x4|(A1)")
        self.facts[0x304] = instruction(0x304, "215f0004", "MOVE.L", "(SP)+|(0x4,A0)")
        self.facts[0x308] = instruction(0x308, "4e75", "RTS", flow="TERMINATOR")
        self.facts[0x22A] = instruction(0x22A, "7001", "MOVEQ", "0x1|D0")
        self.assertNotIn(0x22A, self.discover())

    def test_multiple_field_assignments_accept_internal_labels_but_need_executor(self):
        self.facts[0x340] = instruction(0x340, "217c000004000004", "MOVE.L", "#0x400|(0x4,A0)")
        self.facts[0x348] = instruction(0x348, "217c000004200004", "MOVE.L", "#0x420|(0x4,A0)")
        self.facts[0x340] = replace(self.facts[0x340], references=(InstructionReference(0x400, "DATA", 0),))
        self.facts[0x400] = instruction(0x400, "7001", "MOVEQ", "0x1|D0")
        self.facts[0x420] = instruction(0x420, "7202", "MOVEQ", "0x2|D1")
        self.assertEqual("callback_field_assignment", self.discover()[0x420].kind)
        image = parse_megadrive(cartridge(size=0x800))
        self.assertFalse(discover_callback_abi_seeds(image, self.facts, execution_facts={}))


if __name__ == "__main__":
    unittest.main()
