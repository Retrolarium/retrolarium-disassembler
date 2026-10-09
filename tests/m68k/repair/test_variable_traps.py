from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.repair.variable_traps import discover_variable_inline_trap_calls
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from m68k.builders import instruction


class VariableTrapTests(unittest.TestCase):
    def setUp(self):
        self.items = {
            0x200: instruction(0x200, "48e7fffe", "MOVEM.L", "D0-A6|-(SP)"),
            0x204: instruction(0x204, "2c6f003e", "MOVEA.L", "(0x3e,SP)|A6"),
            0x208: instruction(0x208, "301e", "MOVE.W", "(A6)+|D0w"),
            0x20A: instruction(0x20A, "54af003e", "ADDQ.L", "0x2|(0x3e,SP)"),
            0x20E: instruction(0x20E, "d040", "ADD.W", "D0w|D0w"),
            0x210: instruction(0x210, "303b0006", "MOVE.W", "(0x218,PC,D0w*0x1)|D0w"),
            0x214: instruction(0x214, "4efb0002", "JMP", "(0x218,PC,D0w*0x1)", "COMPUTED_JUMP"),
            0x300: instruction(0x300, "7000", "MOVEQ", "0x0|D0"),
            0x302: instruction(0x302, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6"),
            0x306: instruction(0x306, "4e73", "RTE", flow="TERMINATOR"),
            0x400: instruction(0x400, "58af003e", "ADDQ.L", "0x4|(0x3e,SP)"),
            0x404: instruction(0x404, "201e", "MOVE.L", "(A6)+|D0"),
            0x406: instruction(0x406, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6"),
            0x40A: instruction(0x40A, "4e73", "RTE", flow="TERMINATOR"),
            0x500: instruction(0x500, "4e49", "TRAP", "0x9", "CALL_TERMINATOR"),
            0x510: instruction(0x510, "4e49", "TRAP", "0x9", "CALL_TERMINATOR"),
        }
        self.selectors = (0, 1)

    def discover(self):
        data = bytearray(cartridge(size=0x800))
        data[41*4:42*4] = (0x200).to_bytes(4, "big")
        for item in self.items.values():
            data[item.cpu_address:item.cpu_address+item.length] = item.raw
        for index, target in enumerate((0x300, 0x400)):
            data[0x218+index*2:0x21A+index*2] = (target-0x218).to_bytes(2, "big")
        for address, value in zip((0x502, 0x512), self.selectors):
            data[address:address+2] = value.to_bytes(2, "big")
        return discover_variable_inline_trap_calls(parse_megadrive(bytes(data)), self.items)

    def test_selector_proves_word_or_word_plus_long(self):
        calls = self.discover()
        self.assertEqual([(0x502, 0x504, 2), (0x512, 0x518, 6)],
                         [(c.data_address, c.continuation, c.data_size) for c in calls])
        self.assertTrue(all(c.target is None for c in calls))

    def test_invalid_selector_is_not_wrapped(self):
        self.selectors = (2, 0xffff)
        self.assertFalse(self.discover())

    def test_cursor_and_saved_pc_must_agree(self):
        self.items[0x400] = replace(self.items[0x400], operands="0x2|(0x3e,SP)")
        self.assertEqual([0x500], [c.call_address for c in self.discover()])

    def test_incomplete_restore_and_unknown_call_reject_long_case(self):
        original = self.items[0x406]
        self.items[0x406] = replace(original, operands="(SP)+|D0-A5")
        self.assertEqual([0x500], [c.call_address for c in self.discover()])
        self.items[0x406] = replace(original, mnemonic="JSR", flow_type="UNCONDITIONAL_CALL")
        self.assertEqual([0x500], [c.call_address for c in self.discover()])

    def test_branch_with_incompatible_consumption_rejects_selector(self):
        self.items[0x400] = instruction(0x400, "6602", "BNE.B", "0x404", "CONDITIONAL_JUMP", (0x404,))
        self.items[0x402] = instruction(0x402, "7000", "MOVEQ", "0x0|D0")
        self.assertEqual([0x500], [c.call_address for c in self.discover()])

    def test_unproven_dispatch_register_or_stack_slot_rejects_handler(self):
        original = self.items[0x204]
        self.items[0x204] = replace(original, operands="(0x3c,SP)|A6")
        self.assertFalse(self.discover())
        self.items[0x204] = original
        self.items[0x214] = replace(self.items[0x214], raw=bytes.fromhex("4efb1002"))
        self.assertFalse(self.discover())

    def test_width_qualified_stack_alias_invalidates_only_affected_selector(self):
        for address in tuple(self.items):
            if 0x300 <= address < 0x400:
                self.items.pop(address)
        self.items.update({f.cpu_address: f for f in (
            instruction(0x300, '304f', 'MOVEA.W', 'A7w|A0'),
            instruction(0x302, '58a8003e', 'ADDQ.L', '0x4|(0x3e,A0)'),
            instruction(0x306, '4cdf7fff', 'MOVEM.L', '(SP)+|D0-A6'),
            instruction(0x30a, '4e73', 'RTE', flow='TERMINATOR'))})
        self.assertEqual([0x510], [c.call_address for c in self.discover()])

    def test_exception_pc_cannot_replace_the_active_stack_pointer(self):
        self.items[0x204] = instruction(0x204, '2e6f003e', 'MOVEA.L', '(0x3e,SP)|SP')
        self.items[0x208] = instruction(0x208, '301f', 'MOVE.W', '(SP)+|D0w')
        self.assertFalse(self.discover())


if __name__ == "__main__":
    unittest.main()
