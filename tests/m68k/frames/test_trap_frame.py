from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_kit.m68k_trap_frame import discover_frame_inline_trap_calls
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_m68k_unused import instruction


class TrapFrameTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            0x200: instruction(0x200, "48e7fffe", "MOVEM.L", "D0-A6|-(SP)"),
            0x204: instruction(0x204, "2c6f003e", "MOVEA.L", "(0x3e,SP)|A6"),
            0x208: instruction(0x208, "54af003e", "ADDQ.L", "0x2|(0x3e,SP)"),
            0x20C: instruction(0x20C, "301e", "MOVE.W", "(A6)+|D0w"),
            0x20E: instruction(0x20E, "4a40", "TST.W", "D0w"),
            0x210: instruction(0x210, "6604", "BNE.B", "0x216", "CONDITIONAL_JUMP", (0x216,)),
            0x212: instruction(0x212, "7000", "MOVEQ", "0x0|D0"),
            0x214: instruction(0x214, "6000fffe", "BRA.W", "0x216", "UNCONDITIONAL_JUMP", (0x216,)),
            0x216: instruction(0x216, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6"),
            0x21A: instruction(0x21A, "4e73", "RTE", flow="TERMINATOR"),
            0x300: instruction(0x300, "4e45", "TRAP", "0x5", "CALL_TERMINATOR"),
        }

    def discover(self):
        data = bytearray(cartridge(size=0x800))
        data[(32 + 5)*4:(33 + 5)*4] = (0x200).to_bytes(4, "big")
        for fact in self.facts.values():
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        return discover_frame_inline_trap_calls(parse_megadrive(bytes(data)), self.facts)

    def test_fixed_frame_argument_has_continuation_without_dispatch_target(self):
        calls = self.discover()
        self.assertEqual(1, len(calls))
        self.assertEqual((0x302, 0x304, None), (calls[0].data_address, calls[0].continuation, calls[0].target))

    def test_wrong_frame_offset_or_clobbered_pc_register_reject(self):
        self.facts[0x204] = replace(self.facts[0x204], operands="(0x3c,SP)|A6")
        self.assertFalse(self.discover())
        self.facts[0x204] = replace(self.facts[0x204], operands="(0x3e,SP)|A6")
        self.facts[0x20C] = replace(self.facts[0x20C], operands="(A5)+|D0w")
        self.assertFalse(self.discover())

    def test_variable_arguments_or_incomplete_restore_reject(self):
        original = self.facts[0x212]
        self.facts[0x212] = instruction(0x212, "58af003e", "ADDQ.L", "0x4|(0x3e,SP)")
        self.assertFalse(self.discover())
        self.facts[0x212] = original
        self.facts[0x216] = replace(self.facts[0x216], operands="(SP)+|D0-A5")
        self.assertFalse(self.discover())

    def test_closed_loop_is_not_return_proof(self):
        self.facts[0x210] = replace(self.facts[0x210], flows=(0x210,), flow_type="UNCONDITIONAL_JUMP")
        self.assertFalse(self.discover())

    def test_non_postincrement_read_and_word_saved_frame(self):
        self.facts[0x20C] = replace(self.facts[0x20C], operands="(A6)|D0w")
        self.assertEqual(1, len(self.discover()))
        self.facts[0x200] = instruction(0x200, "48a78000", "MOVEM.W", "D0|-(SP)")
        self.facts[0x204] = replace(self.facts[0x204], operands="(0x4,SP)|A6")
        self.facts[0x208] = replace(self.facts[0x208], operands="0x2|(0x4,SP)")
        self.facts[0x216] = replace(self.facts[0x216], mnemonic="MOVEM.W", operands="(SP)+|D0")
        self.assertEqual(1, len(self.discover()))

    def test_flag_result_abi_discards_saved_sr_then_returns_by_rts(self):
        self.facts[0x21A] = instruction(0x21A, "548f", "ADDQ.L", "0x2|SP")
        self.facts[0x21C] = instruction(0x21C, "4e75", "RTS", flow="TERMINATOR")
        self.assertEqual(1, len(self.discover()))
        self.facts[0x21A] = replace(self.facts[0x21A], operands="0x4|SP")
        self.assertFalse(self.discover())

    def test_plain_rts_or_rte_after_discard_is_not_an_exception_return(self):
        self.facts[0x21A] = instruction(0x21A, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.discover())
        self.facts[0x21A] = instruction(0x21A, "548f", "ADDQ.L", "0x2|SP")
        self.facts[0x21C] = instruction(0x21C, "4e73", "RTE", flow="TERMINATOR")
        self.assertFalse(self.discover())

    def test_width_qualified_stack_alias_cannot_hide_an_extra_pc_adjustment(self):
        for address in tuple(self.facts):
            if 0x20e <= address < 0x300:
                self.facts.pop(address)
        self.facts.update({f.cpu_address: f for f in (
            instruction(0x20e, '304f', 'MOVEA.W', 'A7w|A0'),
            instruction(0x210, '58a8003e', 'ADDQ.L', '0x4|(0x3e,A0)'),
            instruction(0x214, '4cdf7fff', 'MOVEM.L', '(SP)+|D0-A6'),
            instruction(0x218, '4e73', 'RTE', flow='TERMINATOR'))})
        self.assertFalse(self.discover())

    def test_exception_pc_cannot_replace_the_active_stack_pointer(self):
        self.facts[0x204] = instruction(0x204, '2e6f003e', 'MOVEA.L', '(0x3e,SP)|SP')
        self.facts[0x20c] = instruction(0x20c, '301f', 'MOVE.W', '(SP)+|D0w')
        self.assertFalse(self.discover())


if __name__ == "__main__":
    unittest.main()
