from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.frames.inline_calls import discover_inline_subroutine_calls
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from m68k.builders import instruction


class InlineCallTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            0x200: instruction(0x200, "610000fe", "BSR.W", "0x300", "CALL_TERMINATOR", (0x300,)),
            0x300: instruction(0x300, "48e78080", "MOVEM.L", "{ A0 D0}|-(SP)"),
            0x304: instruction(0x304, "206f0008", "MOVEA.L", "(0x8,SP)|A0"),
            0x308: instruction(0x308, "3018", "MOVE.W", "(A0)+|D0w"),
            0x30A: instruction(0x30A, "2f480008", "MOVE.L", "A0|(0x8,SP)"),
            0x30E: instruction(0x30E, "4eb900000400", "JSR", "0x400.l", "UNCONDITIONAL_CALL", (0x400,)),
            0x314: instruction(0x314, "4cdf0101", "MOVEM.L", "(SP)+|{ D0 A0}"),
            0x318: instruction(0x318, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.image = parse_megadrive(cartridge(size=0x800))

    def discover(self):
        return discover_inline_subroutine_calls(self.image, self.facts)

    def test_bsr_inline_word_resumes_after_argument_not_in_argument(self):
        calls = self.discover()
        self.assertEqual(
            [(0x200, 0x204, 0x206, 0x300, 2)],
            [(c.call_address, c.data_address, c.continuation, c.handler, c.data_size) for c in calls],
        )

    def test_jsr_uses_its_actual_length_and_no_vector_table(self):
        self.facts[0x200] = instruction(0x200, "4eb900000300", "JSR", "0x300.l", "UNCONDITIONAL_CALL", (0x300,))
        (call,) = self.discover()
        self.assertEqual((0x206, 0x208), (call.data_address, call.continuation))

    def test_jmp_does_not_push_a_return_pc(self):
        self.facts[0x200] = instruction(0x200, "4ef900000300", "JMP", "0x300.l", "UNCONDITIONAL_JUMP", (0x300,))
        self.assertFalse(self.discover())

    def test_wrong_frame_offset_read_or_write_reject(self):
        for address, operands in (
            (0x304, "(0x4,SP)|A0"),
            (0x308, "(A0)|D0w"),
            (0x308, "(A1)+|D0w"),
            (0x30A, "A0|(0x4,SP)"),
        ):
            with self.subTest(address=address, operands=operands):
                original = self.facts[address]
                self.facts[address] = replace(original, operands=operands)
                self.assertFalse(self.discover())
                self.facts[address] = original

    def test_unknown_branch_or_suppressed_nested_return_reject(self):
        for flow in ("CONDITIONAL_JUMP", "CALL_TERMINATOR", "COMPUTED_CALL"):
            with self.subTest(flow=flow):
                self.facts[0x30E] = replace(self.facts[0x30E], flow_type=flow)
                self.assertFalse(self.discover())

    def test_second_pc_edit_rejects_variable_argument_length(self):
        self.facts[0x30E] = instruction(0x30E, "54af0008", "ADDQ.L", "0x2|(0x8,SP)")
        self.assertFalse(self.discover())

    def test_indirect_pc_edit_through_width_qualified_stack_alias_rejects(self):
        self.facts[0x30E] = instruction(0x30E, "324f", "MOVEA.W", "A7w|A1")
        self.facts[0x310] = instruction(0x310, "58a90008", "ADDQ.L", "0x4|(0x8,A1)")
        self.assertFalse(self.discover())

    def test_incomplete_restore_or_missing_rts_reject(self):
        self.facts[0x314] = replace(self.facts[0x314], operands="(SP)+|D0")
        self.assertFalse(self.discover())
        self.facts[0x314] = instruction(0x314, "4cdf0101", "MOVEM.L", "(SP)+|{ D0 A0}")
        del self.facts[0x318]
        self.assertFalse(self.discover())

    def test_only_rooted_caller_supplied_to_detector_can_get_continuation(self):
        del self.facts[0x200]
        self.assertFalse(self.discover())

    def test_saved_stack_pointer_is_outside_fixed_frame_abi(self):
        self.facts[0x300] = instruction(0x300, "48e78081", "MOVEM.L", "{ A0 D0 SP}|-(SP)")
        self.facts[0x304] = replace(self.facts[0x304], operands="(0xc,SP)|A0")
        self.facts[0x30A] = replace(self.facts[0x30A], operands="A0|(0xc,SP)")
        self.facts[0x314] = instruction(0x314, "4cdf8101", "MOVEM.L", "(SP)+|{ D0 A0 SP}")
        self.assertFalse(self.discover())


if __name__ == "__main__":
    unittest.main()
