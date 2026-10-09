from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.frames.link_continuations import discover_link_continuation_seeds
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from m68k.builders import instruction


LEA = instruction(0x200, "41fa0004", "LEA", "(0x4,PC)|A0")
BRA = instruction(0x204, "60fa", "BRA.B", "0x300", "UNCONDITIONAL_JUMP", (0x300,))
CALLEE_JUMPS_THROUGH_A0 = (
    instruction(0x300, "7001", "MOVEQ", "0x1|D0"),
    instruction(0x302, "4ed0", "JMP", "(A0)", "COMPUTED_JUMP"),
)


class LinkContinuationTests(unittest.TestCase):
    def setUp(self):
        self.image = parse_megadrive(cartridge(size=0x800))

    def seeds(self, *facts):
        return [(seed.address, seed.source_address)
                for seed in discover_link_continuation_seeds(
                    self.image, {fact.cpu_address: fact for fact in facts})]

    def test_lea_naming_the_instruction_after_bra_is_a_continuation(self):
        self.assertEqual([(0x206, 0x200)], self.seeds(LEA, BRA, *CALLEE_JUMPS_THROUGH_A0))

    def test_callee_must_resume_through_the_same_register(self):
        self.assertEqual([], self.seeds(
            LEA, BRA, instruction(0x300, "4e75", "RTS", flow="TERMINATOR")))
        self.assertEqual([], self.seeds(
            LEA, BRA, instruction(0x300, "4ed1", "JMP", "(A1)", "COMPUTED_JUMP")))
        self.assertEqual([], self.seeds(
            LEA, BRA, instruction(0x300, "207c00000400", "MOVEA.L", "#0x400|A0"),
            instruction(0x306, "4ed0", "JMP", "(A0)", "COMPUTED_JUMP")))

    def test_non_adjacent_address_or_call_is_a_data_argument(self):
        self.assertEqual([], self.seeds(
            instruction(0x200, "41fa0010", "LEA", "(0x10,PC)|A0"), BRA, *CALLEE_JUMPS_THROUGH_A0))
        self.assertEqual([], self.seeds(
            LEA, instruction(0x204, "4eb900000300", "JSR", "0x300.l", "UNCONDITIONAL_CALL", (0x300,)),
            *CALLEE_JUMPS_THROUGH_A0))


if __name__ == "__main__":
    unittest.main()
