from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from retrolarium_kit.m68k_link_continuations import discover_link_continuation_seeds
from retrolarium_kit.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_m68k_unused import instruction


class LinkContinuationTests(unittest.TestCase):
    def setUp(self):
        self.image = parse_megadrive(cartridge(size=0x800))

    def seeds(self, *facts):
        return [(seed.address, seed.source_address)
                for seed in discover_link_continuation_seeds(
                    self.image, {fact.cpu_address: fact for fact in facts})]

    def test_lea_naming_the_instruction_after_bra_is_a_continuation(self):
        self.assertEqual([(0x206, 0x200)], self.seeds(
            instruction(0x200, "41fa0004", "LEA", "(0x4,PC)|A0"),
            instruction(0x204, "60fa", "BRA.B", "0x300", "UNCONDITIONAL_JUMP", (0x300,)),
        ))

    def test_pea_before_jmp_is_a_continuation(self):
        self.assertEqual([(0x20A, 0x200)], self.seeds(
            instruction(0x200, "487a0008", "PEA", "(0x8,PC)"),
            instruction(0x204, "4ef900000300", "JMP", "0x300.l", "UNCONDITIONAL_JUMP", (0x300,)),
        ))

    def test_non_adjacent_address_or_call_is_a_data_argument(self):
        self.assertEqual([], self.seeds(
            instruction(0x200, "41fa0010", "LEA", "(0x10,PC)|A0"),
            instruction(0x204, "60fa", "BRA.B", "0x300", "UNCONDITIONAL_JUMP", (0x300,)),
        ))
        self.assertEqual([], self.seeds(
            instruction(0x200, "487a0008", "PEA", "(0x8,PC)"),
            instruction(0x204, "4eb900000300", "JSR", "0x300.l", "UNCONDITIONAL_CALL", (0x300,)),
        ))


if __name__ == "__main__":
    unittest.main()
