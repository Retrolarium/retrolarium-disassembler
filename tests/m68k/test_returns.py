from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_disasm.m68k.returns import discover_returning_call_seeds
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_m68k_unused import instruction


class NormalReturnTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            0x200: instruction(0x200, "4eb900000300", "JSR", "0x300.l", "CALL_TERMINATOR", (0x300,)),
            0x220: instruction(0x220, "4ef900000300", "JMP", "0x300.l", "CALL_TERMINATOR", (0x300,)),
            0x300: instruction(0x300, "6000001e", "BRA.W", "0x320", "UNCONDITIONAL_JUMP", (0x320,)),
            0x320: instruction(0x320, "4a3900ff1000", "TST.B", "(0xff1000).l"),
            0x326: instruction(0x326, "66f8", "BNE.B", "0x320", "CONDITIONAL_JUMP", (0x320,)),
            0x328: instruction(0x328, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.image = parse_megadrive(cartridge(size=0x800))

    def discover(self, calls=None):
        return {s.address for s in discover_returning_call_seeds(self.image, self.facts, calls)}

    def test_external_ram_busy_wait_can_return_through_tail_thunk(self):
        self.assertEqual({0x206}, self.discover())
        self.assertFalse(self.discover({0x220: self.facts[0x220]}))

    def test_unreachable_rts_does_not_prove_return(self):
        self.facts[0x326] = replace(self.facts[0x326], flow_type="UNCONDITIONAL_JUMP")
        self.assertFalse(self.discover())

    def test_constant_flags_cannot_make_infeasible_rts_a_return_witness(self):
        self.facts[0x320] = instruction(0x320, "7000", "MOVEQ", "0x0|D0")
        self.facts[0x322] = instruction(0x322, "4a40", "TST.W", "D0w")
        self.facts[0x324] = instruction(0x324, "67fc", "BEQ.B", "0x322", "CONDITIONAL_JUMP", (0x322,))
        self.facts[0x326] = instruction(0x326, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.discover())

    def test_balanced_saved_registers_return_but_bookmark_does_not(self):
        self.facts[0x300] = instruction(0x300, "48e7fffe", "MOVEM.L", "D0-A6|-(SP)")
        self.facts[0x304] = instruction(0x304, "4cdf7fff", "MOVEM.L", "(SP)+|D0-A6")
        self.facts[0x308] = instruction(0x308, "4e75", "RTS", flow="TERMINATOR")
        self.assertEqual({0x206}, self.discover())
        self.facts[0x300] = instruction(0x300, "215f0004", "MOVE.L", "(SP)+|(0x4,A0)")
        self.assertFalse(self.discover())

    def test_normal_return_must_restore_stack_and_nested_callee_must_return(self):
        self.facts[0x300] = instruction(0x300, "3f00", "MOVE.W", "D0w|-(SP)")
        self.facts[0x302] = instruction(0x302, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.discover())
        self.facts[0x300] = instruction(0x300, "6100001e", "BSR.W", "0x320", "CALL_TERMINATOR", (0x320,))
        self.facts[0x304] = instruction(0x304, "4e75", "RTS", flow="TERMINATOR")
        self.assertEqual({0x206, 0x304}, self.discover())
        self.facts[0x326] = replace(self.facts[0x326], flow_type="UNCONDITIONAL_JUMP")
        self.assertFalse(self.discover())

    def test_address_register_pop_and_backend_suppressed_tail_branch(self):
        self.facts[0x300] = instruction(0x300, "2f08", "MOVE.L", "A0|-(SP)")
        self.facts[0x302] = instruction(0x302, "205f", "MOVEA.L", "(SP)+|A0")
        self.facts[0x304] = instruction(0x304, "6000001a", "BRA.W", "0x320", "CALL_TERMINATOR", (0x320,))
        self.assertEqual({0x206}, self.discover())
        # Restoring more than was saved consumes the caller's return PC.
        self.facts[0x300] = instruction(0x300, "3f08", "MOVE.W", "A0w|-(SP)")
        self.assertFalse(self.discover())

    def test_width_qualified_stack_alias_cannot_prove_normal_return(self):
        self.facts[0x300] = instruction(0x300, "304f", "MOVEA.W", "A7w|A0")
        self.facts[0x302] = instruction(0x302, "5890", "ADDQ.L", "0x4|(A0)")
        self.facts[0x304] = instruction(0x304, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.discover())

    def test_movem_restoring_stack_register_is_not_a_balanced_frame_witness(self):
        self.facts[0x300] = instruction(0x300, "48e7ffff", "MOVEM.L", "D0-A7|-(SP)")
        self.facts[0x304] = instruction(0x304, "4cdfffff", "MOVEM.L", "(SP)+|D0-A7")
        self.facts[0x308] = instruction(0x308, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.discover())


if __name__ == "__main__":
    unittest.main()
