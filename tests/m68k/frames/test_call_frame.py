from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retrolarium_disasm.m68k.frames.call_frame import make_trap_call_frame_validator
from test_m68k_unused import instruction


class TrapCalleeFrameTests(unittest.TestCase):
    def trap_operation(self, operation):
        from test_m68k_dispatch_witness import InlineTrapWitnessTests
        case = InlineTrapWitnessTests()
        case.setUp()
        case.handler.pop(0x20E)
        case.handler.pop(0x212)
        restore = operation.cpu_address + operation.length
        case.handler.update({
            operation.cpu_address: operation,
            restore: instruction(restore, '4cdf7fff', 'MOVEM.L', '(SP)+|D0-A6'),
            restore + 4: instruction(restore + 4, '4e73', 'RTE', flow='TERMINATOR'),
        })
        case.known = {**case.handler, 0x500: case.known[0x500]}
        return case

    def fixture(self, helpers):
        # Keep the complete new witness in the test, not just its local guard.
        from test_m68k_dispatch_witness import InlineTrapWitnessTests
        case = InlineTrapWitnessTests()
        case.setUp()
        case.handler.pop(0x20E)
        case.handler.pop(0x212)
        case.handler.update({
            0x20E: instruction(0x20E, '4eb900000600', 'JSR', '0x600.l', 'UNCONDITIONAL_CALL', (0x600,)),
            0x214: instruction(0x214, '4cdf7fff', 'MOVEM.L', '(SP)+|D0-A6'),
            0x218: instruction(0x218, '4e73', 'RTE', flow='TERMINATOR'),
        })
        case.handler.update({f.cpu_address: f for f in helpers})
        case.known = {**case.handler, 0x500: case.known[0x500]}
        return case

    def test_register_only_nested_helper_preserves_inline_length(self):
        case = self.fixture([
            instruction(0x600, '7001', 'MOVEQ', '0x1|D0'),
            instruction(0x602, '5240', 'ADDQ.W', '0x1|D0w'),
            instruction(0x604, '4e75', 'RTS', flow='TERMINATOR'),
        ])
        self.assertTrue(case.validate())

    def test_balanced_local_save_restore_and_nested_direct_call(self):
        case = self.fixture([
            instruction(0x600, '48e7c000', 'MOVEM.L', 'D0-D1|-(SP)'),
            instruction(0x604, '4eb900000680', 'JSR', '0x680.l', 'UNCONDITIONAL_CALL', (0x680,)),
            instruction(0x60A, '4cdf0003', 'MOVEM.L', '(SP)+|D0-D1'),
            instruction(0x60E, '4e75', 'RTS', flow='TERMINATOR'),
            instruction(0x680, '3200', 'MOVE.W', 'D0w|D1w'),
            instruction(0x682, '4e75', 'RTS', flow='TERMINATOR'),
        ])
        self.assertTrue(case.validate())

    def test_balanced_single_address_register_save_restore(self):
        case = self.fixture([
            instruction(0x600, '2f08', 'MOVE.L', 'A0|-(SP)'),
            instruction(0x602, '207c00000700', 'MOVEA.L', '#0x700|A0'),
            instruction(0x608, '205f', 'MOVEA.L', '(SP)+|A0'),
            instruction(0x60A, '4e75', 'RTS', flow='TERMINATOR'),
        ])
        self.assertTrue(case.validate())

    def test_single_address_register_restore_must_match_on_every_path(self):
        helpers = [
            instruction(0x600, '2f08', 'MOVE.L', 'A0|-(SP)'),
            instruction(0x602, '225f', 'MOVEA.L', '(SP)+|A1'),
            instruction(0x604, '4e75', 'RTS', flow='TERMINATOR'),
        ]
        self.assertFalse(self.fixture(helpers).validate())
        self.assertFalse(self.fixture([
            instruction(0x600, '205f', 'MOVEA.L', '(SP)+|A0'),
            instruction(0x602, '4e75', 'RTS', flow='TERMINATOR'),
        ]).validate())
        self.assertFalse(self.fixture([
            instruction(0x600, '2f08', 'MOVE.L', 'A0|-(SP)'),
            instruction(0x602, '6702', 'BEQ.B', '0x606', 'CONDITIONAL_JUMP', (0x606,)),
            instruction(0x604, '205f', 'MOVEA.L', '(SP)+|A0'),
            instruction(0x606, '4e75', 'RTS', flow='TERMINATOR'),
        ]).validate())

    def test_trap_cannot_write_saved_pc_through_absolute_or_unknown_alias(self):
        # With supervisor SP=$FFF000 on TRAP entry, the saved exception PC
        # is at $FFEFFC. A second advance would return to $406, not $404.
        for operation in (
            instruction(0x20E, '54b900ffeffc', 'ADDQ.L', '0x2|(0x00ffeffc).l'),
            instruction(0x20E, '5490', 'ADDQ.L', '0x2|(A0)'),
        ):
            with self.subTest(operands=operation.operands):
                self.assertFalse(self.trap_operation(operation).validate())

    def test_trap_sr_write_cannot_switch_to_unproved_user_stack(self):
        case = self.trap_operation(instruction(0x20E, '46fc0000', 'MOVE', '#0x0|SR'))
        self.assertFalse(case.validate())

    def test_trap_cannot_save_stack_pointer_or_write_usp(self):
        from test_m68k_dispatch_witness import InlineTrapWitnessTests
        case = InlineTrapWitnessTests()
        case.setUp()
        case.handler.update({
            0x200: instruction(0x200, '48e7ffff', 'MOVEM.L', 'D0-SP|-(SP)'),
            0x204: instruction(0x204, '2c6f0042', 'MOVEA.L', '(0x42,SP)|A6'),
            0x208: instruction(0x208, '54af0042', 'ADDQ.L', '0x2|(0x42,SP)'),
            0x20E: instruction(0x20E, '4cdfffff', 'MOVEM.L', '(SP)+|D0-SP'),
        })
        case.known = {**case.handler, 0x500: case.known[0x500]}
        self.assertFalse(case.validate())
        self.assertFalse(self.trap_operation(
            instruction(0x20E, '4e60', 'MOVE', 'A0|USP')).validate())
        self.assertFalse(self.fixture([
            instruction(0x600, '4e60', 'MOVE', 'A0|USP'),
            instruction(0x602, '4e75', 'RTS', flow='TERMINATOR'),
        ]).validate())

    def test_divide_and_bounds_check_exceptions_are_not_returning_helpers(self):
        for operation in (
            instruction(0x600, '80fc0000', 'DIVU.W', '#0x0|D0'),
            instruction(0x600, '81fc0000', 'DIVS.W', '#0x0|D0'),
            instruction(0x600, '41bc0000', 'CHK.W', '#0x0|D0w'),
        ):
            case = self.fixture([
                operation,
                instruction(operation.cpu_address + operation.length, '4e75', 'RTS', flow='TERMINATOR'),
            ])
            with self.subTest(operation=operation.mnemonic):
                self.assertFalse(case.validate())

    def test_nested_helper_cannot_advance_saved_exception_pc_again(self):
        case = self.fixture([
            # Handler saved 15 long registers. The helper's JSR pushed four
            # more bytes, so its caller's exception PC is at $42(SP).
            instruction(0x600, '54af0042', 'ADDQ.L', '0x2|(0x42,SP)'),
            instruction(0x604, '4e75', 'RTS', flow='TERMINATOR'),
        ])
        self.assertFalse(case.validate())

    def test_unknown_computed_call_recursive_call_and_closed_loop_rejected(self):
        for first in (
            instruction(0x600, '4eb900000680', 'JSR', '0x680.l', 'UNCONDITIONAL_CALL', (0x680,)),
            instruction(0x600, '4e90', 'JSR', '(A0)', 'COMPUTED_CALL'),
            instruction(0x600, '4eb900000600', 'JSR', '0x600.l', 'UNCONDITIONAL_CALL', (0x600,)),
            instruction(0x600, '60fe', 'BRA.B', '0x600', 'UNCONDITIONAL_JUMP', (0x600,)),
        ):
            with self.subTest(first=first.operands):
                case = self.fixture([first, instruction(0x600 + first.length, '4e75', 'RTS', flow='TERMINATOR')])
                self.assertFalse(case.validate())

    def test_stack_alias_implicit_stack_change_unknown_store_and_sr_rejected(self):
        for first in (
            instruction(0x600, '204f', 'MOVEA.L', 'SP|A0'),
            instruction(0x600, '41ef0042', 'LEA', '(0x42,SP)|A0'),
            instruction(0x600, '4850', 'PEA', '(A0)'),
            instruction(0x600, '4e56fffc', 'LINK', 'A6|#-0x4'),
            instruction(0x600, '4e5e', 'UNLK', 'A6'),
            instruction(0x600, '4290', 'CLR.L', '(A0)'),
            instruction(0x600, '46fc0000', 'MOVE', '#0x0|SR'),
        ):
            with self.subTest(first=first.mnemonic, operands=first.operands):
                case = self.fixture([first, instruction(0x600 + first.length, '4e75', 'RTS', flow='TERMINATOR')])
                self.assertFalse(case.validate())

    def test_unbalanced_movem_or_incompatible_branch_stack_rejected(self):
        case = self.fixture([
            instruction(0x600, '48e7c000', 'MOVEM.L', 'D0-D1|-(SP)'),
            instruction(0x604, '6704', 'BEQ.B', '0x60a', 'CONDITIONAL_JUMP', (0x60A,)),
            instruction(0x606, '4cdf0003', 'MOVEM.L', '(SP)+|D0-D1'),
            instruction(0x60A, '4e75', 'RTS', flow='TERMINATOR'),
        ])
        self.assertFalse(case.validate())

    def test_callee_without_reachable_rts_and_trap_with_missing_decode_rejected(self):
        case = self.fixture([
            instruction(0x600, '600000fe', 'BRA.W', '0x700', 'UNCONDITIONAL_JUMP', (0x700,)),
        ])
        self.assertFalse(case.validate())
        self.assertFalse(make_trap_call_frame_validator({})(0x200))


if __name__ == '__main__':
    unittest.main()
