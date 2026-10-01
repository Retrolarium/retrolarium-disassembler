from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.m68k_dispatch_witness import make_dispatch_handler_validator
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_emit import _asm_instruction
from test_megadrive import cartridge
from test_m68k_unused import instruction


class DispatchWitnessTests(unittest.TestCase):
    def setUp(self):
        self.known = {0x500: instruction(0x500, '4e75', 'RTS', flow='TERMINATOR')}
        self.decoded = {
            0x400: instruction(0x400, '4eb900000500', 'JSR', '0x500.l', 'UNCONDITIONAL_CALL', (0x500,)),
            0x406: instruction(0x406, '4a40', 'TST.W', 'D0w'),
            0x408: instruction(0x408, '5240', 'ADDQ.W', '0x1|D0w'),
            0x40A: instruction(0x40A, '4e75', 'RTS', flow='TERMINATOR'),
        }
        self.bytes = bytearray(cartridge(size=0x800))
        for f in (*self.known.values(), *self.decoded.values()):
            self.bytes[f.cpu_address:f.cpu_address + f.length] = f.raw

    def validate(self, **kwargs):
        return make_dispatch_handler_validator(
            parse_megadrive(bytes(self.bytes)), self.known, self.decoded,
            render_instruction=kwargs.pop('render_instruction', _asm_instruction), **kwargs)(0x400)

    def test_complete_handler_with_rooted_call_and_rts(self):
        self.assertTrue(self.validate())

    def test_known_tail_exit_is_valid_but_unknown_target_is_not(self):
        self.decoded[0x40A] = instruction(0x40A, '600000f4', 'BRA.W', '0x500', 'UNCONDITIONAL_JUMP', (0x500,))
        self.bytes[0x40A:0x40E] = self.decoded[0x40A].raw
        self.assertTrue(self.validate())
        self.decoded[0x40A] = replace(self.decoded[0x40A], flows=(0x600,))
        self.assertFalse(self.validate())

    def test_missing_decode_or_conflicting_bytes_rejected(self):
        removed = self.decoded.pop(0x406)
        self.assertFalse(self.validate())
        self.decoded[0x406] = removed
        self.bytes[0x408] ^= 1
        self.assertFalse(self.validate())

    def test_data_range_or_read_as_data_rejected(self):
        self.assertFalse(self.validate(protected_ranges=((0x406, 0x408),)))
        self.known[0x500] = replace(self.known[0x500], references=(InstructionReference(0x408, 'READ', 0),))
        self.assertFalse(self.validate())

    def test_connection_must_be_to_rooted_code(self):
        self.known = {}
        self.assertFalse(self.validate())

    def test_instruction_interior_cannot_be_a_witness(self):
        self.known[0x3FE] = instruction(0x3FE, '303c0000', 'MOVE.W', '0x0|D0w')
        self.assertFalse(self.validate())

    def test_non_renderable_or_exceptional_exit_rejected(self):
        self.assertFalse(self.validate(render_instruction=lambda f: None if f.cpu_address == 0x408 else _asm_instruction(f)))
        self.decoded[0x40A] = instruction(0x40A, '4e73', 'RTE', flow='TERMINATOR')
        self.bytes[0x40A:0x40C] = self.decoded[0x40A].raw
        self.assertFalse(self.validate())

    def test_branch_into_operand_or_nonreturning_loop_rejected(self):
        self.decoded[0x40A] = instruction(0x40A, '60f8', 'BRA.B', '0x404', 'UNCONDITIONAL_JUMP', (0x404,))
        self.bytes[0x40A:0x40C] = self.decoded[0x40A].raw
        self.assertFalse(self.validate())
        self.decoded[0x40A] = replace(self.decoded[0x40A], raw=bytes.fromhex('60f4'), flows=(0x400,))
        self.bytes[0x40A:0x40C] = self.decoded[0x40A].raw
        self.assertFalse(self.validate())


if __name__ == '__main__':
    unittest.main()
