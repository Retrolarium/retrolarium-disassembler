from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retrolarium_kit.m68k_leaf_dispatch import discover_leaf_word_dispatch_seeds
from retrolarium_kit.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class LeafDispatchTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(cartridge(size=0x1000))
        self.table, self.targets = 0x400, (0x408, 0x420, 0x440, 0x460)
        self.write_table()
        self.items = [
            fact(0x200, 'LEA', '(0x400).l|A1'),
            replace(fact(0x202, 'JMP', '0x300', flows=(0x300,)), flow_type='UNCONDITIONAL_JUMP'),
            fact(0x300, 'MOVE.W', '(0x2,A0)|D0w'),
            fact(0x302, 'ADD.W', 'D0w|D0w'),
            fact(0x304, 'ADDA.W', '(0x0,A1,D0w*0x1)|A1'),
            replace(fact(0x306, 'JMP', '(A1)'), flow_type='COMPUTED_JUMP'),
            replace(fact(0x408, 'RTS', ''), flow_type='TERMINATOR'),
        ]

    def write_table(self, absolute=False):
        for i, target in enumerate(self.targets):
            value = target if absolute else target - self.table
            self.data[self.table+2*i:self.table+2*i+2] = (value & 0xFFFF).to_bytes(2, 'big')
            self.data[target:target+2] = bytes.fromhex('4e75')

    def seeds(self, **kwargs):
        return discover_leaf_word_dispatch_seeds(parse_megadrive(bytes(self.data)),
            {f.cpu_address: f for f in self.items}, **kwargs)

    def test_shared_relative_dispatcher_and_first_handler_bound(self):
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.assertTrue(all(s.confidence == 'proven' for s in self.seeds()))
        self.assertTrue(all(s.source_address == 0x200 for s in self.seeds()))

    def test_single_tail_thunk_supported_but_two_not_assumed(self):
        self.items[1] = replace(self.items[1], flows=(0x280,))
        self.items.append(replace(fact(0x280, 'JMP', '0x300', flows=(0x300,)), flow_type='UNCONDITIONAL_JUMP'))
        self.assertEqual(4, len(self.seeds()))
        self.items[-1] = replace(self.items[-1], flows=(0x290,))
        self.items.append(replace(fact(0x290, 'JMP', '0x300', flows=(0x300,)), flow_type='UNCONDITIONAL_JUMP'))
        self.assertFalse(self.seeds())

    def test_zero_extended_absolute_word_dispatcher(self):
        self.write_table(absolute=True)
        self.items = self.items[:2] + [
            fact(0x300, 'MOVEQ', '0x0|D0'),
            fact(0x302, 'MOVE.W', '(0x2,A0)|D0w'),
            fact(0x304, 'ADD.W', 'D0w|D0w'),
            fact(0x306, 'MOVE.W', '(0x0,A1,D0w*0x1)|D0w'),
            fact(0x308, 'MOVEA.L', 'D0|A1'),
            replace(fact(0x30A, 'JMP', '(A1)'), flow_type='COMPUTED_JUMP'),
            fact(0x408, 'RTS', '')]
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.items[2] = replace(self.items[2], operands='0x1|D0')
        self.assertFalse(self.seeds())

    def test_no_table_decode_conflicts_and_signed_backward_target(self):
        self.targets = (0x380, 0x420, 0x440, 0x460)
        self.write_table()
        self.items += [fact(0x380, 'RTS', ''), replace(fact(0x400, 'MOVE.L', 'D0|D1'), length=8)]
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])

    def test_handler_overlap_skipped_without_losing_later_slots(self):
        self.items.append(replace(fact(0x41E, 'MOVE.L', 'D0|D1'), length=4))
        self.assertEqual([0x408, 0x440, 0x460], [s.address for s in self.seeds()])

    def test_register_clobber_and_wrong_index_scale_rejected(self):
        for index, changes in ((0, {'operands':'(0x400).l|A2'}),
                               (3, {'operands':'D0w|D1w'}),
                               (4, {'operands':'(0x0,A1,D1w*0x1)|A1'}),
                               (5, {'operands':'(A2)'})):
            old = self.items[index]
            self.items[index] = replace(old, **changes)
            self.assertFalse(self.seeds())
            self.items[index] = old

    def test_adjacent_handler_bounds_unseen_code_but_gapped_table_needs_witness(self):
        self.items.pop()
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.targets = (0x420, 0x440, 0x460, 0x480)
        self.write_table()
        self.assertFalse(self.seeds())
        self.items.append(fact(0x420, 'RTS', ''))
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])

    def test_minimum_two_entries_and_complete_bounds_required(self):
        self.data[0x402:0x404] = bytes.fromhex('ffff')
        self.assertFalse(self.seeds())

    def test_gapped_table_can_use_a_validated_handler_but_not_an_unchecked_probe(self):
        self.items.pop()
        self.targets = (0x420, 0x440, 0x460, 0x480)
        self.write_table()
        self.assertFalse(self.seeds(handler_validator=lambda target: False))
        seeds = self.seeds(handler_validator=lambda target: target == 0x440)
        self.assertEqual(list(self.targets), [s.address for s in seeds])
        self.assertTrue(all('handler 000440 has a complete bounded CFG' in s.evidence for s in seeds))

    def test_adjacent_table_does_not_request_a_speculative_handler(self):
        def unnecessary(target):
            self.fail('adjacent handler is already a boundary witness')
        self.items.pop()
        self.assertEqual(4, len(self.seeds(handler_validator=unnecessary)))

    def test_conditional_transfer_not_a_leaf_dispatch_call(self):
        self.items[1] = replace(self.items[1], mnemonic='BNE', flow_type='CONDITIONAL_JUMP')
        self.assertFalse(self.seeds())

    def test_inline_scaled_index_add_and_jump_uses_same_table_base(self):
        self.items = [fact(0x1FE, 'ADD.W', 'D2w|D2w'), self.items[0],
                      fact(0x202, 'ADDA.W', '(0x0,A1,D2w*0x1)|A1'),
                      replace(fact(0x204, 'JMP', '(A1)'), flow_type='COMPUTED_JUMP'),
                      self.items[-1]]
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.assertTrue(all(s.kind == 'inline_word_dispatch' for s in self.seeds()))
        for index, operand in ((0,'D1w|D1w'), (2,'(0x0,A1,D3w*0x1)|A1'), (3,'(A2)')):
            old = self.items[index]
            self.items[index] = replace(old, operands=operand)
            self.assertFalse(self.seeds())
            self.items[index] = old


if __name__ == '__main__':
    unittest.main()
