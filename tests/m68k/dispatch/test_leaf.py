from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_disasm.m68k.dispatch.leaf import discover_leaf_word_dispatch_seeds
from retrolarium_core.megadrive import parse_megadrive
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
        kwargs.setdefault('handler_validator', lambda target: target in self.targets)
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

    def unsigned_relative_items(self):
        return self.items[:2] + [
            fact(0x300, 'MOVEQ', '0x0|D0'),
            fact(0x302, 'MOVE.W', '(0x2,A0)|D0w'),
            fact(0x304, 'ADD.W', 'D0w|D0w'),
            fact(0x306, 'MOVE.W', '(0x0,A1,D0w*0x1)|D0w'),
            fact(0x308, 'ADDA.L', 'D0|A1'),
            replace(fact(0x30A, 'JMP', '(A1)'), flow_type='COMPUTED_JUMP'),
            fact(0x408, 'RTS', '')]

    def test_unsigned_relative_words_keep_high_bit_positive(self):
        self.data = bytearray(cartridge(size=0x10000))
        self.targets = (0x408, 0x8420, 0x8440, 0x8460)
        self.write_table()
        self.items = self.unsigned_relative_items()
        seeds = self.seeds()
        self.assertEqual(list(self.targets), [s.address for s in seeds])
        self.assertTrue(all('zero-extended table-relative' in s.evidence for s in seeds))

    def test_unsigned_relative_requires_zero_high_half_and_unchanged_base(self):
        self.items = self.unsigned_relative_items()
        for index, changes in ((2, {'operands': '0x0|D1'}),
                               (2, {'mnemonic': 'CLR.W', 'operands': 'D0w'}),
                               (2, {'operands': '0x1|D0'}),
                               (3, {'mnemonic': 'MOVE.L', 'operands': '(0x2,A0)|D0'}),
                               (4, {'mnemonic': 'ADD.L', 'operands': 'D0|D0'}),
                               (5, {'operands': '(0x0,A2,D0w*0x1)|D0w'}),
                               (6, {'operands': 'D0|A2'}),
                               (7, {'operands': '(A2)'})):
            with self.subTest(index=index, changes=changes):
                old = self.items[index]
                self.items[index] = replace(old, **changes)
                self.assertFalse(self.seeds())
                self.items[index] = old
        # Entering after MOVEQ leaves the previous high half unknown.
        self.items[1] = replace(self.items[1], flows=(0x302,))
        self.assertFalse(self.seeds())

    def test_indexed_jump_sign_extends_the_loaded_word(self):
        self.targets = (0x380, 0x420, 0x440, 0x460)
        self.write_table()
        self.items[4] = replace(self.items[4], mnemonic='MOVE.W', operands='(0x0,A1,D0w*0x1)|D0w')
        self.items[5] = replace(self.items[5], operands='(0x0,A1,D0w*0x1)')
        self.items.append(fact(0x380, 'RTS', ''))
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        for index, operand in ((4, '(0x0,A1,D0w*0x1)|D1w'),
                               (5, '(0x0,A2,D0w*0x1)'),
                               (5, '(0x0,A1,D0l*0x1)'),
                               (5, '(0x2,A1,D0w*0x1)')):
            with self.subTest(index=index, operand=operand):
                old = self.items[index]
                self.items[index] = replace(old, operands=operand)
                self.assertFalse(self.seeds())
                self.items[index] = old

    def test_indexed_jump_second_entry_accepts_caller_supplied_index(self):
        self.items[1] = replace(self.items[1], flows=(0x302,))
        self.items[4] = replace(self.items[4], mnemonic='MOVE.W', operands='(0x0,A1,D0w*0x1)|D0w')
        self.items[5] = replace(self.items[5], operands='(0x0,A1,D0w*0x1)')
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.items[3] = replace(self.items[3], mnemonic='LSL.W', operands='#0x2|D0w')
        self.assertFalse(self.seeds())

    def test_new_leaf_shapes_still_require_bounds_or_handler_witness(self):
        self.items = self.unsigned_relative_items()[:-1]
        self.targets = (0x420, 0x440, 0x460, 0x480)
        self.write_table()
        self.assertFalse(self.seeds(handler_validator=lambda target: False))
        self.assertEqual([0x440], [s.address for s in self.seeds(
            handler_validator=lambda target: target == 0x440)])

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

    def test_adjacent_and_gapped_tables_both_need_per_target_witnesses(self):
        self.items.pop()
        self.assertFalse(self.seeds(handler_validator=None))
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.targets = (0x420, 0x440, 0x460, 0x480)
        self.write_table()
        self.assertFalse(self.seeds(handler_validator=None))
        self.items.append(fact(0x420, 'RTS', ''))
        self.assertEqual([0x420], [s.address for s in self.seeds(handler_validator=None)])

    def test_minimum_two_entries_and_complete_bounds_required(self):
        self.data[0x402:0x404] = bytes.fromhex('ffff')
        self.assertFalse(self.seeds())

    def test_gapped_table_can_use_a_validated_handler_but_not_an_unchecked_probe(self):
        self.items.pop()
        self.targets = (0x420, 0x440, 0x460, 0x480)
        self.write_table()
        self.assertFalse(self.seeds(handler_validator=lambda target: False))
        seeds = self.seeds(handler_validator=lambda target: target == 0x440)
        self.assertEqual([0x440], [s.address for s in seeds])
        self.assertTrue(all('handler 000440 has a complete bounded CFG' in s.evidence for s in seeds))

    def test_adjacent_table_does_not_prove_an_unknown_handler(self):
        self.items.pop()
        self.assertFalse(self.seeds(handler_validator=lambda target: False))

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

    def inline_indexed_items(self, operation='JMP'):
        return [self.items[0],
                fact(0x202, 'ADD.W', 'D2w|D2w'),
                fact(0x204, 'MOVE.W', '(0x0,A1,D2w*0x1)|D2w'),
                replace(fact(0x206, operation, '(0x0,A1,D2w*0x1)'),
                        flow_type='COMPUTED_CALL' if operation == 'JSR' else 'COMPUTED_JUMP'),
                self.items[-1]]

    def test_inline_scaled_word_load_and_indexed_jump_or_call(self):
        initial = self.items
        for operation in ('JMP', 'JSR'):
            with self.subTest(operation=operation):
                self.items = initial
                self.items = self.inline_indexed_items(operation)
                seeds = self.seeds()
                self.assertEqual(list(self.targets), [s.address for s in seeds])
                self.assertTrue(all(s.kind == 'inline_word_dispatch' for s in seeds))
                self.assertTrue(all(s.source_address == 0x200 for s in seeds))

    def test_inline_indexed_word_sign_and_bounds(self):
        self.targets = (0x380, 0x420, 0x440, 0x460)
        self.write_table()
        self.items = self.inline_indexed_items()[:-1] + [fact(0x380, 'RTS', '')]
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])
        self.items.pop()
        self.assertFalse(self.seeds(handler_validator=lambda target: False))
        self.assertEqual([0x440], [s.address for s in self.seeds(
            handler_validator=lambda target: target == 0x440)])

    def test_first_forward_handler_does_not_prove_adjacent_data_offsets(self):
        self.targets = (0x406, 0x420, 0x440)
        self.write_table()
        self.items = self.items[:-1]
        # Only the first two words belong to the real table. The third is
        # adjacent data before the earliest handler, so exact geometry alone
        # must not seed it even when another target is independently valid.
        seeds = self.seeds(handler_validator=lambda target: target in {0x406, 0x420})
        self.assertEqual([0x406, 0x420], [s.address for s in seeds])

    def test_boundary_inside_word_prevents_cross_object_slot(self):
        from retrolarium_disasm.facts import InstructionReference
        self.items.append(replace(fact(0x500, 'LEA', '(0x403).l|A2'),
            references=(InstructionReference(0x403, 'DATA', 0),)))
        self.assertFalse(self.seeds())

    def masked_inline_items(self, mask):
        return [replace(fact(0x200, 'ANDI.W', f'#0x{mask:x}|D2w'), length=4),
                replace(fact(0x204, 'LEA', '(0x400).l|A1'), length=6),
                fact(0x20A, 'ADD.W', 'D2w|D2w'),
                replace(fact(0x20C, 'MOVE.W', '(0x0,A1,D2w*0x1)|D2w'), length=4),
                replace(fact(0x210, 'JMP', '(0x0,A1,D2w*0x1)'), length=4,
                        flow_type='COMPUTED_JUMP')]

    def test_mask_caps_table_even_when_adjacent_targets_have_valid_cfgs(self):
        self.items = self.masked_inline_items(1)
        self.assertEqual(list(self.targets[:2]), [s.address for s in self.seeds()])

    def test_noncontiguous_mask_skips_unreachable_slots(self):
        self.items = self.masked_inline_items(2)
        self.assertEqual([self.targets[0], self.targets[2]], [s.address for s in self.seeds()])

    def test_entry_bypassing_mask_cannot_reuse_its_bound(self):
        self.items = self.masked_inline_items(1)
        self.assertEqual(list(self.targets), [s.address for s in self.seeds(entrypoints=(0x204,))])
        self.items.append(replace(fact(0x240, 'BRA.W', '0x204', flows=(0x204,)),
                                  flow_type='UNCONDITIONAL_JUMP'))
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])

    def test_shared_leaf_uses_call_site_mask_for_caller_supplied_index(self):
        self.items = self.masked_inline_items(1)[:2] + [
            replace(fact(0x20A, 'JMP', '0x300', flows=(0x300,)), flow_type='UNCONDITIONAL_JUMP'),
            fact(0x300, 'ADD.W', 'D2w|D2w'),
            fact(0x302, 'MOVE.W', '(0x0,A1,D2w*0x1)|D2w'),
            replace(fact(0x304, 'JMP', '(0x0,A1,D2w*0x1)'), flow_type='COMPUTED_JUMP')]
        self.assertEqual(list(self.targets[:2]), [s.address for s in self.seeds()])

    def test_leaf_memory_read_replaces_call_site_masked_index(self):
        body = self.items[2:]
        self.items = [replace(fact(0x1FC, 'ANDI.W', '#0x1|D0w'), length=4),
                      *self.items[:2], *body]
        self.assertEqual(list(self.targets), [s.address for s in self.seeds()])

    def test_inline_indexed_form_rejects_unproven_arithmetic_and_bases(self):
        self.items = self.inline_indexed_items()
        for index, changes in ((0, {'operands': '(0x400).l|A2'}),
                               (1, {'operands': 'D1w|D1w'}),
                               (1, {'mnemonic': 'ADD.L', 'operands': 'D2|D2'}),
                               (1, {'flow_type': 'CONDITIONAL_JUMP'}),
                               (2, {'operands': '(0x0,A1,D2w*0x1)|D3w'}),
                               (2, {'operands': '(0x0,A2,D2w*0x1)|D2w'}),
                               (2, {'mnemonic': 'MOVE.L'}),
                               (3, {'operands': '(0x0,A2,D2w*0x1)'}),
                               (3, {'operands': '(0x0,A1,D2l*0x1)'}),
                               (3, {'flow_type': 'UNCONDITIONAL_CALL'})):
            with self.subTest(index=index, changes=changes):
                old = self.items[index]
                self.items[index] = replace(old, **changes)
                self.assertFalse(self.seeds())
                self.items[index] = old

    def test_inline_indexed_form_does_not_cross_a_conditional_base_selection(self):
        self.items = [self.items[0],
                      replace(fact(0x202, 'BEQ.B', '0x208', flows=(0x208,)),
                              flow_type='CONDITIONAL_JUMP'),
                      fact(0x204, 'LEA', '(0x500).l|A1'),
                      fact(0x206, 'ADD.W', 'D2w|D2w'),
                      fact(0x208, 'MOVE.W', '(0x0,A1,D2w*0x1)|D2w'),
                      replace(fact(0x20A, 'JMP', '(0x0,A1,D2w*0x1)'), flow_type='COMPUTED_JUMP'),
                      self.items[-1]]
        # Neither base has a proven complete table for its path. In particular,
        # the table at 0x400 must not be attached to the second LEA's reader.
        self.assertFalse(self.seeds())


if __name__ == '__main__':
    unittest.main()
