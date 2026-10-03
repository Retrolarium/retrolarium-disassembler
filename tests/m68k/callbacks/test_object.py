from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.m68k_abstract import discover_object_field_handler_candidates
from retrolarium_kit.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_z80 import fact


def instruction(address, mnemonic, operands='', *, length=2, flows=(), flow='FALL_THROUGH'):
    return replace(fact(address, mnemonic, operands, flows=flows), length=length,
                   raw=b'\x4e\x75' if mnemonic == 'RTS' else b'\x4e\x71' * (length // 2),
                   flow_type=flow)


def fixture():
    data = bytearray(cartridge(size=0x1000))
    data[0x800:0x804] = bytes.fromhex('302d0016')
    # The writer uses A0; the executor obtains A5 through the same list head.
    items = [
        instruction(0x200, 'JSR', '0x280', length=6, flows=(0x280,), flow='UNCONDITIONAL_CALL'),
        instruction(0x206, 'MOVE.L', '#0x800|(0x4,A0)', length=8),
        instruction(0x280, 'JMP', '0x300', length=4, flows=(0x300,), flow='UNCONDITIONAL_JUMP'),
        instruction(0x300, 'MOVEM.L', '{ A1 D4 D5}|-(SP)', length=4),
        instruction(0x304, 'MOVEA.L', '(0xffff9000).w|A0', length=4),
        instruction(0x308, 'LEA', '(-0x6000).w|A1', length=4),
        instruction(0x30c, 'MOVE.L', '(0x0,A1)|D4', length=4),
        instruction(0x310, 'BEQ.B', '0x31c', flows=(0x31c,), flow='CONDITIONAL_JUMP'),
        instruction(0x312, 'MOVE.L', 'A1|D5'),
        instruction(0x314, 'MOVEA.L', 'D4|A1'),
        instruction(0x316, 'CMP.W', '(0xe,A1)|D0w', length=4),
        instruction(0x31a, 'BHI.B', '0x30c', flows=(0x30c,), flow='CONDITIONAL_JUMP'),
        instruction(0x31c, 'MOVE.L', '(A1)|(A0)'),
        instruction(0x31e, 'MOVE.L', 'A0|(A1)'),
        instruction(0x320, 'MOVEM.L', '(SP)+|{ D4 D5 A1}', length=4),
        instruction(0x324, 'RTS', flow='TERMINATOR'),
        instruction(0x400, 'LEA', '(-0x6000).w|A5', length=4),
        instruction(0x404, 'MOVE.L', '(A5)|D0'),
        instruction(0x406, 'BEQ.B', '0x418', flows=(0x418,), flow='CONDITIONAL_JUMP'),
        instruction(0x408, 'MOVEA.L', 'D0|A5'),
        instruction(0x40a, 'TST.B', '(0x8,A5)', length=4),
        instruction(0x40e, 'BNE.B', '0x404', flows=(0x404,), flow='CONDITIONAL_JUMP'),
        instruction(0x410, 'MOVE.L', '(0x4,A5)|-(SP)', length=4),
        instruction(0x414, 'RTS', flow='TERMINATOR'),
        instruction(0x418, 'RTS', flow='TERMINATOR'),
    ]
    return parse_megadrive(bytes(data)), {f.cpu_address: f for f in items}


class LinkedObjectCallbackTests(unittest.TestCase):
    def candidates(self, facts, execution=None):
        image, _ = fixture()
        return discover_object_field_handler_candidates(image, facts,
                    execution_facts=facts if execution is None else execution)

    def test_allocator_and_executor_share_linked_list_despite_different_registers(self):
        image, facts = fixture()
        result = self.candidates(facts)
        self.assertEqual([0x800], [c.address for c in result])
        self.assertIn('RAM list FFA000', result[0].evidence)
        self.assertEqual('proven', result[0].confidence)
        self.assertNotIn(0x800, facts)  # No backend boundary or terminal is required.
        self.assertEqual((), discover_object_field_handler_candidates(image, facts))

    def test_same_field_of_another_list_is_not_code_evidence(self):
        _, facts = fixture()
        facts[0x308] = replace(facts[0x308], operands='(-0x5000).w|A1')
        self.assertEqual((), self.candidates(facts))

    def test_unrooted_allocator_executor_or_writer_does_not_prove_callback(self):
        _, facts = fixture()
        for omitted in (0x206, 0x280, 0x304, 0x31e, 0x400, 0x410, 0x414):
            with self.subTest(omitted=hex(omitted)):
                execution = {a: f for a, f in facts.items() if a != omitted}
                self.assertEqual((), self.candidates(facts, execution))

    def test_all_return_paths_must_insert_object(self):
        _, facts = fixture()
        facts[0x310] = replace(facts[0x310], flows=(0x320,))
        self.assertEqual((), self.candidates(facts))

    def test_next_link_must_be_copied_before_insertion(self):
        _, facts = fixture()
        facts[0x31c] = instruction(0x31c, 'NOP')
        self.assertEqual((), self.candidates(facts))

    def test_uses_actual_return_register_not_same_offset_in_unrelated_struct(self):
        _, facts = fixture()
        facts[0x206] = replace(facts[0x206], operands='#0x800|(0x4,A2)')
        self.assertEqual((), self.candidates(facts))

    def test_return_register_clobber_and_restore_are_not_ignored(self):
        _, original = fixture()
        for changed in (
            instruction(0x320, 'MOVEA.L', '#0xffb000|A0', length=4),
            instruction(0x320, 'EXG', 'A0|A2', length=4),
            instruction(0x320, 'MOVEM.L', '(SP)+|{ D4 D5 A0}', length=4),
        ):
            with self.subTest(changed=changed.mnemonic):
                facts = dict(original)
                facts[0x320] = changed
                self.assertEqual((), self.candidates(facts))

    def test_executor_base_cannot_be_overwritten_or_postincremented(self):
        _, original = fixture()
        for changed in (
            instruction(0x40a, 'MOVEA.L', '#0xffb000|A5', length=4),
            instruction(0x40a, 'MOVE.L', '(A5)+|D2', length=4),
            instruction(0x40a, 'EXG', 'A5|A2', length=4),
            instruction(0x40a, 'MOVEM.L', '(SP)+|{ A5}', length=4),
        ):
            with self.subTest(changed=changed.mnemonic):
                facts = dict(original)
                facts[0x40a] = changed
                self.assertEqual((), self.candidates(facts))

    def test_other_field_and_non_ram_list_head_are_rejected(self):
        _, original = fixture()
        for address, operand in ((0x206, '#0x800|(0x8,A0)'),
                                  (0x308, '(0x1000).l|A1'),
                                  (0x400, '(0x1000).l|A5')):
            with self.subTest(address=hex(address)):
                facts = dict(original)
                facts[address] = replace(facts[address], operands=operand)
                self.assertEqual((), self.candidates(facts))

    def test_unknown_callee_inside_allocator_is_not_assumed_to_preserve_pointers(self):
        _, facts = fixture()
        facts[0x316] = instruction(0x316, 'JSR', '0x600', length=4,
                                  flows=(0x600,), flow='UNCONDITIONAL_CALL')
        self.assertEqual((), self.candidates(facts))

    def test_target_with_explicit_data_reader_or_instruction_interior_is_rejected(self):
        _, original = fixture()
        read = replace(instruction(0x600, 'MOVE.W', '(0x800).l|D0w', length=6),
                       references=(InstructionReference(0x800, 'READ', 0),))
        for extra in (read, instruction(0x7fe, 'MOVE.L', '#0x30000|D0', length=6)):
            with self.subTest(extra=hex(extra.cpu_address)):
                facts = dict(original)
                facts[extra.cpu_address] = extra
                self.assertEqual((), self.candidates(facts))

    def test_rewriting_new_link_cancels_copied_next_proof(self):
        _, facts = fixture()
        facts[0x31e] = instruction(0x31e, 'CLR.L', '(A0)')
        facts[0x320] = instruction(0x320, 'MOVE.L', 'A0|(A1)')
        facts[0x322] = instruction(0x322, 'MOVEM.L', '(SP)+|{ D4 D5 A1}', length=4)
        facts[0x326] = instruction(0x326, 'RTS', flow='TERMINATOR')
        self.assertEqual((), self.candidates(facts))

    def test_store_after_insertion_could_unlink_object(self):
        _, facts = fixture()
        facts[0x320] = instruction(0x320, 'CLR.L', '(A1)')
        facts[0x322] = instruction(0x322, 'MOVEM.L', '(SP)+|{ D4 D5 A1}', length=4)
        facts[0x326] = instruction(0x326, 'RTS', flow='TERMINATOR')
        self.assertEqual((), self.candidates(facts))

    def test_clobbering_ram_head_detaches_saved_predecessor(self):
        _, original = fixture()
        for replacement in (
            instruction(0x30a, 'CLR.L', '(-0x6000).w', length=4),
            instruction(0x30a, 'CLR.W', '(-0x5ffe).w', length=4),
            instruction(0x30a, 'CLR.L', '(A1)', length=4),
        ):
            facts = {a: f for a, f in original.items() if not 0x300 <= a < 0x400}
            for item in [
                instruction(0x300, 'MOVEA.L', '(0xffff9000).w|A0', length=4),
                instruction(0x304, 'LEA', '(-0x6000).w|A1', length=4),
                instruction(0x308, 'MOVEA.L', '(A1)|A1'), replacement,
                instruction(0x30e, 'MOVE.L', '(A1)|(A0)'),
                instruction(0x310, 'MOVE.L', 'A0|(A1)'),
                instruction(0x312, 'RTS', flow='TERMINATOR'),
            ]:
                facts[item.cpu_address] = item
            with self.subTest(operand=replacement.operands):
                self.assertEqual((), self.candidates(facts))

    def test_dbcc_changes_register_used_as_node_pointer(self):
        _, original = fixture()
        facts = {a: f for a, f in original.items() if not 0x300 <= a < 0x400}
        for item in [
            instruction(0x300, 'MOVEA.L', '(0xffff9000).w|A0', length=4),
            instruction(0x304, 'LEA', '(-0x6000).w|A1', length=4),
            instruction(0x308, 'MOVE.L', '(A1)|D4'),
            instruction(0x30a, 'DBF', 'D4w|0x30e', length=4,
                        flows=(0x30e,), flow='CONDITIONAL_JUMP'),
            instruction(0x30e, 'MOVEA.L', 'D4|A1'),
            instruction(0x310, 'MOVE.L', '(A1)|(A0)'),
            instruction(0x312, 'MOVE.L', 'A0|(A1)'),
            instruction(0x314, 'RTS', flow='TERMINATOR'),
        ]:
            facts[item.cpu_address] = item
        self.assertEqual((), self.candidates(facts))

    def test_comparison_address_updates_invalidate_list_provenance(self):
        _, original = fixture()
        for mnemonic, operands in (('TST.B', '(A5)+'), ('CMP.W', '(A5)+|D0w'),
                                     ('BTST', '#0x1|-(A5)')):
            facts = dict(original)
            facts[0x40a] = instruction(0x40a, mnemonic, operands, length=4)
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual((), self.candidates(facts))

    def test_implicit_stack_operations_cannot_change_allocator_return(self):
        _, original = fixture()
        for mnemonic, operands in (('PEA', '(0x600).l'), ('LINK', 'A6|#-0x4'),
                                     ('UNLK', 'A6')):
            facts = dict(original)
            facts[0x324] = instruction(0x324, mnemonic, operands, length=4)
            facts[0x328] = instruction(0x328, 'RTS', flow='TERMINATOR')
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual((), self.candidates(facts))

    def test_link_cannot_preserve_executor_address_register(self):
        _, facts = fixture()
        facts[0x40a] = instruction(0x40a, 'LINK', 'A5|#-0x4', length=4)
        self.assertEqual((), self.candidates(facts))

    def test_store_must_immediately_follow_allocator(self):
        _, facts = fixture()
        facts[0x206] = instruction(0x206, 'MOVEA.L', '#0xffb000|A0')
        facts[0x208] = instruction(0x208, 'MOVE.L', '#0x800|(0x4,A0)', length=8)
        self.assertEqual((), self.candidates(facts))


if __name__ == '__main__':
    unittest.main()
