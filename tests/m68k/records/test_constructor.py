from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.records.constructor import (
    discover_constructor_record_tables as discover,
    discover_constructor_record_seeds,
    _preserved_registers as preserved_registers,
    _nonzero_immediate_word_division,
    _unsupported_frame_or_exception,
)
from megadrive.builders import fact
from megadrive.builders import cartridge
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.facts import InstructionReference
from m68k.records.builders import fixture, instruction


class ConstructorRecordTests(unittest.TestCase):

    def find(self, facts=None, image=None, rooted=None):
        original_image, original = fixture()
        facts = original if facts is None else facts
        return discover(original_image if image is None else image, facts, execution_facts=facts if rooted is None else rooted)

    def test_count_stride_and_targets_come_from_consumer(self):
        found = self.find()
        self.assertEqual(1, len(found))
        proof = found[0]
        self.assertEqual((3, 12, 0), (proof.count, proof.stride, proof.field))
        self.assertEqual((0x800, 0x900, 0xa00), proof.targets)
        self.assertEqual((0x380,), proof.callback_stores)
        self.assertEqual((0xffe000, 64, 64), proof.pool)

    def test_nested_callee_movem_preserves_counter_and_cursor(self):
        _, facts = fixture()
        self.assertEqual({'d0', 'a2'}, preserved_registers(facts, 0x300, {'d0', 'a2'}))

    def test_rooted_consumer_allocator_and_executor_required(self):
        image, facts = fixture()
        self.assertEqual((), discover(image, facts))
        for omitted in (0x20a, 0x20c, 0x350, 0x380, 0x38a, 0x412, 0x416):
            with self.subTest(omitted=hex(omitted)):
                self.assertEqual((), self.find(facts, rooted={a: f for a, f in facts.items() if a != omitted}))

    def test_cursor_clobber_on_any_callee_return_rejects(self):
        _, facts = fixture()
        facts[0x38a] = instruction(0x38a, 'BNE.W', '0x390', length=4, flows=(0x390,), flow='CONDITIONAL_JUMP')
        facts[0x38e] = instruction(0x38e, 'RTS', flow='TERMINATOR')
        facts[0x390] = instruction(0x390, 'MOVEA.L', '#0x500|A2', length=6)
        facts[0x396] = instruction(0x396, 'RTS', flow='TERMINATOR')
        self.assertEqual((), self.find(facts))

    def test_postincrement_and_dbcc_clobbers_are_not_skipped(self):
        _, original = fixture()
        for changed in (instruction(0x38a, 'TST.B', '(A2)+', length=4), instruction(0x38a, 'CMP.W', '(A2)+|D1w', length=4), instruction(0x38a, 'DBF', 'D0w|0x38e', length=4, flows=(0x38e,), flow='CONDITIONAL_JUMP')):
            facts = dict(original)
            facts[0x38a] = changed
            facts[0x38e] = instruction(0x38e, 'RTS', flow='TERMINATOR')
            with self.subTest(changed=changed.mnemonic):
                self.assertEqual((), self.find(facts))

    def test_saved_register_mask_and_implicit_stack_operations_are_checked(self):
        _, original = fixture()
        mutations = [(0x386, instruction(0x386, 'MOVEM.L', '(SP)+|{ D1 A0}', length=4))]
        mutations += [(0x38a, instruction(0x38a, op, args, length=4)) for op, args in [('PEA', '(0x600).l'), ('LINK', 'A6|#-0x4'), ('UNLK', 'A6')]]
        for addr, changed in mutations:
            facts = dict(original)
            facts[addr] = changed
            facts[0x38e] = instruction(0x38e, 'RTS', flow='TERMINATOR')
            with self.subTest(changed=changed.mnemonic):
                self.assertEqual((), self.find(facts))

    def test_unresolved_call_cannot_preserve_loop_state(self):
        _, facts = fixture()
        facts[0x300] = replace(facts[0x300], flows=(0x700,))
        self.assertEqual((), self.find(facts))

    def test_counter_must_be_fixed_and_unmodified_through_loop(self):
        _, original = fixture()
        for addr, changed in [(0x206, instruction(0x206, 'MOVE.W', '(0xffff9000).w|D0w', length=4)), (0x216, instruction(0x216, 'ADDQ.W', '#0x1|D0w', length=4))]:
            facts = dict(original)
            facts[addr] = changed
            self.assertEqual((), self.find(facts))

    def test_all_paths_to_back_edge_need_same_stride(self):
        _, facts = fixture()
        facts[0x212] = replace(facts[0x212], flows=(0x222,))
        self.assertEqual((), self.find(facts))

    def test_table_cursor_cannot_escape_or_be_written_through(self):
        _, original = fixture()
        for changed in (instruction(0x216, 'MOVEA.L', 'A2|A3', length=4), instruction(0x216, 'MOVE.L', 'D1|(A2)+', length=4), instruction(0x216, 'LEA', '(0x4,A2)|A2', length=4)):
            facts = dict(original)
            facts[0x216] = changed
            self.assertEqual((), self.find(facts))

    def test_additional_constructor_call_requires_its_own_proof(self):
        _, facts = fixture()
        facts[0x216] = instruction(0x216, 'JSR', '0x300', length=4, flows=(0x300,), flow='UNCONDITIONAL_CALL')
        self.assertEqual((), self.find(facts))

    def test_invalid_target_or_overlapping_instruction_is_rejected(self):
        image, original = fixture()
        for target in (0, 0x801, 0xffe000, 0x500):
            data = bytearray(image.data)
            data[0x500:0x504] = target.to_bytes(4, 'big')
            with self.subTest(target=hex(target)):
                self.assertEqual((), self.find(image=parse_megadrive(bytes(data))))
        facts = dict(original)
        facts[0x7fe] = instruction(0x7fe, 'MOVE.L', '#0x30000|D0', length=6)
        self.assertEqual((), self.find(facts))

    def test_explicit_data_reader_blocks_callback_target(self):
        _, facts = fixture()
        facts[0x600] = replace(instruction(0x600, 'MOVE.W', '(0x800).l|D0w', length=6), references=(InstructionReference(0x800, 'READ', 0),))
        self.assertEqual((), self.find(facts))

    def test_same_offset_in_different_ram_pool_does_not_match(self):
        _, facts = fixture()
        facts[0x354] = replace(facts[0x354], operands='(0xffd000).l|A0')
        self.assertEqual((), self.find(facts))

    def test_same_pool_head_but_different_stride_or_count_does_not_match(self):
        _, original = fixture()
        for address, operands in ((0x366, '#0x20|A0'), (0x35a, '#0x1f|D0w')):
            facts = dict(original)
            facts[address] = replace(facts[address], operands=operands)
            with self.subTest(address=hex(address)):
                self.assertEqual((), self.find(facts))

    def test_pool_base_clobber_or_read_offset_change_does_not_match(self):
        _, original = fixture()
        for changed in (instruction(0x35e, 'MOVEA.L', '#0xffd000|A0', length=4), instruction(0x35e, 'TST.B', '(A0)+', length=4)):
            facts = dict(original)
            facts[0x35e] = changed
            self.assertEqual((), self.find(facts))
        facts = dict(original)
        facts[0x412] = replace(facts[0x412], operands='(0x6,A0)|A1')
        self.assertEqual((), self.find(facts))

    def test_callback_parameter_must_reach_store_without_clobber(self):
        _, original = fixture()
        for changed in (instruction(0x35e, 'EXG', 'A1|D7', length=4), instruction(0x35e, 'TST.B', '(A1)+', length=4), instruction(0x35e, 'MOVE.L', '(A1)+|D7', length=4), instruction(0x35e, 'LINK', 'A1|#-0x4', length=4)):
            facts = dict(original)
            facts[0x35e] = changed
            with self.subTest(changed=changed.mnemonic):
                self.assertEqual((), self.find(facts))

    def test_ccr_only_immediate_sr_masks_preserve_constructor_proof(self):
        _, original = fixture()
        for opcode, operands in (
            ('ORI', '#0x1|SR'), ('EORI', '#0x10|SR'),
            ('ANDI', '#-0x2|SR'), ('ANDI', '#0xffe0|SR'),
        ):
            for address in (0x35e, 0x38a, 0x40a, 0x216):
                facts = dict(original)
                facts[address] = instruction(address, opcode, operands, length=4)
                if address == 0x38a:
                    facts[0x38e] = instruction(0x38e, 'RTS', flow='TERMINATOR')
                with self.subTest(opcode=opcode, operands=operands, address=hex(address)):
                    self.assertEqual(1, len(self.find(facts)))

    def test_exceptions_or_stack_bank_changes_block_each_proof_walk(self):
        image, original = fixture()
        from retrolarium_disassembler.m68k.records.constructor import (
            _callback_parameter_stores, _fixed_pool_at,
        )
        for opcode, operands in (
            ('MOVE', '#0x0|SR'), ('ORI', '#0x2000|SR'),
            ('EORI', '#0x8000|SR'), ('ANDI', '#0xdfff|SR'),
            ('MOVE', 'A0|USP'), ('MOVE', 'USP|A0'),
            ('DIVU.W', '#0x0|D7'), ('DIVS.W', '#0x0|D7'),
            ('CHK.W', '#0x0|D7w'),
        ):
            for address in (0x35e, 0x38a, 0x40a, 0x216):
                facts = dict(original)
                facts[address] = instruction(address, opcode, operands, length=4)
                if address == 0x38a:
                    facts[0x38e] = instruction(0x38e, 'RTS', flow='TERMINATOR')
                with self.subTest(opcode=opcode, operands=operands, address=hex(address)):
                    self.assertEqual((), discover_constructor_record_seeds(
                        image, facts, execution_facts=facts))
                    if address == 0x35e:
                        self.assertEqual(set(), _callback_parameter_stores(facts, 0x300, 'A1', {2}))
                        self.assertEqual(set(), _fixed_pool_at(image, facts, 0x380, 'a0'))
                    elif address == 0x40a:
                        self.assertEqual(set(), _fixed_pool_at(image, facts, 0x412, 'a0'))
                    elif address == 0x38a:
                        self.assertIsNone(preserved_registers(facts, 0x300, {'a2', 'd0'}))

    def test_decoder_seeds_include_pool_and_allocator_provenance(self):
        image, facts = fixture()
        seeds = discover_constructor_record_seeds(image, facts, execution_facts=facts)
        self.assertEqual([0x800, 0x900, 0xa00], [seed.address for seed in seeds])
        for seed in seeds:
            self.assertEqual('constructor_record_callback', seed.kind)
            self.assertEqual('proven', seed.confidence)
            self.assertEqual(0x20a, seed.source_address)
            self.assertIn('3 records, stride 12', seed.evidence)
            self.assertIn('RAM pool FFE000, 64 slots, stride 64', seed.evidence)
            self.assertIn('callback field +2', seed.evidence)
            self.assertIn('indirect executor 000416', seed.evidence)
            self.assertIn('stored at 000380', seed.evidence)
        self.assertEqual((), discover_constructor_record_seeds(image, facts))


class ImmediateWordDivisionTests(unittest.TestCase):
    def division(self, address=0x200, *, signed=False, register=1, divisor=8):
        opcode = (0x81fc if signed else 0x80fc) | register << 9
        return replace(instruction(address, 'DIVS.W' if signed else 'DIVU.W',
                                   f'#0x{divisor:x}|D{register}', length=4),
                       raw=opcode.to_bytes(2, 'big') + divisor.to_bytes(2, 'big'))

    def test_nonzero_immediate_word_division_is_nonexceptional_for_each_destination(self):
        for signed in (False, True):
            for register in range(8):
                for divisor in (1, 8, 0x7fff, 0x8000, 0xffff):
                    item = self.division(signed=signed, register=register, divisor=divisor)
                    with self.subTest(signed=signed, register=register, divisor=divisor):
                        self.assertTrue(_nonzero_immediate_word_division(item))
                        self.assertFalse(_unsupported_frame_or_exception(item))
        negative = replace(self.division(signed=True, divisor=0xffff), operands='#-0x1|D1')
        self.assertTrue(_nonzero_immediate_word_division(negative))

    def test_zero_variable_extended_or_mismatched_encoding_remains_exceptional(self):
        item = self.division()
        variants = (
            self.division(divisor=0), self.division(signed=True, divisor=0),
            replace(item, raw=bytes.fromhex('82fc0000')),  # Text must not hide a zero divisor.
            replace(item, operands='#0x0|D1'),
            replace(item, operands='#0x9|D1'),
            replace(item, operands='#0x10008|D1'),
            replace(item, operands='#0x8|D0'),  # Preservation must clobber the encoded D1.
            replace(item, operands='D0w|D1'),
            replace(item, raw=bytes.fromhex('82c0'), length=2, operands='D0w|D1'),
            replace(item, raw=bytes.fromhex('82d0'), length=2, operands='(A0)|D1'),
            replace(item, raw=bytes.fromhex('82d00008')),
            replace(item, mnemonic='DIVS.W'),
            replace(item, mnemonic='DIVU.L'),
            replace(item, mnemonic='DIVUL.L'),
            replace(item, mnemonic='DIVSL.L'),
            replace(item, raw=bytes.fromhex('82fc00080000'), length=6),
            replace(item, raw=bytes.fromhex('82fc')),
            replace(item, length=2),
        )
        for changed in variants:
            with self.subTest(raw=changed.raw.hex(), mnemonic=changed.mnemonic, operands=changed.operands):
                self.assertFalse(_nonzero_immediate_word_division(changed))
                self.assertTrue(_unsupported_frame_or_exception(changed))

    def test_destination_is_clobbered_but_unrelated_registers_and_balanced_saves_survive(self):
        for signed in (False, True):
            operation = self.division(signed=signed)
            facts = {0x200: operation, 0x204: instruction(0x204, 'RTS', flow='TERMINATOR')}
            self.assertEqual(frozenset({'a0', 'a1', 'd0'}),
                             preserved_registers(facts, 0x200, {'a0', 'a1', 'd0', 'd1'}))
            # Even when quotient overflow is possible, D1 is not assumed to
            # retain its input. An explicit balanced save can preserve it.
            saved = {
                0x200: instruction(0x200, 'MOVEM.L', 'D1|-(SP)', length=4),
                0x204: self.division(0x204, signed=signed),
                0x208: instruction(0x208, 'MOVEM.L', '(SP)+|D1', length=4),
                0x20c: instruction(0x20c, 'RTS', flow='TERMINATOR'),
            }
            self.assertEqual(frozenset({'a0', 'd1'}), preserved_registers(saved, 0x200, {'a0', 'd1'}))
            facts[0x200] = replace(operation, raw=operation.raw[:2] + b'\x00\x00')
            self.assertIsNone(preserved_registers(facts, 0x200, {'a0', 'd1'}))

    def test_valid_immediate_division_can_be_crossed_by_each_constructor_walk(self):
        image, original = fixture()
        for address in (0x35e, 0x38a, 0x40a, 0x216):
            facts = dict(original)
            facts[address] = self.division(address, register=7)
            if address == 0x38a:
                facts[0x38e] = instruction(0x38e, 'RTS', flow='TERMINATOR')
            with self.subTest(address=hex(address)):
                self.assertEqual(3, len(discover_constructor_record_seeds(image, facts, execution_facts=facts)))

if __name__ == '__main__':
    unittest.main()
