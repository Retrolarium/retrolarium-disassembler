from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))

from retrolarium_disassembler.m68k.records.cleared_pool_states import discover_cleared_pool_state_seeds
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.emit import _asm_instruction
from megadrive.builders import cartridge
from m68k.builders import instruction


class PoolFixture:
    """A complete, deliberately small allocator/executor lifecycle."""

    def __init__(self, producer_prefix=(), delete_prefix=(), zero_instruction=None):
        self.facts = {}
        self.hypotheses = {}
        self.at = 0
        zero_instruction = zero_instruction or ('7200', 'MOVEQ', '#0x0|D1')

        self.at = 0x200
        self.emit('43f900ff8000', 'LEA', '(0xff8000).l|A1')
        self.emit('7001', 'MOVEQ', '#0x1|D0')
        self.emit('4a51', 'TST.W', '(A1)')
        self.branch('67', 'BEQ.W', 0x216)
        self.emit('43e90010', 'LEA', '(0x10,A1)|A1')
        self.dbf('D0', 0x208)
        self.rts()

        self.at = 0x300
        for _ in range(4):
            self.emit('22c1', 'MOVE.L', 'D1|(A1)+')
        self.rts()
        self.at = 0x340
        self.emit('43f900ff8000', 'LEA', '(0xff8000).l|A1')
        self.emit(*zero_instruction)
        self.emit('7001', 'MOVEQ', '#0x1|D0')
        clear_call = self.at
        self.branch('61', 'BSR.W', 0x300)
        self.dbf('D0', clear_call)
        self.rts()
        self.at = 0x380
        self.emit('2248', 'MOVEA.L', 'A0|A1')
        self.emit(*zero_instruction)
        self.branch('60', 'BRA.W', 0x300)

        self.at = 0x400
        self.emit('41f900ff8000', 'LEA', '(0xff8000).l|A0')
        self.branch('61', 'BSR.W', 0x440)
        self.at = 0x440
        self.emit('7e01', 'MOVEQ', '#0x1|D7')
        self.emit('3010', 'MOVE.W', '(A0)|D0w')
        self.branch('67', 'BEQ.W', 0x454)
        self.emit('48e70180', 'MOVEM.L', '{ A0 D7}|-(SP)')
        self.branch('61', 'BSR.W', 0x500)
        self.emit('4cdf0180', 'MOVEM.L', '(SP)+|{ D7 A0}')
        self.emit('41e80010', 'LEA', '(0x10,A0)|A0')
        self.dbf('D7', 0x442)
        self.rts()
        self.at = 0x500
        self.emit('d040', 'ADD.W', 'D0w|D0w')
        self.emit('d040', 'ADD.W', 'D0w|D0w')
        self.emit('227b002a', 'MOVEA.L', '(0x530,PC,D0w*0x1)|A1')
        self.emit('4e91', 'JSR', '(A1)', 'COMPUTED_CALL')
        self.emit('082800040008', 'BTST.B', '#0x4|(0x8,A0)')
        self.branch('67', 'BEQ.W', 0x518)
        self.branch('61', 'BSR.W', 0x380)
        self.rts()

        self.at = 0x900
        self.branch('61', 'BSR.W', 0x200)
        failure = 0x908 + sum(len(bytes.fromhex(row[0])) for row in producer_prefix) + 6
        self.branch('66', 'BNE.W', failure)
        for row in producer_prefix:
            self.emit(*row)
        self.publisher = self.at
        self.emit('337c00010000', 'MOVE.W', '#0x1|(0x0,A1)')
        self.rts()

        self.at = 0x1000
        self.emit('43f900001020', 'LEA', '(0x1020).l|A1')
        self.emit('4ef900001100', 'JMP', '(0x1100).l', 'UNCONDITIONAL_JUMP', (0x1100,))
        self.at = 0x1040
        self.emit('7001', 'MOVEQ', '#0x1|D0', hypothesis=True)
        self.emit('4a40', 'TST.W', 'D0w', hypothesis=True)
        self.emit('5240', 'ADDQ.W', '0x1|D0w', hypothesis=True)
        self.emit('4e75', 'RTS', '', 'TERMINATOR', hypothesis=True)
        self.at = 0x1060
        self.emit('317c00000000', 'MOVE.W', '#0x0|(0x0,A0)')
        for row in delete_prefix:
            self.emit(*row)
        self.marker = self.at
        self.emit('08e800040008', 'BSET.B', '#0x4|(0x8,A0)')
        self.rts()
        self.at = 0x1100
        self.emit('30280002', 'MOVE.W', '(0x2,A0)|D0w')
        self.emit('d040', 'ADD.W', 'D0w|D0w')
        self.emit('d2f10000', 'ADDA.W', '(0x0,A1,D0w*0x1)|A1')
        self.emit('4ed1', 'JMP', '(A1)', 'COMPUTED_JUMP')

    def emit(self, raw, mnemonic, operands='', flow='FALL_THROUGH', flows=(), *, hypothesis=False):
        fact = instruction(self.at, raw, mnemonic, operands, flow, flows)
        (self.hypotheses if hypothesis else self.facts)[self.at] = fact
        self.at += fact.length

    def branch(self, opcode, mnemonic, target):
        displacement = (target - (self.at + 2)) & 0xffff
        flow = ('UNCONDITIONAL_CALL' if mnemonic.startswith('BSR') else
                'UNCONDITIONAL_JUMP' if mnemonic.startswith('BRA') else 'CONDITIONAL_JUMP')
        self.emit(opcode + '00' + f'{displacement:04x}', mnemonic, f'0x{target:x}', flow, (target,))

    def dbf(self, register, target):
        self.emit(f'{0x51c8 + int(register[1]):04x}{(target - self.at - 2) & 0xffff:04x}',
                  'DBF', register + f'w|0x{target:x}', 'CONDITIONAL_JUMP', (target,))

    def rts(self):
        self.emit('4e75', 'RTS', '', 'TERMINATOR')

    def discover(self, **kwargs):
        data = bytearray(cartridge(size=0x2000))
        data[0x200:] = b'\xff' * (len(data) - 0x200)
        data[0x534:0x538] = (0x1000).to_bytes(4, 'big')
        data[0x1020:0x1024] = bytes.fromhex('0020 0040')
        for fact in (*self.facts.values(), *self.hypotheses.values()):
            data[fact.cpu_address:fact.cpu_address + len(fact.raw)] = fact.raw
        return discover_cleared_pool_state_seeds(
            parse_megadrive(bytes(data)), self.facts, {**self.facts, **self.hypotheses},
            render_instruction=_asm_instruction, **kwargs)


class ClearedPoolStateTests(unittest.TestCase):
    def test_positive_slot_zero_without_outgoing_known_edge(self):
        seeds = PoolFixture().discover()
        self.assertEqual([0x1040], [seed.address for seed in seeds])
        self.assertEqual('high', seeds[0].confidence)
        self.assertIn('not whole-game reachability', seeds[0].evidence)

    def test_state_is_not_zero_after_constructor(self):
        fixture = PoolFixture(producer_prefix=[('337c00030002', 'MOVE.W', '#0x3|(0x2,A1)')])
        self.assertEqual((), fixture.discover())

    def test_explicit_state_reset_is_accepted(self):
        fixture = PoolFixture(producer_prefix=[
            ('337c00030002', 'MOVE.W', '#0x3|(0x2,A1)'),
            ('42690002', 'CLR.W', '(0x2,A1)'),
        ])
        self.assertEqual([0x1040], [seed.address for seed in fixture.discover()])

    def test_temporary_free_without_delete_mark_rejects_stale_state_reuse(self):
        fixture = PoolFixture()
        fixture.facts[fixture.marker] = instruction(fixture.marker, '4e75', 'RTS', flow='TERMINATOR')
        self.assertEqual((), fixture.discover())

    def test_unknown_call_between_free_and_clear_rejected(self):
        fixture = PoolFixture(delete_prefix=[('4eb900001800', 'JSR', '(0x1800).l', 'UNCONDITIONAL_CALL', (0x1800,))])
        self.assertEqual((), fixture.discover())

    def test_allocation_between_free_and_clear_rejected(self):
        fixture = PoolFixture(delete_prefix=[('4eb900000200', 'JSR', '(0x200).l', 'UNCONDITIONAL_CALL', (0x200,))])
        self.assertEqual((), fixture.discover())

    def test_unknown_call_before_publication_rejected(self):
        fixture = PoolFixture(producer_prefix=[('4eb900001800', 'JSR', '(0x1800).l', 'UNCONDITIONAL_CALL', (0x1800,))])
        self.assertEqual((), fixture.discover())

    def test_pointer_clobber_before_publication_rejected(self):
        fixture = PoolFixture(producer_prefix=[('43f900ff9000', 'LEA', '(0xff9000).l|A1')])
        self.assertEqual((), fixture.discover())

    def test_pointer_alias_before_publication_rejected(self):
        for row in [('2449', 'MOVEA.L', 'A1|A2'),
                    ('2049', 'MOVEA.L', 'A1l|A0'),
                    ('45e90002', 'LEA', '(0x2,A1)|A2')]:
            with self.subTest(row=row):
                self.assertEqual((), PoolFixture(producer_prefix=[row]).discover())

    def test_pointer_alias_after_free_rejected(self):
        fixture = PoolFixture(delete_prefix=[('43e80002', 'LEA', '(0x2,A0)|A1')])
        self.assertEqual((), fixture.discover())

    def test_foreign_executor_pool_rejected(self):
        fixture = PoolFixture()
        fixture.facts[0x400] = instruction(0x400, '41f900ff9000', 'LEA', '(0xff9000).l|A0')
        self.assertEqual((), fixture.discover())

    def test_executor_stride_mismatch_rejected(self):
        fixture = PoolFixture()
        fixture.facts[0x454] = instruction(0x454, '41e80020', 'LEA', '(0x20,A0)|A0')
        self.assertEqual((), fixture.discover())

    def test_incomplete_full_record_clear_rejected(self):
        fixture = PoolFixture()
        fixture.facts[0x306] = instruction(0x306, '4e75', 'RTS', flow='TERMINATOR')
        self.assertEqual((), fixture.discover())

    def test_word_zero_does_not_clear_high_half_of_longword(self):
        fixture = PoolFixture(zero_instruction=('323c0000', 'MOVE.W', '#0x0|D1w'))
        self.assertEqual((), fixture.discover())

    def test_long_zero_clears_full_record(self):
        fixture = PoolFixture(zero_instruction=('223c00000000', 'MOVE.L', '#0x0|D1'))
        self.assertEqual([0x1040], [seed.address for seed in fixture.discover()])

    def test_low_byte_free_needs_cleanup_even_with_nonzero_state(self):
        for raw, mnemonic, operands in [
            ('42280001', 'CLR.B', '(0x1,A0)'),
            ('117c00000001', 'MOVE.B', '#0x0|(0x1,A0)'),
        ]:
            with self.subTest(mnemonic=mnemonic):
                fixture = PoolFixture()
                item = instruction(0x1060, raw, mnemonic, operands)
                fixture.facts[0x1060] = item
                fixture.facts[0x1060 + item.length] = instruction(
                    0x1060 + item.length, '4e75', 'RTS', flow='TERMINATOR')
                self.assertEqual((), fixture.discover())

    def test_other_type_does_not_borrow_slot_zero_proof(self):
        fixture = PoolFixture()
        fixture.facts[fixture.publisher] = instruction(
            fixture.publisher, '337c00020000', 'MOVE.W', '#0x2|(0x0,A1)')
        self.assertEqual((), fixture.discover())

    def test_indexed_type_free_cannot_hide_from_lifecycle_scan(self):
        fixture = PoolFixture()
        fixture.facts[0x1060] = instruction(0x1060, '7200', 'MOVEQ', '#0x0|D1')
        fixture.facts[0x1062] = instruction(0x1062, '42701000', 'CLR.W', '(0x0,A0,D1w*0x1)')
        fixture.facts[0x1066] = instruction(0x1066, '4e75', 'RTS', flow='TERMINATOR')
        self.assertEqual((), fixture.discover())

    def test_straight_setup_metadata_cannot_invent_jump(self):
        fixture = PoolFixture()
        fixture.facts[0x206] = replace(fixture.facts[0x206], flow_type='CONDITIONAL_JUMP', flows=(0x900,))
        self.assertEqual((), fixture.discover())

    def test_type_dispatch_cannot_overwrite_record_pointer(self):
        fixture = PoolFixture()
        fixture.facts[0x504] = instruction(0x504, '207b002a', 'MOVEA.L', '(0x530,PC,D0w*0x1)|A0')
        fixture.facts[0x508] = instruction(0x508, '4e90', 'JSR', '(A0)', 'COMPUTED_CALL')
        self.assertEqual((), fixture.discover())

    def test_state_table_load_cannot_overwrite_record_pointer(self):
        fixture = PoolFixture()
        fixture.facts[0x1000] = instruction(0x1000, '41f900001020', 'LEA', '(0x1020).l|A0')
        fixture.facts[0x1106] = instruction(0x1106, 'd0f00000', 'ADDA.W', '(0x0,A0,D0w*0x1)|A0')
        fixture.facts[0x110A] = instruction(0x110A, '4ed0', 'JMP', '(A0)', 'COMPUTED_JUMP')
        self.assertEqual((), fixture.discover())

    def test_neighbor_record_free_does_not_borrow_current_delete_mark(self):
        fixture = PoolFixture(delete_prefix=[('317c00000010', 'MOVE.W', '#0x0|(0x10,A0)')])
        self.assertEqual((), fixture.discover())

    def test_absolute_neighbor_free_does_not_borrow_current_delete_mark(self):
        fixture = PoolFixture(delete_prefix=[('33fc000000ff8010', 'MOVE.W', '#0x0|(0xff8010).l')])
        self.assertEqual((), fixture.discover())

    def helper_delete_fixture(self, continuation):
        fixture = PoolFixture()
        for address in list(fixture.facts):
            if 0x1060 <= address < 0x1080:
                del fixture.facts[address]
        fixture.at = 0x1060
        fixture.branch('61', 'BSR.W', 0x1200)
        for row in continuation:
            fixture.emit(*row)
        fixture.rts()
        fixture.at = 0x1200
        fixture.emit('317c00000000', 'MOVE.W', '#0x0|(0x0,A0)')
        fixture.emit('08e800040008', 'BSET.B', '#0x4|(0x8,A0)')
        fixture.rts()
        return fixture

    def test_delete_helper_with_preserving_caller_continuation(self):
        fixture = self.helper_delete_fixture([('4e71', 'NOP')])
        self.assertEqual([0x1040], [seed.address for seed in fixture.discover()])

    def test_delete_helper_caller_cannot_allocate_before_executor_clear(self):
        fixture = self.helper_delete_fixture([
            ('4eb900000200', 'JSR', '(0x200).l', 'UNCONDITIONAL_CALL', (0x200,)),
        ])
        self.assertEqual((), fixture.discover())

    def test_delete_helper_caller_cannot_clobber_record(self):
        fixture = self.helper_delete_fixture([('41f900ff9000', 'LEA', '(0xff9000).l|A0')])
        self.assertEqual((), fixture.discover())

    def test_absolute_write_starting_before_pool_must_not_overlap_type(self):
        fixture = PoolFixture(delete_prefix=[('23fc0000000000ff7ffe', 'MOVE.L', '#0x0|(0xff7ffe).l')])
        self.assertEqual((), fixture.discover())

    def test_bad_physical_offset_and_length_rejected(self):
        for change in [dict(physical_offset=0x202), dict(length=3), dict(length=12)]:
            fixture = PoolFixture()
            fixture.facts[0x200] = replace(fixture.facts[0x200], **change)
            with self.subTest(change=change):
                self.assertEqual((), fixture.discover())

    def test_protected_or_incomplete_candidate_rejected(self):
        self.assertEqual((), PoolFixture().discover(protected_ranges=((0x1044, 0x1046),)))
        fixture = PoolFixture()
        del fixture.hypotheses[0x1044]
        self.assertEqual((), fixture.discover())


if __name__ == '__main__':
    unittest.main()
