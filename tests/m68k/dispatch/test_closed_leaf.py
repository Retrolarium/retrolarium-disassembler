from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.dispatch.closure import (
    _strong_closed_leaf,
    make_dispatch_closure_validator,
)
from retrolarium_disassembler.m68k.dispatch.witness import make_dispatch_handler_validator
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.emit import _asm_instruction
from megadrive.builders import cartridge
from m68k.builders import instruction


def closed_leaf():
    """A complete, balanced function with two exits and no known-code edges."""
    body = {}
    address = 0x300

    def emit(raw, mnemonic, operands='', flow='FALL_THROUGH', flows=()):
        nonlocal address
        fact = instruction(address, raw, mnemonic, operands, flow, flows)
        body[address] = fact
        address += fact.length
        return fact.cpu_address

    emit('48e7c0c0', 'MOVEM.L', '{ A1 A0 D1 D0}|-(SP)')
    emit('7000', 'MOVEQ', '#0x0|D0')
    emit('7201', 'MOVEQ', '#0x1|D1')
    emit('34280002', 'MOVE.W', '(0x2,A0)|D2w')
    emit('0c420003', 'CMPI.W', '#0x3|D2w')
    branch = emit('66000000', 'BNE.W', '0x0', 'CONDITIONAL_JUMP', (0,))
    for row in (
        ('52680004', 'ADDQ.W', '0x1|(0x4,A0)'),
        ('53680006', 'SUBQ.W', '0x1|(0x6,A0)'),
        ('4a680008', 'TST.W', '(0x8,A0)'),
        ('0242000f', 'ANDI.W', '#0xf|D2w'),
        ('00420010', 'ORI.W', '#0x10|D2w'),
        ('0a420020', 'EORI.W', '#0x20|D2w'),
        ('08e80001000a', 'BSET.B', '#0x1|(0xa,A0)'),
        ('08a80002000b', 'BCLR.B', '#0x2|(0xb,A0)'),
        ('d442', 'ADD.W', 'D2w|D2w'),
        ('e24a', 'LSR.W', '#0x1|D2w'),
        ('3142000c', 'MOVE.W', 'D2w|(0xc,A0)'),
        ('4a68000e', 'TST.W', '(0xe,A0)'),
        ('42680010', 'CLR.W', '(0x10,A0)'),
        ('4442', 'NEG.W', 'D2w'),
        ('4642', 'NOT.W', 'D2w'),
        ('4842', 'SWAP', 'D2'),
        ('4a42', 'TST.W', 'D2w'),
        ('06420004', 'ADDI.W', '#0x4|D2w'),
        ('04420002', 'SUBI.W', '#0x2|D2w'),
    ):
        emit(*row)
    emit('4cdf0303', 'MOVEM.L', '(SP)+|{ D0 D1 A0 A1}')
    emit('4e75', 'RTS', flow='TERMINATOR')
    other = address
    emit('4cdf0303', 'MOVEM.L', '(SP)+|{ D0 D1 A0 A1}')
    emit('4e75', 'RTS', flow='TERMINATOR')
    body[branch] = instruction(
        branch, f'6600{other - branch - 2:04x}', 'BNE.W', f'0x{other:x}',
        'CONDITIONAL_JUMP', (other,))
    return body


def validation_results(body, protected=(), *, origin=0, entry=0x300):
    data = bytearray(cartridge(size=0x900))
    data[0x200:] = b'\xff' * (len(data) - 0x200)
    known = {
        0x2ee: instruction(0x2ee, '4e75', 'RTS', flow='TERMINATOR'),
        0x800: instruction(0x800, '4e75', 'RTS', flow='TERMINATOR'),
    }
    for fact in (*known.values(), *body.values()):
        data[fact.cpu_address:fact.cpu_address + len(fact.raw)] = fact.raw
    image = parse_megadrive(bytes(data))
    if origin:
        image = replace(image, header=replace(
            image.header, rom_start=origin, rom_end=origin + len(data) - 1))

        def shift(facts):
            return {a + origin: replace(
                fact, cpu_address=a + origin,
                flows=tuple(target + origin for target in fact.flows),
                operands=(f'0x{fact.flows[0] + origin:x}'
                          if fact.flow_type == 'CONDITIONAL_JUMP' else fact.operands),
            ) for a, fact in facts.items()}

        known, body = shift(known), shift(body)
    arguments = dict(render_instruction=_asm_instruction)
    logical_protected = tuple((origin + start, origin + end) for start, end in protected)
    decoded = {**known, **body}
    default = make_dispatch_closure_validator(
        image, known, decoded, protected_ranges=logical_protected, **arguments)
    optional = make_dispatch_closure_validator(
        image, known, decoded, protected_ranges=logical_protected,
        allow_closed_leaves=True, **arguments)
    public = make_dispatch_handler_validator(
        image, known, decoded, protected_ranges=protected, **arguments)
    return tuple(validator(origin + entry) for validator in (default, optional, public))


class ClosedLeafDispatchTests(unittest.TestCase):
    def test_default_stays_strict_and_only_opt_in_accepts_independent_leaf(self):
        self.assertEqual((False, True, True), validation_results(closed_leaf()))

    def test_new_competitor_does_not_revoke_existing_rooted_witness(self):
        body = closed_leaf()
        # The long immediate at $2FE embeds the independent leaf's MOVEM at
        # $300. Both interpretations balance their stack. The earlier entry
        # has a rooted call, so its existing acceptance must stay unchanged.
        body[0x2f4] = instruction(0x2f4, '48e7c0c0', 'MOVEM.L', '{ A1 A0 D1 D0}|-(SP)')
        body[0x2f8] = instruction(
            0x2f8, '4eb900000800', 'JSR', '0x800.l', 'UNCONDITIONAL_CALL', (0x800,))
        body[0x2fe] = instruction(0x2fe, '203c48e7c0c0', 'MOVE.L', '#0x48e7c0c0|D0')
        self.assertEqual((True, False, True), validation_results(body, entry=0x2f4))

    def test_nonzero_origin_and_physical_protection_contract(self):
        self.assertEqual((False, True, True), validation_results(closed_leaf(), origin=0x200000))
        self.assertEqual(
            (False, False, False),
            validation_results(closed_leaf(), ((0x320, 0x322),), origin=0x200000))

    def test_small_accidental_leaf_still_rejected(self):
        body = {address: instruction(address, raw, mnemonic, operands, flow)
                for address, raw, mnemonic, operands, flow in (
                    (0x300, '7001', 'MOVEQ', '#0x1|D0', 'FALL_THROUGH'),
                    (0x302, '4a40', 'TST.W', 'D0w', 'FALL_THROUGH'),
                    (0x304, '5240', 'ADDQ.W', '0x1|D0w', 'FALL_THROUGH'),
                    (0x306, '4e75', 'RTS', '', 'TERMINATOR'),
                )}
        self.assertEqual((False, False, False), validation_results(body))

    def test_trap_computed_call_stack_alias_and_sr_switch_still_rejected(self):
        for row in (
            ('4e40', 'TRAP', '0x0', 'FALL_THROUGH'),
            ('4e91', 'JSR', '(A1)', 'COMPUTED_CALL'),
            ('244f', 'MOVEA.L', 'SP|A2', 'FALL_THROUGH'),
        ):
            with self.subTest(row=row):
                body = closed_leaf()
                body[0x304] = instruction(0x304, *row)
                self.assertEqual((False, False, False), validation_results(body))
        body = closed_leaf()
        body[0x308] = instruction(0x308, '46fc0000', 'MOVE', '#0x0|SR')
        self.assertEqual((False, False, False), validation_results(body))

    def test_unbalanced_movem_still_rejected(self):
        body = closed_leaf()
        restore = next(a for a, fact in body.items() if fact.operands.startswith('(SP)+'))
        body[restore] = instruction(restore, '4cdf0003', 'MOVEM.L', '(SP)+|{ D0 D1}')
        self.assertEqual((False, False, False), validation_results(body))

    def test_raw_call_cannot_be_hidden_by_flow_or_mnemonic_metadata(self):
        for raw in ('4e91', '6100'):
            with self.subTest(raw=raw):
                body = closed_leaf()
                body[0x304] = replace(body[0x304], raw=bytes.fromhex(raw), mnemonic='NOP', operands='')
                self.assertFalse(_strong_closed_leaf(body))

    def test_branch_to_its_fallthrough_is_not_a_two_way_witness(self):
        body = closed_leaf()
        branch = next(a for a, fact in body.items() if fact.flow_type == 'CONDITIONAL_JUMP')
        body[branch] = replace(body[branch], flows=(branch + body[branch].length,))
        self.assertFalse(_strong_closed_leaf(body))

    def test_external_successor_cannot_supply_closed_leaf_witness(self):
        for flow, mnemonic, raw in (
            ('UNCONDITIONAL_JUMP', 'BRA.B', '6010'),
            ('CONDITIONAL_JUMP', 'BNE.B', '6610'),
            ('UNCONDITIONAL_CALL', 'BSR.B', '6110'),
            ('FALL_THROUGH', 'NOP', '4e71'),
        ):
            with self.subTest(flow=flow):
                body = closed_leaf()
                body[0x304] = instruction(0x304, raw, mnemonic, '0x800', flow, (0x800,))
                self.assertFalse(_strong_closed_leaf(body))

    def test_protected_data_and_missing_decode_still_rejected(self):
        self.assertEqual(
            (False, False, False), validation_results(closed_leaf(), ((0x320, 0x322),)))
        body = closed_leaf()
        del body[0x304]
        self.assertEqual((False, False, False), validation_results(body))


if __name__ == '__main__':
    unittest.main()
