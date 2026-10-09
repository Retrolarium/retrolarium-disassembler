from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.callbacks.relative_record import (
    discover_relative_record_callbacks as discover,
    discover_relative_record_callback_seeds,
)
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.facts import InstructionReference
from test_megadrive import cartridge
from test_m68k_unused import instruction


def fixture():
    instructions = [
        instruction(0x300, '7000', 'MOVEQ', '0x0|D0'),
        instruction(0x302, '10280028', 'MOVE.B', '(0x28,A0)|D0b'),
        instruction(0x306, '43f900000800', 'LEA', '(0x800).l|A1'),
        instruction(0x30C, 'd2f10000', 'ADDA.W', '(0x0,A1,D0w*0x1)|A1'),
        instruction(0x310, '2159003a', 'MOVE.L', '(A1)+|(0x3a,A0)'),
        instruction(0x314, '2459', 'MOVEA.L', '(A1)+|A2'),
        instruction(0x316, '1019', 'MOVE.B', '(A1)+|D0b'),
        instruction(0x318, '11400030', 'MOVE.B', 'D0b|(0x30,A0)'),
        instruction(0x31C, '1019', 'MOVE.B', '(A1)+|D0b'),
        instruction(0x31E, '11400031', 'MOVE.B', 'D0b|(0x31,A0)'),
        instruction(0x322, '1019', 'MOVE.B', '(A1)+|D0b'),
        instruction(0x324, '11400032', 'MOVE.B', 'D0b|(0x32,A0)'),
        instruction(0x328, '11590033', 'MOVE.B', '(A1)+|(0x33,A0)'),
        instruction(0x32C, '4e75', 'RTS', flow='TERMINATOR'),
        instruction(0x400, '2468003a', 'MOVEA.L', '(0x3a,A0)|A2'),
        instruction(0x404, '2648', 'MOVEA.L', 'A0|A3'),
        instruction(0x406, '30280034', 'MOVE.W', '(0x34,A0)|D0w'),
        instruction(0x40A, '41f8fb00', 'LEA', '(-0x500).w|A0'),
        instruction(0x40E, 'd0c0', 'ADDA.W', 'D0w|A0'),
        instruction(0x410, '43f8fb80', 'LEA', '(-0x480).w|A1'),
        instruction(0x414, 'd2c0', 'ADDA.W', 'D0w|A1'),
        instruction(0x416, '4e92', 'JSR', '(A2)', 'COMPUTED_CALL'),
        instruction(0x418, '4e75', 'RTS', flow='TERMINATOR'),
        instruction(0x600, '7000', 'MOVEQ', '0x0|D0'),
        instruction(0x602, '4e75', 'RTS', flow='TERMINATOR'),
        instruction(0x620, '7200', 'MOVEQ', '0x0|D1'),
        instruction(0x622, '4e75', 'RTS', flow='TERMINATOR'),
        instruction(0x640, '7400', 'MOVEQ', '0x0|D2'),
        instruction(0x642, '4e75', 'RTS', flow='TERMINATOR'),
    ]
    facts = {f.cpu_address: f for f in instructions}
    data = bytearray(cartridge(size=0x1000))
    for slot, target in enumerate((0x600, 0x620, 0x640)):
        offset = 6 + slot * 12
        data[0x800 + 2*slot:0x802 + 2*slot] = offset.to_bytes(2, 'big')
        data[0x800 + offset:0x804 + offset] = target.to_bytes(4, 'big')
        data[0x804 + offset:0x80C + offset] = bytes.fromhex('00000900000f0807')
    return data, facts


def image_for(data, facts):
    data = bytearray(data)
    for fact in facts.values():
        data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
    return parse_megadrive(bytes(data))


class RelativeRecordCallbackTests(unittest.TestCase):
    def run_model(self, data=None, facts=None, **kwargs):
        default_data, default_facts = fixture()
        data = default_data if data is None else data
        facts = default_facts if facts is None else facts
        trusted = {a: f for a, f in facts.items() if a < 0x620}
        return discover(image_for(data, facts), trusted, facts, **kwargs)

    def test_rooted_cursor_layout_and_preserved_delayed_executor(self):
        model, = self.run_model()
        self.assertEqual((0x310, 0x800, (0x806, 0x812, 0x81E), 12),
                         (model.producer, model.table, model.records, model.stride))
        self.assertEqual(('A0', 0x3A, 0x400, 0x416, (0x600, 0x620, 0x640)),
                         (model.object_register, model.field, model.reader, model.executor, model.targets))
        data, facts = fixture()
        seeds = discover_relative_record_callback_seeds(image_for(data, facts),
                    {a: f for a, f in facts.items() if a < 0x620}, facts)
        self.assertEqual([0x600, 0x620, 0x640], [s.address for s in seeds])
        self.assertTrue(all(s.confidence == 'high' and s.kind == 'relative_record_callback' for s in seeds))

    def test_no_unrooted_producer_or_consumer_inference(self):
        data, facts = fixture()
        for missing in (0x302, 0x30C, 0x314, 0x400, 0x410, 0x416):
            rooted = {a: f for a, f in facts.items() if a != missing and a < 0x620}
            self.assertEqual((), discover(image_for(data, facts), rooted, facts), hex(missing))

    def test_all_evidence_must_match_immutable_rom(self):
        data, facts = fixture()
        original = image_for(data, facts)
        rooted = {a: f for a, f in facts.items() if a < 0x620}
        for address in (0x300, 0x310, 0x328, 0x400, 0x416, 0x620):
            corrupt = bytearray(original.data)
            corrupt[address] ^= 1
            self.assertEqual((), discover(parse_megadrive(bytes(corrupt)), rooted, facts), hex(address))

    def test_callback_register_clobber_and_foreign_field_rejected(self):
        data, facts = fixture()
        for replacement in (
            instruction(0x404, '2448', 'MOVEA.L', 'A0|A2'),
            instruction(0x400, '24680038', 'MOVEA.L', '(0x38,A0)|A2'),
            instruction(0x400, '246c003a', 'MOVEA.L', '(0x3a,A4)|A2'),
            instruction(0x404, '4e90', 'JSR', '(A0)', 'COMPUTED_CALL'),
        ):
            self.assertEqual((), self.run_model(data, {**facts, replacement.cpu_address: replacement}))

    def test_cursor_clobber_call_and_callback_overwrite_rejected(self):
        data, facts = fixture()
        for replacement in (
            instruction(0x314, '224a', 'MOVEA.L', 'A2|A1'),
            instruction(0x314, '4e92', 'JSR', '(A2)', 'COMPUTED_CALL'),
            instruction(0x314, '2249', 'MOVEA.L', 'A1|A1'),
            instruction(0x324, '1140003a', 'MOVE.B', 'D0b|(0x3a,A0)'),
            instruction(0x324, '1140003b', 'MOVE.B', 'D0b|(0x3b,A0)'),
            instruction(0x314, '3449', 'MOVEA.W', 'A1w|A2'),
            instruction(0x324, '11800000', 'MOVE.B', 'D0b|(0x0,A0,D0w*0x1)'),
        ):
            self.assertEqual((), self.run_model(data, {**facts, replacement.cpu_address: replacement}))

    def test_direct_object_write_alias_at_field_zero_is_rejected(self):
        data, facts = fixture()
        facts[0x310] = instruction(0x310, '21590000', 'MOVE.L', '(A1)+|(0x0,A0)')
        facts[0x400] = instruction(0x400, '24680000', 'MOVEA.L', '(0x0,A0)|A2')
        facts[0x318] = instruction(0x318, '2080', 'MOVE.L', 'D0|(A0)')
        facts[0x31A] = instruction(0x31A, '4e71', 'NOP')
        self.assertEqual((), self.run_model(data, facts))

    def test_readonly_object_field_comparison_is_not_an_overwrite(self):
        data, facts = fixture()
        facts[0x318] = instruction(0x318, '4a68003a', 'TST.W', '(0x3a,A0)')
        self.assertEqual(1, len(self.run_model(data, facts)))

    def test_changed_cursor_read_width_changes_derived_stride(self):
        data, facts = fixture()
        records = [bytes(data[0x806 + i*12:0x812 + i*12]) for i in range(3)]
        for slot, record in enumerate(records):
            offset = 6 + slot * 10
            data[0x800+slot*2:0x802+slot*2] = offset.to_bytes(2, 'big')
            data[0x800+offset:0x80A+offset] = record[:10]
        facts[0x314] = instruction(0x314, '3459', 'MOVEA.W', '(A1)+|A2')
        self.assertEqual(10, self.run_model(data, facts)[0].stride)

    def test_physical_offsets_must_match_image_mapping(self):
        data, facts = fixture()
        image = image_for(data, facts)
        for address in (0x300, 0x310, 0x400, 0x620):
            changed = {**facts, address: replace(facts[address], physical_offset=address+2)}
            self.assertEqual((), discover(image, {a:f for a,f in changed.items() if a<0x620}, changed))

    def test_nonzero_cpu_origin_and_logical_protection(self):
        data, facts = fixture()
        origin = 0x100000
        for record in (0x806, 0x812, 0x81E):
            data[record:record+4] = (int.from_bytes(data[record:record+4], 'big') + origin).to_bytes(4, 'big')
        facts[0x306] = instruction(0x306, '43f900100800', 'LEA', '(0x100800).l|A1')
        image = image_for(data, facts)
        image = replace(image, header=replace(image.header, rom_start=origin, rom_end=origin+len(image.data)-1))
        decoded = {a+origin: replace(f, cpu_address=a+origin, flows=tuple(t+origin for t in f.flows))
                   for a,f in facts.items()}
        rooted = {a:f for a,f in decoded.items() if a<origin+0x620}
        model, = discover(image, rooted, decoded)
        self.assertEqual((origin+0x600, origin+0x620, origin+0x640), model.targets)
        self.assertEqual((), discover(image, rooted, decoded,
                                     protected_ranges=((origin+0x621, origin+0x622),)))

    def test_direct_read_covering_target_from_previous_word_protects_all_bytes(self):
        data, facts = fixture()
        facts[0x500] = replace(instruction(0x500, '22390000061e', 'MOVE.L', '(0x61e).l|D1'),
                              references=(InstructionReference(0x61E, 'READ', 0),))
        self.assertEqual((), self.run_model(data, facts))

    def test_skipped_record_reads_in_one_path_reject_inconsistent_stride(self):
        data, facts = fixture()
        facts[0x318] = instruction(0x318, '6600000a', 'BNE.W', '0x324', 'CONDITIONAL_JUMP', (0x324,))
        self.assertEqual((), self.run_model(data, facts))

    def test_non_cursor_loop_preserves_single_layout(self):
        data, facts = fixture()
        facts[0x318] = instruction(0x318, '51c8fffe', 'DBF', 'D0w|0x318', 'CONDITIONAL_JUMP', (0x318,))
        self.assertEqual(12, self.run_model(data, facts)[0].stride)

    def test_cursor_read_loop_cannot_infer_finite_stride(self):
        data, facts = fixture()
        facts[0x318] = instruction(0x318, '51c8fffc', 'DBF', 'D0w|0x316', 'CONDITIONAL_JUMP', (0x316,))
        self.assertEqual((), self.run_model(data, facts))

    def test_adjacent_unrelated_offsets_do_not_extend_table(self):
        data, facts = fixture()
        # First offset alone suggests three slots. A neighboring table has
        # plausible offsets but does not corroborate the full record layout.
        for value in (0x24, 0x12, 0xFFFF, 0x8006):
            changed = bytearray(data)
            changed[0x804:0x806] = value.to_bytes(2, 'big')
            self.assertEqual((), self.run_model(changed, facts), hex(value))

    def test_record_holes_overlaps_and_odd_extent_rejected(self):
        data, facts = fixture()
        for address, value in ((0x800, 5), (0x800, 0x106), (0x802, 0x10), (0x802, 0x14), (0x804, 0x12)):
            changed = bytearray(data)
            changed[address:address + 2] = value.to_bytes(2, 'big')
            self.assertEqual((), self.run_model(changed, facts))

    def test_decoded_opcode_and_signed_word_index_encoding_must_agree(self):
        data, facts = fixture()
        for raw in ('d2f10800', 'd2f10002', 'd2f11000'):
            changed = {**facts, 0x30C: replace(facts[0x30C], raw=bytes.fromhex(raw))}
            self.assertEqual((), self.run_model(data, changed))

    def test_target_data_and_operand_interior_protected(self):
        data, facts = fixture()
        for protected in (((0x620, 0x622),), ((0x621, 0x623),)):
            self.assertEqual((), self.run_model(data, facts, protected_ranges=protected))
        changed = bytearray(data)
        changed[0x812:0x816] = (0x40C).to_bytes(4, 'big')
        # Even a speculative decode at this address cannot replace rooted
        # LEA's immediate extension word.
        extra = instruction(0x40C, 'fb00', 'LINEF', '0xb00', flow='TERMINATOR')
        self.assertEqual((), self.run_model(changed, {**facts, 0x40C: extra}))

    def test_whole_first_instruction_must_avoid_protected_bytes(self):
        data, facts = fixture()
        facts[0x620] = instruction(0x620, '203c00000000', 'MOVE.L', '#0x0|D0')
        del facts[0x622]
        self.assertEqual((), self.run_model(data, facts, protected_ranges=((0x624, 0x626),)))

    def test_table_and_records_may_be_pointer_data_but_not_payload_or_code(self):
        data, facts = fixture()
        self.assertEqual(1, len(self.run_model(data, facts, protected_ranges=((0x800, 0x82A),))))
        for protected in (((0x800, 0x806),), ((0x824, 0x825),)):
            self.assertEqual((), self.run_model(data, facts, protected_record_ranges=protected))
        facts[0x802] = instruction(0x802, '0012', 'NOP')
        image = image_for(data, facts)
        self.assertEqual((), discover(image, facts, facts))

    def test_no_self_referential_callback_into_record_bytes(self):
        data, facts = fixture()
        data[0x812:0x816] = (0x818).to_bytes(4, 'big')
        facts[0x818] = instruction(0x818, '7000', 'MOVEQ', '0x0|D0')
        self.assertEqual((), self.run_model(data, facts))

    def test_missing_target_requests_probe_without_promoting_unchecked_bytes(self):
        data, facts = fixture()
        image = image_for(data, facts)
        missing = {a: f for a, f in facts.items() if a != 0x620}
        requests = []
        self.assertEqual((), discover(image, {a: f for a, f in facts.items() if a < 0x620}, missing,
                         decode_request=lambda *args: requests.append(args)))
        self.assertEqual([(0x620, 0x310, 'relative record callback first instruction')], requests)

    def test_unsupported_target_fact_is_not_promoted(self):
        data, facts = fixture()
        facts[0x620] = instruction(0x620, 'a000', 'LINEA', '0x0', flow='TERMINATOR')
        self.assertEqual((), self.run_model(data, facts))


if __name__ == '__main__':
    unittest.main()
