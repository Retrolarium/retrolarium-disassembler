from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_kit.m68k_indexed_dispatch import (
    discover_register_indexed_dispatch_seeds, discover_added_index_dispatch_seeds,
    discover_nested_word_dispatch_seeds,
    discover_dense_absolute_jump_seeds,
)
from test_megadrive import cartridge
from test_megadrive_z80 import fact


def data_image():
    data = bytearray(cartridge(size=0x800))
    for i, target in enumerate((0x400, 0x410, 0x420)):
        data[0x300 + 4 * i:0x304 + 4 * i] = target.to_bytes(4, "big")
        data[target:target + 2] = bytes.fromhex("4E75")
    return data


def indexed_facts():
    items = [fact(0x200, "MOVEQ", "0x0|D0"), fact(0x202, "MOVE.B", "(A0)|D0b"),
             replace(fact(0x204, "BEQ.B", "0x218"), flows=(0x218,), flow_type="CONDITIONAL_JUMP"),
             fact(0x206, "ADD.W", "D0w|D0w"), fact(0x208, "ADD.W", "D0w|D0w"),
             replace(fact(0x20A, "LEA", "(0x300).l|A1"), length=6),
             replace(fact(0x210, "MOVEA.L", "(-0x4,A1,D0w*0x1)|A1"), length=4),
             replace(fact(0x214, "JSR", "(A1)"), flow_type="COMPUTED_CALL")]
    return {f.cpu_address: f for f in items}


class IndexedDispatchTests(unittest.TestCase):
    def test_dense_absolute_jumps_include_nop_slots_but_require_four_entries(self):
        data = data_image()
        for index in range(4):
            start = 0x240 + index * 8
            data[start:start + 8] = bytes.fromhex("4EF9000004004E71")
        addresses = {s.address for s in discover_dense_absolute_jump_seeds(parse_megadrive(bytes(data)))}
        self.assertEqual({0x400, 0x240, 0x248, 0x250, 0x258, 0x246, 0x24E, 0x256, 0x25E}, addresses)
        data[0x258:0x260] = bytes(8)
        self.assertFalse(discover_dense_absolute_jump_seeds(parse_megadrive(bytes(data))))

    def test_scaled_nonzero_byte_reads_first_pointer_at_base(self):
        seeds = discover_register_indexed_dispatch_seeds(parse_megadrive(bytes(data_image())), indexed_facts())
        self.assertEqual((0x400, 0x410, 0x420), tuple(s.address for s in seeds))

    def test_missing_nonzero_guard_or_wrong_stride_is_not_proof(self):
        image = parse_megadrive(bytes(data_image()))
        for address, mnemonic in ((0x204, "BNE.B"), (0x208, "NOP")):
            facts = indexed_facts()
            facts[address] = replace(facts[address], mnemonic=mnemonic)
            self.assertFalse(discover_register_indexed_dispatch_seeds(image, facts))

    def test_added_index_uses_pc_of_lea_extension_word(self):
        items = [replace(fact(0x200, "LEA", "(0xfe,PC)|A2"), raw=bytes.fromhex("45FA00FE"), length=4),
                 fact(0x204, "ADDA.W", "D3w|A2"), fact(0x206, "MOVEA.L", "(A2)|A2"),
                 replace(fact(0x208, "JSR", "(A2)"), flow_type="COMPUTED_CALL")]
        facts = {f.cpu_address: f for f in items}
        image = parse_megadrive(bytes(data_image()))
        self.assertEqual((0x400, 0x410, 0x420), tuple(s.address for s in discover_added_index_dispatch_seeds(image, facts)))
        # A bad existing decode crossing one target must not hide later slots.
        facts[0x3FE] = replace(fact(0x3FE, "MOVE.W", "D0w|D1w"), length=4)
        self.assertEqual((0x410, 0x420), tuple(s.address for s in discover_added_index_dispatch_seeds(image, facts)))
        facts[0x206] = replace(facts[0x206], operands="(A2)|A3")
        self.assertFalse(discover_added_index_dispatch_seeds(image, facts))

    def test_nested_offsets_are_relative_to_each_entry_not_table_start(self):
        data = data_image()
        data[0x300:0x310] = bytes.fromhex("00000340000003500000000000000000")
        for slot, target in ((0x340, 0x400), (0x342, 0x410), (0x350, 0x420), (0x352, 0x430)):
            data[slot:slot + 2] = (target - slot).to_bytes(2, "big")
            data[target:target + 2] = bytes.fromhex("4E75")
        items = [replace(fact(0x200, "MOVEA.L", "(0x300,PC,D0w*0x1)|A0"), length=4),
                 fact(0x204, "MOVEQ", "0x0|D2"), replace(fact(0x206, "MOVE.B", "(0x24,A6)|D2b"), length=4),
                 fact(0x20A, "ADDA.W", "D2w|A0"), fact(0x20C, "ADDA.W", "(A0)|A0"),
                 replace(fact(0x20E, "JMP", "(A0)"), flow_type="COMPUTED_JUMP")]
        facts = {f.cpu_address: f for f in items}
        image = parse_megadrive(bytes(data))
        self.assertEqual({0x400, 0x410, 0x420, 0x430}, {s.address for s in discover_nested_word_dispatch_seeds(image, facts)})
        facts[0x20C] = replace(facts[0x20C], mnemonic="ADDA.L")
        self.assertFalse(discover_nested_word_dispatch_seeds(image, facts))

    def test_word_index_read_from_object_field_uses_entry_relative_offsets(self):
        data = data_image()
        data[0x300:0x310] = bytes(16)
        for i, target in enumerate((0x400, 0x410, 0x420)):
            slot = 0x300 + 2 * i
            data[slot:slot + 2] = (target - slot).to_bytes(2, "big")
        items = [replace(fact(0x200, "LEA", "(0xfe,PC)|A2"), raw=bytes.fromhex("45FA00FE"), length=4),
                 replace(fact(0x204, "ADDA.W", "(0x2a,A6)|A2"), length=4),
                 fact(0x208, "ADDA.W", "(A2)|A2"),
                 replace(fact(0x20A, "JMP", "(A2)"), flow_type="COMPUTED_JUMP")]
        facts = {f.cpu_address: f for f in items}
        image = parse_megadrive(bytes(data))
        self.assertEqual((0x400, 0x410, 0x420), tuple(s.address for s in discover_added_index_dispatch_seeds(image, facts)))
        facts[0x208] = replace(facts[0x208], mnemonic="ADDA.L")
        self.assertFalse(discover_added_index_dispatch_seeds(image, facts))

    def test_scalar_index_preparation_between_lea_and_add_preserves_base(self):
        data = data_image()
        data[0x300:0x310] = bytes(16)
        for i, target in enumerate((0x400, 0x410, 0x420)):
            slot = 0x300 + 2 * i
            data[slot:slot + 2] = (target - slot).to_bytes(2, "big")
        items = [replace(fact(0x200, "LEA", "(0xfe,PC)|A0"), raw=bytes.fromhex("41FA00FE"), length=4),
                 fact(0x204, "MOVEQ", "0x0|D0"), replace(fact(0x206, "MOVE.B", "(0x29,A6)|D0b"), length=4),
                 fact(0x20A, "ASR.L", "#0x1|D0"), fact(0x20C, "ADDA.W", "D0w|A0"),
                 fact(0x20E, "ADDA.W", "(A0)|A0"),
                 replace(fact(0x210, "JMP", "(A0)"), flow_type="COMPUTED_JUMP")]
        facts = {f.cpu_address: f for f in items}
        image = parse_megadrive(bytes(data))
        self.assertEqual((0x400, 0x410, 0x420), tuple(s.address for s in discover_added_index_dispatch_seeds(image, facts)))
        facts[0x20A] = replace(facts[0x20A], mnemonic="MOVEA.L", operands="D0|A0")
        self.assertFalse(discover_added_index_dispatch_seeds(image, facts))
