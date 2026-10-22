from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from retrolarium_disassembler.m68k.records.constructor import discover_tail_allocator_callback_seeds
from retrolarium_disassembler.facts import InstructionReference
from m68k.records.builders import fixture as constructor_fixture, instruction
from m68k.builders import instruction as encoded_instruction


def fixture():
    image, original = constructor_fixture()
    facts = {a: f for a, f in original.items() if a >= 0x300}
    facts[0x200] = encoded_instruction(0x200, "43f900000900", "LEA", "(0x900).l|A1")
    facts[0x206] = encoded_instruction(0x206, "4ef900000300", "JMP", "0x300.l", "UNCONDITIONAL_JUMP", (0x300,))
    return image, facts


class TailAllocatorCallbackTests(unittest.TestCase):
    def find(self, facts=None, *, rooted=None, **kwargs):
        image, original = fixture()
        facts = original if facts is None else facts
        return discover_tail_allocator_callback_seeds(
            image, facts, execution_facts=facts if rooted is None else rooted, **kwargs
        )

    def test_direct_tail_callback_has_same_pool_and_field_provenance(self):
        seeds = self.find()
        self.assertEqual([0x900], [s.address for s in seeds])
        self.assertEqual("tail_allocator_callback", seeds[0].kind)
        self.assertEqual("proven", seeds[0].confidence)
        self.assertEqual(0x200, seeds[0].source_address)
        for text in (
            "LEA at 000200",
            "tail transfer 000206",
            "allocator 000300",
            "stored at 000380",
            "RAM pool FFE000, 64 slots, stride 64, field +2",
            "indirect executor 000416",
        ):
            self.assertIn(text, seeds[0].evidence)

    def test_direct_bra_and_backend_tail_call_terminator_are_supported(self):
        _, facts = fixture()
        facts[0x206] = encoded_instruction(0x206, "600000f8", "BRA.W", "0x300", "UNCONDITIONAL_JUMP", (0x300,))
        self.assertEqual([0x900], [s.address for s in self.find(facts)])
        facts[0x206] = replace(facts[0x206], flow_type="CALL_TERMINATOR")
        self.assertEqual([0x900], [s.address for s in self.find(facts)])

    def test_pc_relative_and_absolute_word_lea_are_address_construction(self):
        _, original = fixture()
        for source in (
            encoded_instruction(0x200, "43fa06fe", "LEA", "(0x6fe,PC)|A1"),
            encoded_instruction(0x200, "43f80900", "LEA", "(0x900).w|A1"),
        ):
            facts = dict(original)
            facts[0x200] = source
            facts.pop(0x206)
            facts[0x204] = encoded_instruction(0x204, "4ef900000300", "JMP", "0x300.l", "UNCONDITIONAL_JUMP", (0x300,))
            self.assertEqual([0x900], [s.address for s in self.find(facts)])

    def test_all_parts_of_writer_allocator_and_executor_must_be_rooted(self):
        image, facts = fixture()
        self.assertEqual((), discover_tail_allocator_callback_seeds(image, facts))
        for omitted in (0x200, 0x206, 0x300, 0x350, 0x354, 0x35A, 0x380, 0x400, 0x406, 0x412, 0x416):
            with self.subTest(omitted=hex(omitted)):
                self.assertEqual((), self.find(facts, rooted={a: f for a, f in facts.items() if a != omitted}))

    def test_conditional_computed_or_ordinary_calls_are_not_tail_proof(self):
        _, original = fixture()
        for tail in (
            encoded_instruction(0x206, "660000f8", "BNE.W", "0x300", "CONDITIONAL_JUMP", (0x300,)),
            encoded_instruction(0x206, "4ed0", "JMP", "(A0)", "COMPUTED_JUMP", (0x300,)),
            encoded_instruction(0x206, "4ed0", "JMP", "(A0)", "UNCONDITIONAL_JUMP", (0x300,)),
            encoded_instruction(0x206, "4ef900000300", "JMP", "0x300.l", "COMPUTED_JUMP", (0x300,)),
            encoded_instruction(0x206, "4eb900000300", "JSR", "0x300.l", "UNCONDITIONAL_CALL", (0x300,)),
        ):
            facts = dict(original)
            facts[0x206] = tail
            with self.subTest(mnemonic=tail.mnemonic, flow=tail.flow_type):
                self.assertEqual((), self.find(facts))

    def test_unknown_tail_or_nonadjacent_writer_is_rejected(self):
        _, facts = fixture()
        facts[0x206] = replace(facts[0x206], flows=(0x700,))
        self.assertEqual((), self.find(facts))
        _, facts = fixture()
        facts[0x206] = encoded_instruction(0x206, "4e71", "NOP")
        facts[0x208] = encoded_instruction(0x208, "4ef900000300", "JMP", "0x300.l", "UNCONDITIONAL_JUMP", (0x300,))
        self.assertEqual((), self.find(facts))

    def test_callback_parameter_clobbers_or_exception_before_store_reject(self):
        _, original = fixture()
        for op, args in (
            ("EXG", "A1|D7"),
            ("TST.B", "(A1)+"),
            ("MOVE.L", "(A1)+|D7"),
            ("MOVEA.L", "#0x800|A1"),
            ("LINK", "A1|#-0x4"),
            ("MOVE", "#0x0|SR"),
            ("DIVU.W", "#0x0|D7"),
        ):
            facts = dict(original)
            facts[0x35E] = instruction(0x35E, op, args, length=4)
            with self.subTest(op=op, args=args):
                self.assertEqual((), self.find(facts))

    def test_same_field_in_different_pool_count_stride_or_offset_rejects(self):
        _, original = fixture()
        for address, args in (
            (0x354, "(0xffd000).l|A0"),
            (0x35A, "#0x1f|D0w"),
            (0x366, "#0x20|A0"),
            (0x380, "A1|(0x6,A0)"),
            (0x412, "(0x6,A0)|A1"),
        ):
            facts = dict(original)
            facts[address] = replace(facts[address], operands=args)
            with self.subTest(address=hex(address), args=args):
                self.assertEqual((), self.find(facts))

    def test_target_instruction_interior_and_explicit_data_reader_reject(self):
        _, facts = fixture()
        facts[0x8FE] = encoded_instruction(0x8FE, "203c12345678", "MOVE.L", "#0x12345678|D0")
        self.assertEqual((), self.find(facts))
        _, facts = fixture()
        reader = encoded_instruction(0x600, "4a7900000900", "TST.W", "(0x900).l")
        facts[0x600] = replace(reader, references=(InstructionReference(0x900, "READ", 0),))
        self.assertEqual((), self.find(facts))
        self.assertEqual((), self.find(protected_ranges=((0x900, 0x902),)))

    def test_invalid_target_odd_address_or_ram_address_is_rejected(self):
        _, original = fixture()
        for target in (0, 0x901, 0xFFE000):
            facts = dict(original)
            facts[0x200] = replace(facts[0x200], operands=f"(0x{target:x}).l|A1")
            self.assertEqual((), self.find(facts))


if __name__ == "__main__":
    unittest.main()
