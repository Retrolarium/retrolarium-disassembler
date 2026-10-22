from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from retrolarium_disassembler.m68k.dispatch.reaching import discover_reaching_word_dispatch_tables as discover
from retrolarium_disassembler.m68k.dispatch.reaching import discover_reaching_word_dispatch_seeds
from retrolarium_disassembler.m68k.dispatch.reaching import make_word_index_mask_reader
from retrolarium_disassembler.facts import InstructionReference
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from megadrive.builders import fact


def f(address, mnemonic, operands, raw, flow="FALL_THROUGH", targets=()):
    return replace(
        fact(address, mnemonic, operands, flows=targets),
        length=len(bytes.fromhex(raw)),
        raw=bytes.fromhex(raw),
        flow_type=flow,
    )


def fixture():
    items = [
        f(0x220, "MOVE.W", "(A0)|D1w", "3210"),
        f(0x222, "ADD.W", "D1w|D1w", "d241"),
        f(0x224, "LEA", "(0x300).l|A1", "43f900000300"),
        f(0x22A, "TST.B", "D0b", "4a00"),
        f(0x22C, "BEQ.B", "0x234", "6706", "CONDITIONAL_JUMP", (0x234,)),
        f(0x22E, "LEA", "(0x340).l|A1", "43f900000340"),
        f(0x234, "MOVE.W", "(0x0,A1,D1w*0x1)|D1w", "32311000"),
        f(0x238, "JSR", "(0x0,A1,D1w*0x1)", "4eb11000", "COMPUTED_CALL"),
    ]
    items += [f(a, "RTS", "", "4e75", "TERMINATOR") for a in (0x400, 0x404, 0x408, 0x500, 0x504, 0x508)]
    data = bytearray(cartridge(size=0x800))
    data[0x200:] = b"\xff" * (len(data) - 0x200)
    for item in items:
        data[item.cpu_address : item.cpu_address + item.length] = item.raw
    for table, targets in ((0x300, (0x400, 0x404, 0x408)), (0x340, (0x500, 0x504, 0x508))):
        data[table : table + 6] = b"".join(((a - table).to_bytes(2, "big") for a in targets))
    return (parse_megadrive(bytes(data)), {item.cpu_address: item for item in items})


class ReachingDispatchProofTests(unittest.TestCase):
    def test_mask_bound_excludes_unreachable_adjacent_data_even_with_validator(self):
        image, original = fixture()
        items = [
            f(0x220, "MOVE.W", "(A0)|D1w", "3210"),
            f(0x222, "ANDI.W", "#0x1|D1w", "02410001"),
            f(0x226, "ADD.W", "D1w|D1w", "d241"),
            f(0x228, "LEA", "(0x300).l|A1", "43f900000300"),
            f(0x22E, "MOVE.W", "(0x0,A1,D1w*0x1)|D1w", "32311000"),
            f(0x232, "JMP", "(0x0,A1,D1w*0x1)", "4ef11000", "COMPUTED_JUMP"),
            original[0x400],
            original[0x404],
        ]
        data = bytearray(image.data)
        data[0x300:0x306] = bytes.fromhex("0100 0104 0200")
        facts = {item.cpu_address: item for item in items}
        tables = discover(parse_megadrive(bytes(data)), facts, handler_validator=lambda _: True)
        self.assertEqual([(0x400, 0x404)], [table.targets for table in tables])
        self.assertEqual([0x304], [table.end for table in tables])

    def test_noncontiguous_mask_excludes_holes_even_when_targets_are_code(self):
        image, original = fixture()
        items = [
            f(0x220, "MOVE.W", "(A0)|D1w", "3210"),
            f(0x222, "ANDI.W", "#0x5|D1w", "02410005"),
            f(0x226, "ADD.W", "D1w|D1w", "d241"),
            f(0x228, "LEA", "(0x300).l|A1", "43f900000300"),
            f(0x22E, "MOVE.W", "(0x0,A1,D1w*0x1)|D1w", "32311000"),
            f(0x232, "JMP", "(0x0,A1,D1w*0x1)", "4ef11000", "COMPUTED_JUMP"),
            original[0x400],
            original[0x404],
            original[0x408],
            f(0x40C, "RTS", "", "4e75", "TERMINATOR"),
            original[0x500],
            original[0x504],
        ]
        data = bytearray(image.data)
        data[0x300:0x30C] = bytes.fromhex("0100 0104 0200 0204 0108 010c")
        data[0x40C:0x40E] = bytes.fromhex("4e75")
        facts = {item.cpu_address: item for item in items}
        tables = discover(parse_megadrive(bytes(data)), facts, handler_validator=lambda _: True)
        self.assertEqual([(0x400, 0x404, 0x408, 0x40C)], [table.targets for table in tables])
        self.assertEqual([0x30C], [table.end for table in tables])

    def test_unrecognized_target_needs_its_own_cfg_validation(self):
        image, facts = fixture()
        facts.pop(0x408)
        facts.pop(0x508)
        checked = []

        def validate(target):
            checked.append(target)
            return target == 0x508

        targets = {target for table in discover(image, facts, handler_validator=validate) for target in table.targets}
        self.assertNotIn(0x408, targets)
        self.assertIn(0x508, targets)
        self.assertEqual([0x408, 0x508], checked)

    def test_occupied_slots_and_odd_byte_boundaries_stop_scan(self):
        image, facts = fixture()
        occupied = {**facts, 0x304: f(0x304, "NOP", "", "4e71")}
        tables = discover(image, occupied, handler_validator=lambda _: True)
        self.assertEqual((0x400, 0x404), next(t.targets for t in tables if t.table == 0x300))
        boundary = replace(
            f(0x600, "LEA", "(0x305).l|A2", "45f900000305"),
            references=(InstructionReference(0x305, "DATA", 0),),
        )
        tables = discover(image, {**facts, 0x600: boundary}, handler_validator=lambda _: True)
        self.assertEqual((0x400, 0x404), next(t.targets for t in tables if t.table == 0x300))

    def test_mask_reader_invalidates_later_arithmetic_and_missing_paths(self):
        facts = {
            0x220: f(0x220, "ANDI.W", "#0x1|D1w", "02410001"),
            0x224: f(0x224, "ADD.W", "D1w|D1w", "d241"),
        }
        masks = make_word_index_mask_reader(facts)
        self.assertEqual(frozenset({1}), masks(0x224, "d1"))
        facts[0x224] = f(0x224, "ADDI.W", "#0x2|D1w", "06410002")
        facts[0x228] = f(0x228, "ADD.W", "D1w|D1w", "d241")
        self.assertIsNone(make_word_index_mask_reader(facts)(0x228, "d1"))
        facts[0x210] = f(0x210, "BRA.W", "0x224", "60000012", "UNCONDITIONAL_JUMP", (0x224,))
        self.assertIsNone(make_word_index_mask_reader(facts)(0x224, "d1"))

    def test_independent_bases_keep_offsets_correlated(self):
        image, facts = fixture()
        tables = discover(image, facts)
        self.assertEqual(
            {0x300: (0x400, 0x404, 0x408), 0x340: (0x500, 0x504, 0x508)},
            {t.table: t.targets for t in tables},
        )
        self.assertEqual({(0x222,)}, {t.scales for t in tables})

    def test_stride_four_and_non_word_scale_are_rejected(self):
        image, facts = fixture()
        for changed in (f(0x220, "ADD.W", "D1w|D1w", "d241"), f(0x220, "LSL.W", "#0x1|D1w", "e349")):
            with self.subTest(changed=changed.mnemonic):
                self.assertEqual((), discover(image, {**facts, 0x220: changed}))
        self.assertEqual((), discover(image, {**facts, 0x222: f(0x222, "ADD.L", "D1|D1", "d281")}))

    def test_base_register_updates_and_counter_writes_stop_proof(self):
        image, facts = fixture()
        variants = [
            f(0x22A, "EXG", "A1|A2", "c34a"),
            f(0x22A, "TST.B", "(A1)+", "4a19"),
            f(0x22A, "MOVE.W", "D0w|D1w", "3200"),
            f(0x22A, "ADDA.W", "D0w|A1", "d2c0"),
            f(0x22A, "DBF", "D1w|0x234", "51c90008", "CONDITIONAL_JUMP", (0x234,)),
        ]
        for changed in variants:
            with self.subTest(changed=(changed.mnemonic, changed.operands)):
                self.assertEqual((), discover(image, {**facts, 0x22A: changed}))

    def test_unknown_calls_and_traps_are_not_register_preservation(self):
        image, facts = fixture()
        for changed in (
            f(0x22A, "JSR", "(A0)", "4e90", "COMPUTED_CALL"),
            f(0x22A, "BSR.B", "0x400", "6174", "UNCONDITIONAL_CALL", (0x400,)),
            f(0x22A, "TRAP", "#0x0", "4e40", "CALL_TERMINATOR"),
        ):
            with self.subTest(changed=changed.mnemonic):
                self.assertEqual((), discover(image, {**facts, 0x22A: changed}))

    def test_incoming_path_with_base_but_without_scale_rejects(self):
        image, facts = fixture()
        facts.update(
            {
                0x260: f(0x260, "LEA", "(0x300).l|A1", "43f900000300"),
                0x266: f(0x266, "BRA.B", "0x234", "60cc", "UNCONDITIONAL_JUMP", (0x234,)),
            }
        )
        self.assertEqual((), discover(image, facts))

    def test_external_entry_and_call_bypassing_load_reject(self):
        image, facts = fixture()
        self.assertEqual((), discover(image, facts, entrypoints={0x224}))
        self.assertEqual((), discover(image, facts, entrypoints={0x234}))
        self.assertEqual(
            (),
            discover(
                image,
                {**facts, 0x280: f(0x280, "BSR.B", "0x238", "61b6", "UNCONDITIONAL_CALL", (0x238,))},
            ),
        )

    def test_base_overwrite_terminates_previous_definition(self):
        image, facts = fixture()
        facts = {a: item for a, item in facts.items() if not 0x22A <= a <= 0x238}
        facts.update(
            {
                0x22A: f(0x22A, "LEA", "(0x340).l|A1", "43f900000340"),
                0x230: f(0x230, "MOVE.W", "(0x0,A1,D1w*0x1)|D1w", "32311000"),
                0x234: f(0x234, "JSR", "(0x0,A1,D1w*0x1)", "4eb11000", "COMPUTED_CALL"),
            }
        )
        self.assertEqual([0x340], [table.table for table in discover(image, facts)])

    def test_unproved_loop_and_nonzero_callback_field_reject(self):
        image, facts = fixture()
        loop = f(0x22A, "BNE.B", "0x22a", "66fe", "CONDITIONAL_JUMP", (0x22A,))
        self.assertEqual((), discover(image, {**facts, 0x22A: loop}))
        load = replace(facts[0x234], operands="(0x2,A1,D1w*0x1)|D1w")
        self.assertEqual((), discover(image, {**facts, 0x234: load}))

    def test_constant_arithmetic_cannot_hide_an_earlier_scale(self):
        image, original = fixture()
        for operation, operands, raw in (
            ("ADDI.W", "#0x2|D1w", "06410002"),
            ("SUBI.W", "#0x2|D1w", "04410002"),
            ("ADDQ.W", "#0x2|D1w", "5441"),
            ("SUBQ.W", "#0x2|D1w", "5541"),
            ("ANDI.W", "#0xfffe|D1w", "0241fffe"),
            ("ORI.W", "#0x2|D1w", "00410002"),
            ("EORI.W", "#0x2|D1w", "0a410002"),
            ("ADD.W", "D0w|D1w", "d240"),
        ):
            with self.subTest(operation=operation):
                changed = f(0x204, operation, operands, raw)
                branch = changed.cpu_address + changed.length
                facts = {
                    **original,
                    0x200: f(0x200, "MOVE.W", "(A0)|D1w", "3210"),
                    0x202: f(0x202, "ADD.W", "D1w|D1w", "d241"),
                    0x204: changed,
                    branch: f(branch, "BRA.W", "0x220", "60000018", "UNCONDITIONAL_JUMP", (0x220,)),
                    0x220: f(0x220, "NOP", "", "4e71"),
                }
                self.assertEqual((), discover(image, facts))

    def test_subtracting_a_constant_from_fresh_index_keeps_word_dispatch(self):
        image, facts = fixture()
        facts.update(
            {
                0x200: f(0x200, "MOVE.W", "(A0)|D1w", "3210"),
                0x202: f(0x202, "SUBI.W", "#0x3e8|D1w", "044103e8"),
                0x206: f(0x206, "BRA.W", "0x220", "60000018", "UNCONDITIONAL_JUMP", (0x220,)),
                0x220: f(0x220, "NOP", "", "4e71"),
            }
        )
        self.assertEqual({0x300, 0x340}, {table.table for table in discover(image, facts)})

    def test_partial_memory_input_and_masks_do_not_reuse_old_scale(self):
        image, facts = fixture()
        facts.update(
            {
                0x200: f(0x200, "MOVE.B", "(A0)|D1b", "1210"),
                0x202: f(0x202, "ANDI.W", "#0xf|D1w", "0241000f"),
                0x206: f(0x206, "BRA.W", "0x220", "60000018", "UNCONDITIONAL_JUMP", (0x220,)),
                0x220: f(0x220, "NOP", "", "4e71"),
            }
        )
        self.assertEqual(2, len(discover(image, facts)))

    def test_exceptions_and_status_register_writes_cannot_witness_path(self):
        image, facts = fixture()
        variants = (
            f(0x22A, "DIVU.W", "#0x0|D2w", "84fc0000"),
            f(0x22A, "DIVS.W", "#0x0|D2w", "85fc0000"),
            f(0x22A, "CHK.W", "D0w|D2w", "4580"),
            f(0x22A, "ORI", "#0x2000|SR", "007c2000"),
            f(0x22A, "ANDI", "#0xdfff|SR", "027cdfff"),
            f(0x22A, "MOVE", "D0w|SR", "46c0"),
        )
        for changed in variants:
            with self.subTest(operation=changed.mnemonic):
                self.assertEqual((), discover(image, {**facts, 0x22A: changed}))

    def test_seeds_explain_the_rooted_consumer(self):
        image, facts = fixture()
        seeds = discover_reaching_word_dispatch_seeds(image, facts)
        self.assertEqual([0x400, 0x404, 0x408, 0x500, 0x504, 0x508], [s.address for s in seeds])
        self.assertEqual({"reaching_word_dispatch"}, {s.kind for s in seeds})
        self.assertEqual({0x238}, {s.source_address for s in seeds})
        self.assertTrue(all(("all incoming paths" in seed.evidence for seed in seeds)))


if __name__ == "__main__":
    unittest.main()
