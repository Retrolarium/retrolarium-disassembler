from pathlib import Path
from decimal import Decimal
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.benchmarks.sonic_corpus import (
    below_source_recall_target, compare, normalise_reference_listing,
)


def as_line(address, encoded, source):
    return f"       1/{address:8X} : {encoded:<20}{source}"


def sn_line(address, encoded, source):
    return f"{address:08X} {encoded:<26}{source}"


class SonicCorpusBenchmarkTests(unittest.TestCase):
    def test_source_recall_gate_uses_counts_without_rounding(self):
        case = {"source_emission": {"matching_instructions": 8999,
                                    "reference_instructions": 10000}}
        self.assertTrue(below_source_recall_target(case, Decimal("90")))
        case["source_emission"]["matching_instructions"] = 9000
        self.assertFalse(below_source_recall_target(case, Decimal("90")))
        self.assertTrue(below_source_recall_target({}, Decimal("90")))

    def read(self, lines, rom, **options):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.lst").write_text("\n".join(lines), encoding="utf-8")
            return normalise_reference_listing(root / "input.lst", rom, root / "output.lst", **options)

    def test_macro_bodies_z80_and_data_do_not_enter_m68k_denominator(self):
        found, _, _ = self.read([
            as_line(0, "", "wrapper macro x"),
            as_line(0, "", " nop"), as_line(0, "", "endm"),
            as_line(0, "F3", "di"), as_line(2, "0000", "dc.w 0"),
            as_line(4, "4E75", "Finish: rts"),
        ], bytes.fromhex("F30000004E75"))
        self.assertEqual({4: bytes.fromhex("4E75")}, found)

    def test_sn_single_statement_macros_do_not_hide_following_code(self):
        found, _, _ = self.read([
            sn_line(0, "", "Finish macros"),
            sn_line(0, "", " rts"),
            sn_line(0, "", "Wrapper macro"),
            sn_line(0, "", " nop"), sn_line(0, "", " endm"),
            sn_line(0, "4E71", " nop"), sn_line(2, "4E75", " rts"),
        ], bytes.fromhex("4E714E75"), sn=True)
        self.assertEqual({0: bytes.fromhex("4E71"), 2: bytes.fromhex("4E75")}, found)

    def test_as_named_endm_closes_definition_without_hiding_real_code(self):
        found, _, _ = self.read([
            as_line(0, "", "wrapper macro x"),
            as_line(0, "", "dc.w x"), as_line(0, "", "wrapper endm"),
            as_line(0, "4E75", "rts"),
        ], bytes.fromhex("4E75"))
        self.assertEqual({0: bytes.fromhex("4E75")}, found)

    def test_phase_maps_ram_instruction_to_physical_rom(self):
        found, _, _ = self.read([
            as_line(0, "4E71", "nop"),
            as_line(0xFF0000, "", "phase $FF0000"),
            as_line(0xFF0000, "4E75", "rts"),
            as_line(4, "", "dephase"),
        ], bytes.fromhex("4E714E75"))
        self.assertEqual({0: bytes.fromhex("4E71"), 2: bytes.fromhex("4E75")}, found)

    def test_saved_cpu_context_excludes_z80_and_restores_m68k(self):
        found, _, _ = self.read([
            as_line(0, "", "save"), as_line(0, "", "cpu Z80"),
            as_line(0, "4E75", "rts"),
            as_line(2, "", "restore"), as_line(2, "4E71", "nop"),
        ], bytes.fromhex("4E754E71"))
        self.assertEqual({2: bytes.fromhex("4E71")}, found)

    def test_long_instruction_is_recovered_from_next_byte_boundary(self):
        rom = bytes.fromhex("23FC1234567800A111004E75")
        found, opened, _ = self.read([
            as_line(0, "23FC 1234 5678", "move.l #$12345678,($A11100).l"),
            as_line(10, "4E75", "rts"),
        ], rom)
        self.assertEqual(rom[:10], found[0])
        self.assertFalse(opened)

    def test_local_label_at_first_source_column_is_an_instruction(self):
        found, _, _ = self.read([as_line(0, "4E75", ".done: rts")], bytes.fromhex("4E75"))
        self.assertEqual({0: bytes.fromhex("4E75")}, found)

    def test_byte_data_delimits_truncated_instruction(self):
        rom = bytes.fromhex("33FC000000C000003215")
        found, opened, _ = self.read([
            as_line(0, "33FC 0000 00C0", "move.w #0,($C00000).l"),
            as_line(8, "32 15", "dc.b $32,$15"),
        ], rom)
        self.assertEqual(rom[:8], found[0])
        self.assertFalse(opened)

    def test_only_explicit_postprocessing_ranges_can_change_as_operands(self):
        lines = [as_line(0, "303C 0001", "move.w #1,d0")]
        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.read(lines, bytes.fromhex("303C0002"))
        found, _, stats = self.read(lines, bytes.fromhex("303C0002"), patched_ranges=((2, 4),))
        self.assertEqual(bytes.fromhex("303C0002"), found[0])
        self.assertEqual(1, stats["postprocessed_instructions"])

    def test_forced_macro_instruction_and_later_byte_overwrite_are_final_encoding(self):
        rom = bytes.fromhex("137C005B0000")
        found, opened, stats = self.read([
            as_line(0, "137C 005B 0001", "!move.b #$5B,1(a1)"),
            as_line(5, "", "!org *-1"),
            as_line(5, "00", "!dc.b 0"),
            as_line(6, "", "Next:"),
        ], rom)
        self.assertEqual(rom, found[0])
        self.assertEqual(1, stats["postprocessed_instructions"])

    def test_sn_forward_references_and_ram_obj_are_mapped_and_validated(self):
        rom = bytes.fromhex("60024E714E75")
        found, _, stats = self.read([
            sn_line(0x880000, "6000", "bra.s Target"),
            sn_line(0x880002, "", "obj $FF0000"),
            sn_line(0xFF0000, "4E71", "nop"),
            sn_line(0xFF0002, "", "objend"),
            sn_line(0x880004, "4E75", "Target: rts"),
        ], rom, sn=True)
        self.assertEqual({0: rom[:2], 2: rom[2:4], 4: rom[4:6]}, found)
        self.assertEqual(1, stats["first_pass_operands_resolved"])
        with self.assertRaisesRegex(ValueError, "opcode disagrees"):
            self.read([sn_line(0x880000, "4E75", "rts")], bytes.fromhex("4E71"), sn=True)

    def test_same_prefix_of_different_length_is_a_mismatch(self):
        result = compare({0: b"\x4e\x75"}, frozenset(), {0: b"\x4e\x75\0\0"})
        self.assertEqual(0, result["matching_instructions"])
        self.assertEqual(1, result["different_encodings"])

    def test_sn_known_bank_mapping_survives_obj_transition(self):
        rom = bytearray(0x200004)
        rom[0x200000:0x200004] = bytes.fromhex("4E714E75")
        found, _, stats = self.read([
            sn_line(0x880000, "", "obj $2000000"),
            sn_line(0x2000000, "", "obj $900000"),
            sn_line(0x900000, "4E71", "nop"),
            sn_line(0x900002, "4E75", "rts"),
        ], bytes(rom), sn=True)
        self.assertEqual({0x200000: bytes.fromhex("4E71"), 0x200002: bytes.fromhex("4E75")}, found)
        self.assertEqual(0, stats.get("instructions_outside_rom", 0))


if __name__ == "__main__":
    unittest.main()
