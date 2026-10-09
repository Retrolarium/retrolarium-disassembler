from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_disasm.facts import InstructionReference
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disasm.megadrive.pointers import _pc_word_dispatch_tables, discover_dispatch_table_seeds
from retrolarium_disasm.m68k.instructions import absolute_referenced_addresses
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class PcWordDispatchBoundaryTests(unittest.TestCase):
    def setup_table(self, suffix="w"):
        data = bytearray(cartridge(size=0x800))
        self.targets = (0x308, 0x330, 0x350, 0x360)
        for index, target in enumerate(self.targets):
            data[0x300 + 2 * index:0x302 + 2 * index] = (target - 0x300).to_bytes(2, "big")
            data[target:target + 2] = bytes.fromhex("4E75")
        self.image = parse_megadrive(bytes(data))
        items = (
            replace(fact(0x200, "MOVE.W", "(0x300,PC,D0w*0x1)|D0w"), length=4),
            replace(fact(0x204, "JMP", "(0x300,PC,D0w*0x1)"), length=4,
                    flow_type="COMPUTED_JUMP"),
            replace(fact(0x600, "LEA", f"(0x302).{suffix}|A1",
                         references=(InstructionReference(0x302, "DATA", 0),)), length=4),
        )
        self.facts = {item.cpu_address: item for item in items}

    def assert_table_open(self):
        seeds = discover_dispatch_table_seeds(
            self.image, self.facts, handler_validator=lambda address: address == 0x308)
        self.assertEqual(self.targets, tuple(s.address for s in seeds))
        self.assertTrue(all("complete_cfg_witness_at_000308" in seed.evidence for seed in seeds))

    def assert_table_closed(self):
        self.assertEqual((), discover_dispatch_table_seeds(self.image, self.facts))

    def assert_strong_boundary(self):
        self.assertEqual((), discover_dispatch_table_seeds(
            self.image, self.facts, handler_validator=lambda address: True))

    def test_weak_lea_boundary_needs_exact_table_and_valid_handler(self):
        for suffix in ("w", "l"):
            with self.subTest(suffix=suffix):
                self.setup_table(suffix)
                self.facts[0x604] = fact(0x604, "MOVE.L", "A1|D2")
                self.facts[0x606] = replace(fact(0x606, "RTS", ""), flow_type="TERMINATOR")
                self.assertIn(0x302, absolute_referenced_addresses(self.facts))
                self.assert_table_closed()
                self.assert_table_open()

    def test_absolute_lea_followed_by_memory_read_keeps_boundary(self):
        self.setup_table()
        self.facts[0x604] = fact(0x604, "MOVE.W", "(A1)+|D2w")
        self.assert_strong_boundary()

    def test_read_in_direct_callee_keeps_boundary(self):
        self.setup_table()
        self.facts[0x604] = replace(fact(0x604, "BSR.W", "0x00000620", flows=(0x620,)),
                                    length=4, flow_type="UNCONDITIONAL_CALL")
        self.facts[0x620] = fact(0x620, "MOVE.B", "(0x2,A1)|D0b")
        self.assert_strong_boundary()

    def test_read_after_direct_branch_keeps_boundary(self):
        self.setup_table()
        self.facts[0x604] = replace(fact(0x604, "BRA.B", "0x00000620", flows=(0x620,)),
                                    flow_type="UNCONDITIONAL_JUMP")
        self.facts[0x620] = fact(0x620, "TST.B", "(A1)")
        self.assert_strong_boundary()

    def test_replaced_register_does_not_attribute_later_read_to_old_address(self):
        self.setup_table()
        self.facts[0x604] = fact(0x604, "MOVEA.L", "D0|A1")
        self.facts[0x606] = fact(0x606, "MOVE.W", "(A1)|D2w")
        self.assert_table_closed()
        self.assert_table_open()

    def test_direct_memory_read_keeps_boundary_independent_of_lea(self):
        self.setup_table()
        self.facts[0x650] = replace(fact(0x650, "MOVE.W", "(0x302).w|D0w",
            references=(InstructionReference(0x302, "READ", 0),)), length=4)
        self.assert_strong_boundary()

    def test_pc_relative_lea_keeps_explicit_object_boundary(self):
        self.setup_table()
        self.facts[0x600] = replace(self.facts[0x600], operands="(-0x300,PC)|A1")
        self.assert_strong_boundary()

    def test_called_through_register_preserves_global_boundary(self):
        self.setup_table()
        self.facts[0x604] = replace(fact(0x604, "JMP", "(A1)"), flow_type="COMPUTED_JUMP")
        self.assertIn(0x302, absolute_referenced_addresses(self.facts))
        self.assert_table_closed()

    def test_no_handler_witness_preserves_boundary(self):
        self.setup_table()
        self.assertEqual((), discover_dispatch_table_seeds(
            self.image, self.facts, handler_validator=lambda address: False))

    def test_gap_before_first_handler_cannot_override_boundary(self):
        self.setup_table()
        data = bytearray(self.image.data)
        data[0x300:0x302] = bytes.fromhex("0020")
        data[0x320:0x322] = bytes.fromhex("4E75")
        self.image = parse_megadrive(bytes(data))
        self.assert_strong_boundary()

    def test_unknown_callee_and_stored_pointer_retain_global_boundary(self):
        for instruction in (
            replace(fact(0x604, "JSR", "(A2)"), flow_type="COMPUTED_CALL"),
            fact(0x604, "MOVE.L", "A1|(0xff1000).l"),
        ):
            with self.subTest(instruction=instruction.operands):
                self.setup_table()
                self.facts[0x604] = instruction
                self.assertIn(0x302, absolute_referenced_addresses(self.facts))
                self.assert_table_closed()

    def test_register_use_budget_does_not_remove_global_boundary(self):
        self.setup_table()
        for address in range(0x604, 0x604 + 128, 2):
            self.facts[address] = fact(address, "NOP", "")
        self.facts[0x684] = fact(0x684, "MOVE.W", "(A1)|D0w")
        self.assertIn(0x302, absolute_referenced_addresses(self.facts))
        self.assert_table_closed()

    def test_instruction_overlap_is_not_ignored_by_handler_witness(self):
        self.setup_table()
        self.facts[0x300] = replace(fact(0x300, "NOP", ""), raw=bytes.fromhex("4E71"))
        self.assert_strong_boundary()

    def test_failure_after_weak_boundary_preserves_valid_original_prefix(self):
        self.setup_table()
        self.facts[0x600] = replace(self.facts[0x600], operands="(0x304).w|A1",
            references=(InstructionReference(0x304, "DATA", 0),))
        seeds = discover_dispatch_table_seeds(
            self.image, self.facts, handler_validator=lambda address: False)
        self.assertEqual(self.targets[:2], tuple(seed.address for seed in seeds))

    def setup_conflicting_handler(self, *, known_first=True):
        self.setup_table()
        self.facts.pop(0x600)
        self.facts[0x34E] = replace(fact(0x34E, "MOVE.W", "#0x4e75|D0w"), length=4)
        if known_first:
            self.facts[0x308] = replace(fact(0x308, "RTS", ""), raw=bytes.fromhex("4E75"),
                                      flow_type="TERMINATOR")

    def test_conflicting_handler_does_not_hide_later_bounded_targets(self):
        self.setup_conflicting_handler()
        seeds = discover_dispatch_table_seeds(self.image, self.facts,
            handler_validator=lambda address: address == 0x360)
        self.assertEqual((0x308, 0x330, 0x360), tuple(seed.address for seed in seeds))
        self.assertNotIn(0x350, {seed.address for seed in seeds})
        # Ordinary pointer reporting keeps its existing conservative prefix;
        # only the seed scan may use the independently bounded suffix.
        table = _pc_word_dispatch_tables(self.image, self.facts)[0]
        self.assertEqual(self.targets[:2], tuple(e.target for e in table.candidate.entries))

    def test_conflicted_slots_remain_in_table_geometry(self):
        self.setup_conflicting_handler()
        table = _pc_word_dispatch_tables(self.image, self.facts, skip_conflicting_targets=True,
            handler_validator=lambda address: address == 0x360)[0]
        self.assertEqual(self.targets, tuple(e.target for e in table.candidate.entries))
        self.assertEqual(0x308, table.candidate.physical_end)
        self.assertEqual(frozenset({0x350}), table.excluded_targets)

    def test_conflicted_suffix_without_validator_preserves_original_prefix(self):
        self.setup_conflicting_handler()
        seeds = discover_dispatch_table_seeds(self.image, self.facts)
        self.assertEqual(self.targets[:2], tuple(seed.address for seed in seeds))

    def test_conflicted_suffix_with_invalid_handler_preserves_original_prefix(self):
        self.setup_conflicting_handler()
        seeds = discover_dispatch_table_seeds(self.image, self.facts,
            handler_validator=lambda address: False)
        self.assertEqual(self.targets[:2], tuple(seed.address for seed in seeds))

    def test_valid_suffix_handler_does_not_validate_neighbouring_data_offsets(self):
        self.setup_conflicting_handler()
        data = bytearray(self.image.data)
        targets = (0x30C, 0x330, 0x350, 0x360, 0x370, 0x380)
        for index, target in enumerate(targets):
            data[0x300 + index * 2:0x302 + index * 2] = (target - 0x300).to_bytes(2, "big")
            data[target:target + 2] = bytes.fromhex("4E75")
        self.image = parse_megadrive(bytes(data))
        self.facts.pop(0x308)
        self.facts[0x30C] = replace(fact(0x30C, "RTS", ""), raw=bytes.fromhex("4E75"),
                                  flow_type="TERMINATOR")
        seeds = discover_dispatch_table_seeds(self.image, self.facts,
            handler_validator=lambda address: address == 0x360)
        self.assertEqual((0x30C, 0x330, 0x360), tuple(seed.address for seed in seeds))

    def test_unknown_first_forward_handler_cannot_use_later_known_rts_as_bound(self):
        self.setup_conflicting_handler(known_first=False)
        self.facts[0x360] = replace(fact(0x360, "RTS", ""), raw=bytes.fromhex("4E75"),
                                  flow_type="TERMINATOR")
        seeds = discover_dispatch_table_seeds(self.image, self.facts, handler_validator=lambda address: True)
        self.assertEqual(self.targets[:2], tuple(seed.address for seed in seeds))

    def test_gap_after_conflicting_table_restores_original_prefix(self):
        self.setup_conflicting_handler(known_first=False)
        data = bytearray(self.image.data)
        data[0x300:0x302] = bytes.fromhex("0010")
        data[0x310:0x312] = bytes.fromhex("4E75")
        self.image = parse_megadrive(bytes(data))
        self.facts[0x310] = replace(fact(0x310, "RTS", ""), raw=bytes.fromhex("4E75"),
                                  flow_type="TERMINATOR")
        seeds = discover_dispatch_table_seeds(self.image, self.facts, handler_validator=lambda address: True)
        self.assertEqual((0x310, 0x330), tuple(seed.address for seed in seeds))

    def test_hard_data_boundary_after_conflict_still_ends_scan(self):
        self.setup_conflicting_handler()
        self.facts[0x660] = fact(0x660, "MOVE.W", "(0x306).w|D0w",
            references=(InstructionReference(0x306, "READ", 0),))
        seeds = discover_dispatch_table_seeds(self.image, self.facts, handler_validator=lambda address: True)
        self.assertEqual(self.targets[:2], tuple(seed.address for seed in seeds))


if __name__ == "__main__":
    unittest.main()
