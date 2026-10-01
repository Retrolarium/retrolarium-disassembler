from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from retrolarium_kit.m68k_word_callbacks import (
    discover_nested_word_resolver_seeds, discover_word_ram_callback_seeds,
)
from retrolarium_kit.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class WordCallbacksTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(cartridge(size=0x1000))
        for target in (0x500, 0x520):
            self.data[target:target+2] = bytes.fromhex("4e75")
        self.items = [
            fact(0x200, "MOVEQ", "0x0|D2"),
            fact(0x202, "MOVE.W", "(0xffffff90).w|D2w"),
            fact(0x204, "MOVEA.L", "D2|A3"),
            replace(fact(0x206, "JMP", "(A3)"), flow_type="COMPUTED_JUMP"),
            fact(0x300, "MOVE.W", "#0x500|(0xffffff90).w"),
            fact(0x302, "MOVE.W", "#0x520|(0xffffff90).w"),
        ]

    def seeds(self):
        return discover_word_ram_callback_seeds(parse_megadrive(bytes(self.data)),
            {f.cpu_address: f for f in self.items},
            execution_facts={f.cpu_address: f for f in self.items[:4]})

    def test_proven_zero_extended_word_slot_and_unrooted_immediate_writer(self):
        self.assertEqual([0x500, 0x520], [seed.address for seed in self.seeds()])
        self.assertTrue(all(seed.confidence == "proven" for seed in self.seeds()))

    def test_unknown_upper_word_or_different_called_register_rejected(self):
        for index, changes in ((0, {"operands": "0x1|D2"}),
                               (2, {"mnemonic": "MOVEA.W"}),
                               (3, {"operands": "(A4)"})):
            original = self.items[index]
            self.items[index] = replace(original, **changes)
            self.assertFalse(self.seeds())
            self.items[index] = original

    def test_partial_data_reads_and_unverified_writes_disqualify_slot(self):
        for extra in (fact(0x350, "MOVE.B", "#0x5|(0xffffff90).w"),
                      fact(0x350, "MOVE.W", "(0xffffff90).w|D3w"),
                      fact(0x350, "MOVE.W", "D0w|(0xffffff90).w"),
                      fact(0x350, "MOVE.W", "#0x3|(0xffffff90).w")):
            self.items.append(extra)
            self.assertFalse(self.seeds())
            self.items.pop()

    def test_null_and_tests_allowed_but_non_ram_slot_is_rejected(self):
        self.items += [fact(0x350, "CLR.W", "(0xffffff90).w"),
                       fact(0x352, "TST.W", "(0xffffff90).w")]
        self.assertEqual(2, len(self.seeds()))
        self.items = [replace(f, operands=f.operands.replace("0xffffff90", "0x700")) for f in self.items]
        self.assertFalse(self.seeds())


class NestedResolverTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(cartridge(size=0x1000))
        for i, target in enumerate((0x420, 0x440)):
            self.data[0x400+4*i:0x404+4*i] = target.to_bytes(4, "big")
        for at, targets in ((0x420, (0x500, 0x520)), (0x440, (0x540, 0x560))):
            for i, target in enumerate(targets):
                self.data[at+2*i:at+2*i+2] = target.to_bytes(2, "big")
                self.data[target:target+2] = bytes.fromhex("4e75")
        body = [
            ("MOVEQ", "0x0|D1"), ("MOVE.W", "(0xffff8f34).w|D1w"),
            ("ADD.W", "D1w|D1w"), ("ADD.W", "D1w|D1w"),
            ("MOVEA.L", "(0x0,A0,D1w*0x1)|A0"),
            ("MOVE.W", "(0xffff8f36).w|D1w"), ("ADD.W", "D1w|D1w"),
            ("MOVE.W", "(0x0,A0,D1w*0x1)|D1w"), ("MOVEA.L", "D1|A0"), ("RTS", "")]
        self.items = [fact(0x200+2*i, op, operands) for i, (op, operands) in enumerate(body)]
        self.items[-1] = replace(self.items[-1], flow_type="TERMINATOR")
        self.items += [fact(0x300, "LEA", "(0x400).l|A0"),
                       replace(fact(0x302, "JSR", "0x200", flows=(0x200,)), flow_type="UNCONDITIONAL_CALL"),
                       replace(fact(0x304, "JSR", "(A0)"), flow_type="COMPUTED_CALL"),
                       replace(fact(0x500, "RTS", ""), flow_type="TERMINATOR")]

    def seeds(self):
        return discover_nested_word_resolver_seeds(parse_megadrive(bytes(self.data)),
            {f.cpu_address: f for f in self.items})

    def test_leaf_returns_address_used_by_caller_not_data(self):
        self.assertEqual([0x500, 0x520, 0x540, 0x560], [s.address for s in self.seeds()])

    def test_requires_zero_extension_and_executable_returned_register(self):
        for index, changes in ((0, {"operands": "0x1|D1"}),
                               (8, {"operands": "D1|A1"}),
                               (9, {"mnemonic": "NOP"}),
                               (12, {"mnemonic": "MOVE.L"})):
            old = self.items[index]
            self.items[index] = replace(old, **changes)
            self.assertFalse(self.seeds())
            self.items[index] = old

    def test_requires_corroborated_code_and_keeps_tables_out_of_code(self):
        self.items.pop()
        self.assertFalse(self.seeds())
        self.items.append(fact(0x500, "RTS", ""))
        self.data[0x400:0x408] = b"\0"*8
        self.assertFalse(self.seeds())

    def test_backend_subtable_decode_does_not_hide_other_tables(self):
        self.items.append(fact(0x440, "MOVE.W", "D0w|D1w"))
        self.assertEqual([0x500, 0x520, 0x540, 0x560], [s.address for s in self.seeds()])

    def test_conflicting_handler_is_skipped_without_truncating_later_slots(self):
        self.data[0x424:0x426] = (0x580).to_bytes(2, "big")
        self.data[0x580:0x582] = bytes.fromhex("4e75")
        self.items.append(replace(fact(0x51E, "MOVE.L", "D0|D1"), length=4))
        self.assertEqual([0x500, 0x540, 0x560, 0x580], [s.address for s in self.seeds()])


if __name__ == "__main__":
    unittest.main()
