from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from retrolarium_kit.m68k_dispatch_witness import make_dispatch_handler_validator
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_kit.megadrive_emit import _asm_instruction
from test_megadrive import cartridge
from test_m68k_unused import instruction


class TailBranchMetadataTests(unittest.TestCase):
    def setUp(self):
        self.body = {
            0x400: instruction(0x400, "7001", "MOVEQ", "0x1|D0"),
            0x402: instruction(0x402, "4a40", "TST.W", "D0w"),
            0x404: instruction(0x404, "5240", "ADDQ.W", "0x1|D0w"),
            0x406: instruction(0x406, "600000f8", "BRA.W", "0x500",
                               "CALL_TERMINATOR", (0x500,)),
        }
        self.known = {a: instruction(a, "4e75", "RTS", flow="TERMINATOR")
                      for a in (0x300, 0x420, 0x500, 0x502)}

    def validate(self):
        data = bytearray(cartridge(size=0x800))
        for fact in (*self.body.values(), *self.known.values()):
            data[fact.cpu_address:fact.cpu_address + len(fact.raw)] = fact.raw
        return make_dispatch_handler_validator(
            parse_megadrive(bytes(data)), self.known, self.body,
            render_instruction=_asm_instruction)(0x400)

    def test_word_bra_tail_with_callee_no_return_annotation(self):
        self.assertTrue(self.validate())

    def test_quackshot_tail_metadata_in_a_complete_handler(self):
        # Real QuackShot fact: $18D90 6000 0C36 -> $199C8, CALL_TERMINATOR.
        self.body = {f.cpu_address: f for f in (
            instruction(0x18D8A, "7001", "MOVEQ", "0x1|D0"),
            instruction(0x18D8C, "4a40", "TST.W", "D0w"),
            instruction(0x18D8E, "5240", "ADDQ.W", "0x1|D0w"),
            instruction(0x18D90, "60000c36", "BRA.W", "0x000199c8",
                        "CALL_TERMINATOR", (0x199C8,)),
        )}
        known = {0x199C8: instruction(0x199C8, "4e75", "RTS", flow="TERMINATOR")}
        data = bytearray(cartridge(size=0x20000))
        for fact in (*self.body.values(), *known.values()):
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        validator = make_dispatch_handler_validator(
            parse_megadrive(bytes(data)), known, self.body, render_instruction=_asm_instruction)
        self.assertTrue(validator(0x18D8A))

    def test_short_and_negative_word_displacements(self):
        for raw, mnemonic, target in (("6018", "BRA.B", 0x420),
                                     ("6000fef8", "BRA.W", 0x300)):
            with self.subTest(raw=raw):
                self.body[0x406] = instruction(0x406, raw, mnemonic, f"0x{target:x}",
                                                "CALL_TERMINATOR", (target,))
                self.assertTrue(self.validate())

    def test_inconsistent_operand_or_flow_cannot_select_another_rooted_target(self):
        original = self.body[0x406]
        for changes in ({"operands": "0x502"}, {"flows": (0x502,)},
                        {"flows": (0x500, 0x502)}, {"flows": ()}):
            with self.subTest(changes=changes):
                self.body[0x406] = replace(original, **changes)
                self.assertFalse(self.validate())

    def test_truncated_extended_or_wrong_opcode_is_not_a_tail_bra(self):
        for raw in ("6000", "600000f80000", "6618"):
            with self.subTest(raw=raw):
                self.body[0x406] = instruction(0x406, raw, "BRA.W", "0x500",
                                                "CALL_TERMINATOR", (0x500,))
                self.assertFalse(self.validate())


if __name__ == "__main__":
    unittest.main()
