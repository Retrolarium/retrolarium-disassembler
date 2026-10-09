from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_disasm.facts import InstructionReference
from retrolarium_disasm.m68k.repair.unused import (
    discover_validated_unused_candidates, validate_unused_fragment,
)
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disasm.megadrive.emit import _asm_instruction
from test_megadrive import cartridge
from test_megadrive_z80 import fact


def instruction(address, raw, mnemonic, operands="", flow="FALL_THROUGH", flows=()):
    payload = bytes.fromhex(raw)
    return replace(fact(address, mnemonic, operands, flows=flows),
                   raw=payload, length=len(payload), flow_type=flow)


class UnusedCodeTests(unittest.TestCase):
    def setUp(self):
        self.previous = instruction(0x200, "4e75", "RTS", flow="TERMINATOR")
        self.body = (
            instruction(0x202, "7001", "MOVEQ", "#0x1|D0"),
            instruction(0x204, "4e71", "NOP"),
            instruction(0x206, "5240", "ADDQ.W", "0x1|D0w"),
            instruction(0x208, "4e75", "RTS", flow="TERMINATOR"),
        )
        self.following = instruction(0x20A, "4e75", "RTS", flow="TERMINATOR")

    def image(self, fragment):
        raw = bytearray(cartridge(size=0x500))
        for item in (self.previous, self.following, *fragment):
            raw[item.cpu_address:item.cpu_address + item.length] = item.raw
        return parse_megadrive(bytes(raw))

    def validate(self, fragment=None, **kwargs):
        fragment = self.body if fragment is None else fragment
        return validate_unused_fragment(
            self.image(fragment), fragment, {0x200: self.previous},
            data_addresses=kwargs.pop("data_addresses", set()),
            render_instruction=_asm_instruction, **kwargs,
        )[0]

    def test_complete_gap_becomes_candidate_without_runtime_dead_claim(self):
        accepted, rejected = discover_validated_unused_candidates(
            self.image(self.body), {0x200: self.previous, 0x20A: self.following},
            {item.cpu_address: item for item in self.body}, render_instruction=_asm_instruction,
        )
        self.assertEqual(1, len(accepted))
        self.assertEqual((0x202, 0x20A, 4),
                         (accepted[0].address, accepted[0].end, accepted[0].instruction_count))
        self.assertEqual("unknown", accepted[0].runtime_status)
        self.assertIn("nop", accepted[0].signatures)

    def test_unknown_bytes_between_instructions_rejected(self):
        self.assertEqual("fallthrough_outside_fragment", self.validate(self.body[:2] + self.body[3:]))

    def test_known_data_reference_anywhere_inside_rejected(self):
        self.assertEqual("known_data_reference", self.validate(data_addresses={0x207}))

    def test_music_table_or_z80_copy_overlap_rejected(self):
        self.assertEqual("known_data_range", self.validate(protected_ranges=((0x206, 0x230),)))

    def test_opcode_markers_in_immediate_are_not_signatures(self):
        body = (
            instruction(0x202, "203c4e714e75", "MOVE.L", "#0x4e714e75|D0"),
            instruction(0x208, "5240", "ADDQ.W", "0x1|D0w"),
            instruction(0x20A, "7201", "MOVEQ", "#0x1|D1"),
            instruction(0x20C, "4e75", "RTS", flow="TERMINATOR"),
        )
        self.assertEqual("insufficient_boundary_signatures", self.validate(body))

    def test_nop_rts_padding_rejected(self):
        body = tuple(instruction(0x202 + i * 2, "4e71", "NOP") for i in range(4)) + (
            instruction(0x20A, "4e75", "RTS", flow="TERMINATOR"),)
        self.assertEqual("insufficient_instruction_variety", self.validate(body))

    def test_small_data_header_before_real_code_is_not_promoted(self):
        body = (
            instruction(0x202, "0004003c", "ORI.B", "#0x3c|D4b"),
            instruction(0x206, "7001", "MOVEQ", "#0x1|D0"),
            instruction(0x208, "4e71", "NOP"),
            instruction(0x20A, "4e75", "RTS", flow="TERMINATOR"),
        )
        self.assertEqual("ambiguous_ori_entry", self.validate(body))

    def test_branch_into_operand_rejected(self):
        body = (
            instruction(0x202, "6603", "BNE.B", "0x207", "CONDITIONAL_JUMP", (0x207,)),
            *self.body[1:],
        )
        self.assertEqual("branch_outside_fragment_or_into_operand", self.validate(body))

    def test_computed_jump_and_unknown_call_rejected(self):
        computed = instruction(0x206, "4ed0", "JMP", "(A0)", "COMPUTED_JUMP")
        self.assertEqual("unresolved_or_exceptional_flow", self.validate(self.body[:2] + (computed, self.body[-1])))
        call = instruction(0x206, "4eb900000400", "JSR", "(0x400).l", "UNCONDITIONAL_CALL", (0x400,))
        tail = instruction(0x20C, "4e75", "RTS", flow="TERMINATOR")
        self.assertEqual("unproven_call_target", self.validate(self.body[:2] + (call, tail)))

    def test_rte_does_not_satisfy_rts_rule(self):
        rte = instruction(0x208, "4e73", "RTE", flow="TERMINATOR")
        self.assertEqual("no_final_rts", self.validate(self.body[:-1] + (rte,)))

    def test_formatter_fallback_is_rejected(self):
        # Noncanonical immediate upper byte cannot be emitted byte-exactly as BTST.
        body = (
            instruction(0x202, "0800ff00", "BTST.L", "#0x0|D0"),
            instruction(0x206, "4e71", "NOP"),
            instruction(0x208, "7001", "MOVEQ", "#0x1|D0"),
            instruction(0x20A, "4e75", "RTS", flow="TERMINATOR"),
        )
        self.assertEqual("requires_data_directive", self.validate(body))

    def test_early_return_bypassed_by_local_branch_is_supported(self):
        body = (
            instruction(0x202, "6606", "BNE.B", "0x20a", "CONDITIONAL_JUMP", (0x20A,)),
            instruction(0x204, "7001", "MOVEQ", "#0x1|D0"),
            instruction(0x206, "4e71", "NOP"),
            instruction(0x208, "4e75", "RTS", flow="TERMINATOR"),
            instruction(0x20A, "5240", "ADDQ.W", "0x1|D0w"),
            instruction(0x20C, "4e71", "NOP"),
            instruction(0x20E, "4e75", "RTS", flow="TERMINATOR"),
        )
        self.assertIsNone(self.validate(body))
        following = instruction(0x210, "4e75", "RTS", flow="TERMINATOR")
        accepted, _ = discover_validated_unused_candidates(
            self.image(body), {0x200: self.previous, 0x210: following},
            {item.cpu_address: item for item in body}, render_instruction=_asm_instruction,
        )
        self.assertEqual(0x210, accepted[0].end)

    def test_data_reference_prevents_skipping_to_later_code_looking_bytes(self):
        reader = replace(self.previous, operands="(0x204).l|D0",
                         references=(InstructionReference(0x204, "READ", 0),))
        accepted, rejected = discover_validated_unused_candidates(
            self.image(self.body), {0x200: reader, 0x20A: self.following},
            {item.cpu_address: item for item in self.body}, render_instruction=_asm_instruction,
        )
        self.assertFalse(accepted)


if __name__ == "__main__":
    unittest.main()
