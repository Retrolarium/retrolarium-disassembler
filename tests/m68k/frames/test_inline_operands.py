from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.frames.inline_operands import (
    discover_inline_operand_calls, inline_operand_length, InlineOperandProver,
)
from retrolarium_disassembler.m68k.frames import inline_operands as inline_module
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from m68k.builders import instruction


# A frame-based handler in the style of a software floating-point runtime:
# bit 7 of the inline op byte selects a four-byte immediate after the op word.
HANDLER = bytes.fromhex(
    "4e560000"      # link    a6,#0
    "48e78080"      # movem.l d0/a0,-(sp)
    "206e0004"      # movea.l 4(a6),a0      ; saved return PC
    "1010"          # move.b  (a0),d0       ; upper bits of d0 stay unknown
    "7202"          # moveq   #2,d1
    "08000007"      # btst    #7,d0
    "6702"          # beq.s   +2
    "5841"          # addq.w  #4,d1
    "d3ae0004"      # add.l   d1,4(a6)      ; skip the operands
    "4cdf0101"      # movem.l (sp)+,d0/a0
    "4e5e"          # unlk    a6
    "4e75"          # rts
)
CALLER = bytes.fromhex(
    "4eb900000400"  # 0x200 jsr $400
    "800012345678"  # 0x206 op word with immediate
    "4e71"          # 0x20c nop
    "4eb900000400"  # 0x20e jsr $400
    "0000"          # 0x214 op word alone
    "4e75"          # 0x216 rts
)


class InlineOperandTests(unittest.TestCase):
    def build(self, handler=HANDLER, at=0x400):
        data = bytearray(cartridge(size=0x800))
        data[0x200:0x200 + len(CALLER)] = CALLER
        data[at:at + len(handler)] = handler
        self.image = parse_megadrive(bytes(data))
        self.facts = {0x200: instruction(0x200, "4eb900000400", "JSR", "0x400.l",
                                         "UNCONDITIONAL_CALL", (0x400,))}

    def calls(self):
        return [(c.call_address, c.data_address, c.continuation, c.handler, c.data_size)
                for c in discover_inline_operand_calls(self.image, self.facts)]

    def test_length_follows_the_inline_operand_bytes(self):
        self.build()
        self.assertEqual(6, inline_operand_length(self.image, 0x400, 0x206))
        self.assertEqual(2, inline_operand_length(self.image, 0x400, 0x214))

    def test_chain_of_calls_resolves_from_one_rooted_site(self):
        self.build()
        self.assertEqual([(0x200, 0x206, 0x20C, 0x400, 6), (0x20E, 0x214, 0x216, 0x400, 2)],
                         self.calls())

    def test_ordinary_subroutine_is_not_an_operand_consumer(self):
        self.build(handler=bytes.fromhex("70004e75"))
        self.assertEqual([], self.calls())

    def test_length_depending_on_unknown_ram_is_rejected(self):
        handler = bytearray(HANDLER)
        handler[12:14] = bytes.fromhex("1410")  # move.b (a0),d2; d0 stays unknown
        self.build(handler=bytes(handler))
        self.assertIsNone(inline_operand_length(self.image, 0x400, 0x206))
        self.assertEqual([], self.calls())

    def test_unsupported_instruction_rejects_instead_of_guessing(self):
        handler = bytearray(HANDLER)
        handler[22:24] = bytes.fromhex("4e40")  # trap #0 instead of addq
        self.build(handler=bytes(handler))
        self.assertIsNone(inline_operand_length(self.image, 0x400, 0x206))

    def test_operands_longer_than_the_inline_limit_are_rejected(self):
        handler = bytearray(HANDLER)
        handler[14:16] = bytes.fromhex("7228")  # moveq #40,d1
        self.build(handler=bytes(handler))
        self.assertIsNone(inline_operand_length(self.image, 0x400, 0x214))

    def test_popped_return_resumed_through_jmp(self):
        self.build(handler=bytes.fromhex(
            "225f"  # movea.l (sp)+,a1
            "3019"  # move.w  (a1)+,d0
            "4ed1"  # jmp     (a1)
        ))
        self.assertEqual(2, inline_operand_length(self.image, 0x400, 0x214))

    def test_internal_helper_calls_keep_separate_return_contexts(self):
        # Each helper call advances the caller's PC by one byte. Joining the
        # two helper invocations would lose the slot value and the proof.
        self.build(handler=bytes.fromhex(
            "2057"      # movea.l (sp),a0
            "3010"      # move.w  (a0),d0
            "6106"      # bsr.s   helper
            "6104"      # bsr.s   helper
            "4e75"      # rts
            "4e71"      # nop
            "52af0004"  # helper: addq.l #1,4(sp)
            "4e75"      # rts
        ))
        self.assertEqual(2, inline_operand_length(self.image, 0x400, 0x214))

    def test_rom_only_proofs_are_reused_across_passes_with_different_facts(self):
        self.build()
        prover = InlineOperandProver(self.image)
        with (patch.object(inline_module, '_reads_return_stream', wraps=inline_module._reads_return_stream) as probe,
              patch.object(inline_module, 'inline_operand_length', wraps=inline_operand_length) as length):
            first = discover_inline_operand_calls(self.image, self.facts, prover=prover)
            expanded = {**self.facts,
                        0x20E: instruction(0x20E, '4eb900000400', 'JSR', '0x400.l',
                                           'UNCONDITIONAL_CALL', (0x400,))}
            second = discover_inline_operand_calls(self.image, expanded, prover=prover)
            self.assertEqual(first, second)
            self.assertEqual(1, probe.call_count)
            self.assertEqual(2, length.call_count)  # Once for each distinct return PC.

    def test_rejected_length_is_cached_as_well_as_success(self):
        handler = bytearray(HANDLER)
        handler[12:14] = bytes.fromhex('1410')
        self.build(handler=bytes(handler))
        prover = InlineOperandProver(self.image)
        with patch.object(inline_module, 'inline_operand_length', wraps=inline_operand_length) as length:
            self.assertEqual((), discover_inline_operand_calls(self.image, self.facts, prover=prover))
            self.assertEqual((), discover_inline_operand_calls(self.image, self.facts, prover=prover))
            self.assertEqual(1, length.call_count)
            self.assertIn((0x400, 0x206), prover.lengths)
            self.assertIsNone(prover.lengths[(0x400, 0x206)])

    def test_prover_cannot_leak_results_to_another_rom(self):
        self.build()
        prover = InlineOperandProver(self.image)
        self.assertEqual(2, len(discover_inline_operand_calls(self.image, self.facts, prover=prover)))
        self.build(handler=bytes.fromhex('70004e75'))
        with self.assertRaisesRegex(ValueError, 'different image'):
            discover_inline_operand_calls(self.image, self.facts, prover=prover)
        self.assertEqual((), discover_inline_operand_calls(self.image, self.facts))

    def test_continuation_walk_recomputes_current_known_boundaries(self):
        self.build()
        prover = InlineOperandProver(self.image)
        barrier = instruction(0x20C, '4e71', 'NOP')
        known_barrier = {**self.facts, 0x20C: barrier}
        blocked = discover_inline_operand_calls(self.image, known_barrier, prover=prover)
        self.assertEqual([0x200], [c.call_address for c in blocked])
        expanded = discover_inline_operand_calls(self.image, self.facts, prover=prover)
        self.assertEqual([0x200, 0x20E], [c.call_address for c in expanded])
        blocked_again = discover_inline_operand_calls(self.image, known_barrier, prover=prover)
        self.assertEqual(blocked, blocked_again)


if __name__ == "__main__":
    unittest.main()
