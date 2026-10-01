from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from retrolarium_kit.m68k_packed import discover_packed_orphan_closure, _call_continuations, _complete_cfg
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_emit import _asm_instruction
from retrolarium_kit.facts import InstructionReference
from test_megadrive import cartridge
from test_m68k_unused import instruction


class PackedClosureTests(unittest.TestCase):
    def setUp(self):
        self.known = {
            0x200: instruction(0x200, "4e75", "RTS", flow="TERMINATOR"),
            0x220: instruction(0x220, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.decoded = {
            0x202: instruction(0x202, "7001", "MOVEQ", "0x1|D0"),
            0x204: instruction(0x204, "4e75", "RTS", flow="TERMINATOR"),
            0x206: instruction(0x206, "5240", "ADDQ.W", "0x1|D0w"),
            0x208: instruction(0x208, "6016", "BRA.B", "0x220", "UNCONDITIONAL_JUMP", (0x220,)),
            0x20A: instruction(0x20A, "7202", "MOVEQ", "0x2|D1"),
            0x20C: instruction(0x20C, "4e75", "RTS", flow="TERMINATOR"),
        }

    def discover(self, **kwargs):
        data = bytearray(cartridge(size=0x800))
        for fact in (*self.known.values(), *self.decoded.values()):
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        return [c.address for c in discover_packed_orphan_closure(
            parse_megadrive(bytes(data)), self.known, self.decoded,
            render_instruction=_asm_instruction, **kwargs)]

    def test_multiple_adjacent_routines_and_tail_jump_in_one_batch(self):
        result = self.discover()
        self.assertTrue({0x202, 0x206, 0x20A} <= set(result))

    def test_no_resynchronization_after_unknown_bytes(self):
        del self.decoded[0x204]
        self.assertEqual([0x202], self.discover())

    def test_data_use_or_z80_copy_blocks_expansion(self):
        self.assertEqual([0x202], self.discover(protected_ranges=((0x202, 0x210),)))
        self.known[0x220] = replace(self.known[0x220],
                                  references=(InstructionReference(0x203, "READ", 0),))
        self.assertEqual([0x202], self.discover())

    def test_branch_into_operand_and_closed_loop_block_expansion(self):
        self.decoded[0x202] = instruction(0x202, "6001", "BRA.B", "0x205", "UNCONDITIONAL_JUMP", (0x205,))
        self.assertFalse(self.discover())
        self.decoded[0x202] = instruction(0x202, "60fe", "BRA.B", "0x202", "UNCONDITIONAL_JUMP", (0x202,))
        self.assertEqual([0x202], self.discover())

    def test_suppressed_call_continuation_requires_complete_cfg(self):
        self.known[0x200] = instruction(0x200, "4eb900000240", "JSR", "0x240.l",
                                      "CALL_TERMINATOR", (0x240,))
        self.known[0x240] = instruction(0x240, "4e75", "RTS", flow="TERMINATOR")
        self.decoded = {
            0x206: instruction(0x206, "7001", "MOVEQ", "0x1|D0"),
            0x208: instruction(0x208, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.assertIn(0x206, self.discover())
        del self.decoded[0x208]
        data = bytearray(cartridge(size=0x800))
        for fact in (*self.known.values(), *self.decoded.values()):
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        image = parse_megadrive(bytes(data))
        candidate = next(_call_continuations(self.known, image))
        self.assertFalse(_complete_cfg(image, candidate, self.known, self.decoded,
                                       (), _asm_instruction, ()))

    def test_no_return_jump_or_data_does_not_seed_continuation(self):
        self.known[0x200] = instruction(0x200, "4ef900000240", "JMP", "0x240.l",
                                      "CALL_TERMINATOR", (0x240,))
        self.known[0x240] = instruction(0x240, "4e75", "RTS", flow="TERMINATOR")
        self.decoded = {
            0x206: instruction(0x206, "7001", "MOVEQ", "0x1|D0"),
            0x208: instruction(0x208, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.assertFalse(list(_call_continuations(self.known, parse_megadrive(cartridge(size=0x800)))))
        self.known[0x200] = replace(self.known[0x200], raw=bytes.fromhex("4eb900000240"),
                                  mnemonic="JSR")
        data = bytearray(cartridge(size=0x800))
        for fact in (*self.known.values(), *self.decoded.values()):
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        image = parse_megadrive(bytes(data))
        candidate = next(_call_continuations(self.known, image))
        self.assertFalse(_complete_cfg(image, candidate, self.known, self.decoded,
                                       ((0x206, 0x210),), _asm_instruction, ()))
        self.assertFalse(_complete_cfg(image, candidate, self.known, self.decoded,
                                       (), _asm_instruction, (0x206,)))

    def test_large_gap_requires_complete_prefix_with_known_code_link(self):
        del self.known[0x220]
        self.known[0xB00] = instruction(0xB00, "4e75", "RTS", flow="TERMINATOR")
        self.known[0x200] = instruction(0x200, "4ed5", "JMP", "(A5)", "COMPUTED_JUMP")
        self.decoded = {
            0x202: instruction(0x202, "7001", "MOVEQ", "0x1|D0"),
            0x204: instruction(0x204, "4e95", "JSR", "(A5)", "COMPUTED_CALL"),
            0x206: instruction(0x206, "7202", "MOVEQ", "0x2|D1"),
            0x208: instruction(0x208, "4ef900000b00", "JMP", "0xb00.l", "UNCONDITIONAL_JUMP", (0xB00,)),
        }
        data = bytearray(cartridge(size=0xC00))
        for fact in (*self.known.values(), *self.decoded.values()):
            data[fact.cpu_address:fact.cpu_address + fact.length] = fact.raw
        image = parse_megadrive(bytes(data))
        discover = lambda: discover_packed_orphan_closure(image, self.known, self.decoded,
                                                         render_instruction=_asm_instruction)
        self.assertIn(0x202, [candidate.address for candidate in discover()])
        del self.decoded[0x206]
        self.assertNotIn(0x202, [candidate.address for candidate in discover()])

    def test_signature_after_local_data_requires_full_function_and_known_callee(self):
        self.decoded = {
            0x20A: instruction(0x20A, "303c0001", "MOVE.W", "#0x1|D0w"),
            0x20E: instruction(0x20E, "61000010", "BSR.W", "0x220", "UNCONDITIONAL_CALL", (0x220,)),
            0x212: instruction(0x212, "7202", "MOVEQ", "0x2|D1"),
            0x214: instruction(0x214, "4e75", "RTS", flow="TERMINATOR"),
        }
        self.assertIn(0x20A, self.discover())
        self.assertNotIn(0x20A, self.discover(protected_ranges=((0x20A, 0x216),)))
        self.decoded[0x20E] = replace(self.decoded[0x20E], flows=(0x280,))
        self.assertNotIn(0x20A, self.discover())
        self.decoded[0x20E] = instruction(0x20E, "4e714e71", "NOP")
        self.assertNotIn(0x20A, self.discover())

    def test_adjacent_function_is_validated_before_its_interior_signature(self):
        self.decoded = {
            0x202: instruction(0x202, "7001", "MOVEQ", "#0x1|D0"),
            0x204: instruction(0x204, "303c0001", "MOVE.W", "#0x1|D0w"),
            0x208: instruction(0x208, "61000016", "BSR.W", "0x220", "UNCONDITIONAL_CALL", (0x220,)),
            0x20C: instruction(0x20C, "7202", "MOVEQ", "#0x2|D1"),
            0x20E: instruction(0x20E, "4e75", "RTS", flow="TERMINATOR"),
        }
        roots = self.discover()
        self.assertIn(0x202, roots)
        self.assertNotIn(0x204, roots)

    def test_missing_head_joins_a_known_function_tail_without_local_rts(self):
        self.known[0x20A] = instruction(0x20A, "4e75", "RTS", flow="TERMINATOR")
        self.decoded = {
            0x202: instruction(0x202, "7001", "MOVEQ", "#0x1|D0"),
            0x204: instruction(0x204, "7202", "MOVEQ", "#0x2|D1"),
            0x206: instruction(0x206, "7403", "MOVEQ", "#0x3|D2"),
            0x208: instruction(0x208, "7604", "MOVEQ", "#0x4|D3"),
        }
        self.assertIn(0x202, self.discover())


if __name__ == "__main__":
    unittest.main()
