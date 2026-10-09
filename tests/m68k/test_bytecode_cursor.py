from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.bytecode_cursor import (
    discover_bytecode_callbacks as discover, _absolute_address as absolute,
    discover_bytecode_cursor_seeds,
)
from m68k.builders import instruction
from megadrive.builders import cartridge
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.facts import InstructionReference


def fixture():
    facts = [
        instruction(0x200, '23fc0000070000ffe000', 'MOVE.L', '#0x700|(0x00ffe000).l'),
        instruction(0x220, '207900ffe000', 'MOVEA.L', '(0x00ffe000).l|A0'),
        instruction(0x226, '3218', 'MOVE.W', '(A0)+|D1w'),
        instruction(0x228, '3018', 'MOVE.W', '(A0)+|D0w'),
        instruction(0x22A, '23c800ffe000', 'MOVE.L', 'A0|(0x00ffe000).l'),
        instruction(0x230, 'e541', 'ASL.W', '#0x2|D1w'),
        instruction(0x232, '207b104c', 'MOVEA.L', '(0x280,PC,D1w*0x1)|A0'),
        instruction(0x236, '4e90', 'JSR', '(A0)', 'COMPUTED_CALL'),
        instruction(0x400, '207900ffe000', 'MOVEA.L', '(0x00ffe000).l|A0'),
        instruction(0x406, '4840', 'SWAP', 'D0'),
        instruction(0x408, '3018', 'MOVE.W', '(A0)+|D0w'),
        instruction(0x40A, '23c800ffe000', 'MOVE.L', 'A0|(0x00ffe000).l'),
        instruction(0x410, '2040', 'MOVEA.L', 'D0|A0'),
        instruction(0x412, '4ed0', 'JMP', '(A0)', 'COMPUTED_JUMP'),
        instruction(0x420, '207900ffe000', 'MOVEA.L', '(0x00ffe000).l|A0'),
        instruction(0x426, '4840', 'SWAP', 'D0'),
        instruction(0x428, '3010', 'MOVE.W', '(A0)|D0w'),
        instruction(0x42A, '23c000ffe000', 'MOVE.L', 'D0|(0x00ffe000).l'),
        instruction(0x430, '4e75', 'RTS', flow='TERMINATOR'),
        instruction(0x440, '4a3900ffe010', 'TST.B', '(0x00ffe010).l'),
        instruction(0x446, '6700ffd8', 'BEQ.W', '0x420', 'CONDITIONAL_JUMP', (0x420,)),
        instruction(0x44A, '54b900ffe000', 'ADDQ.L', '0x2|(0x00ffe000).l'),
        instruction(0x450, '4e75', 'RTS', flow='TERMINATOR'),
    ]
    data = bytearray(cartridge(size=0x1000))
    for selector, target in ((1, 0x400), (2, 0x420), (3, 0x440)):
        data[0x280 + selector*4:0x284 + selector*4] = target.to_bytes(4, 'big')
    data[0x700:0x706] = bytes.fromhex('000100000900')
    data[0x900:0x904] = bytes.fromhex('70004e75')
    data[0xA00:0xA04] = bytes.fromhex('72004e75')
    return data, {f.cpu_address: f for f in facts}


def image_for(data, facts):
    data = bytearray(data)
    for f in facts.values():
        data[f.cpu_address:f.cpu_address+f.length] = f.raw
    return parse_megadrive(bytes(data))


class CursorVMTests(unittest.TestCase):
    def run_model(self, data=None, facts=None, rooted=None, **kwargs):
        d, f = fixture()
        data = d if data is None else data
        facts = f if facts is None else facts
        return discover(image_for(data, facts), facts,
                        execution_facts=facts if rooted is None else rooted, **kwargs)

    def test_complete_rooted_chain_and_two_word_callback_provenance(self):
        callbacks, consumers, stops = self.run_model()
        self.assertEqual(1, len(callbacks))
        c = callbacks[0]
        self.assertEqual((0x900, 0x200, 0xFFE000, 0x700, 1),
                         (c.target, c.initialization, c.cursor, c.command, c.selector))
        self.assertEqual((2, 2, 0x280, 0x400, 0x412, 0x408, 0x702, 0x704),
                         (c.selector_width, c.parameter_width, c.table, c.handler, c.indirect,
                          c.operand_read, c.high_word_address, c.low_word_address))
        self.assertEqual(4, consumers[0].stride)
        self.assertIn('callback_return_effect_not_summarized', stops[0])

    def test_decoder_seed_has_complete_rooted_flow_evidence(self):
        data, facts = fixture()
        image = image_for(data, facts)
        self.assertEqual((), discover_bytecode_cursor_seeds(image, facts))
        seeds = discover_bytecode_cursor_seeds(image, facts, execution_facts=facts)
        self.assertEqual([0x900], [s.address for s in seeds])
        self.assertEqual('bytecode_cursor_callback', seeds[0].kind)
        self.assertEqual('proven', seeds[0].confidence)
        self.assertEqual(0x412, seeds[0].source_address)
        for fragment in ('initialization 000200', 'RAM cursor FFE000', 'command 000700',
                         'selector 1', 'handler table 000280', 'handler 000400',
                         '000702/000704', 'indirect execution 000412', 'stops after callback'):
            self.assertIn(fragment, seeds[0].evidence)

    def test_rooted_facts_must_match_the_immutable_rom(self):
        data, facts = fixture()
        original = image_for(data, facts).data
        for address in (0x200, 0x228, 0x408):
            changed = bytearray(original)
            changed[address] ^= 1
            self.assertEqual((), discover_bytecode_cursor_seeds(
                parse_megadrive(bytes(changed)), facts, execution_facts=facts))

    def test_selector_is_read_from_dispatch_table_not_a_game_opcode(self):
        data, facts = fixture()
        data[0x700:0x702] = (14).to_bytes(2, 'big')
        data[0x2B8:0x2BC] = (0x400).to_bytes(4, 'big')
        callbacks, _, _ = self.run_model(data, facts)
        self.assertEqual([(14, 0x900)], [(c.selector, c.target) for c in callbacks])

    def test_conditional_stream_transition_follows_both_bounded_branches(self):
        data, facts = fixture()
        data[0x700:0x70C] = bytes.fromhex('000300000740000100000900')
        data[0x740:0x746] = bytes.fromhex('000100000a00')
        callbacks, _, _ = self.run_model(data, facts)
        self.assertEqual({0x900, 0xA00}, {c.target for c in callbacks})

    def test_callback_does_not_imply_cursor_preservation(self):
        data, facts = fixture()
        data[0x706:0x70C] = bytes.fromhex('000100000a00')
        self.assertEqual([0x900], [c.target for c in self.run_model(data, facts)[0]])

    def test_initializer_consumer_and_handler_must_all_be_rooted(self):
        data, facts = fixture()
        self.assertEqual((), discover(image_for(data, facts), facts)[0])
        for omitted in (0x200, 0x220, 0x226, 0x228, 0x22A, 0x230, 0x232, 0x236,
                        0x400, 0x406, 0x408, 0x40A, 0x410, 0x412):
            with self.subTest(omitted=hex(omitted)):
                self.assertEqual((), self.run_model(data, facts,
                    rooted={a:f for a,f in facts.items() if a != omitted})[0])

    def test_same_register_or_wrong_width_does_not_prove_selector(self):
        data, original = fixture()
        for addr, changed in (
            (0x228, instruction(0x228, '3218', 'MOVE.W', '(A0)+|D1w')),
            (0x226, instruction(0x226, '1218', 'MOVE.B', '(A0)+|D1b')),
            (0x230, instruction(0x230, 'e341', 'ASL.W', '#0x1|D1w')),
            (0x22A, instruction(0x22A, '23c800ffe004', 'MOVE.L', 'A0|(0x00ffe004).l')),
        ):
            facts = dict(original); facts[addr] = changed
            with self.subTest(addr=hex(addr), operands=changed.operands):
                self.assertEqual((), self.run_model(data, facts)[0])

    def test_incomplete_or_clobbered_pointer_assembly_is_not_a_callback(self):
        data, original = fixture()
        for addr, changed in (
            (0x406, instruction(0x406, '4e71', 'NOP')),
            (0x408, instruction(0x408, '3418', 'MOVE.W', '(A0)+|D2w')),
            (0x410, instruction(0x410, '2041', 'MOVEA.L', 'D1|A0')),
            (0x40A, instruction(0x40A, '23c800ffe004', 'MOVE.L', 'A0|(0x00ffe004).l')),
            (0x412, instruction(0x412, '4ed1', 'JMP', '(A1)', 'COMPUTED_JUMP')),
        ):
            facts = dict(original); facts[addr] = changed
            with self.subTest(addr=hex(addr)):
                self.assertEqual((), self.run_model(data, facts)[0])

    def test_unknown_opcode_selector_or_variable_cursor_mutation_stops(self):
        data, facts = fixture()
        for selector in (0, 0x4000, 0xFFFF):
            changed = bytearray(data); changed[0x700:0x702] = selector.to_bytes(2, 'big')
            self.assertEqual((), self.run_model(changed, facts)[0])
        for first in (
            instruction(0x400, 'd1c1', 'ADDA.L', 'D1|A0'),
            instruction(0x400, '46fc0000', 'MOVE', '#0x0|SR'),
            instruction(0x400, '80fc0000', 'DIVU.W', '#0x0|D0'),
            instruction(0x400, '4e90', 'JSR', '(A0)', 'COMPUTED_CALL'),
            instruction(0x400, '4ed0', 'JMP', '(A0)', 'COMPUTED_JUMP', (0x420,)),
        ):
            changed = dict(facts); changed[0x400] = first
            self.assertEqual((), self.run_model(data, changed)[0])

    def test_an_unsupported_conditional_arm_invalidates_summary(self):
        data, facts = fixture()
        data[0x700:0x706] = bytes.fromhex('000300000740')
        data[0x740:0x746] = bytes.fromhex('000100000a00')
        facts.pop(0x450)
        self.assertEqual((), self.run_model(data, facts)[0])

    def test_music_data_reads_protection_and_instruction_interiors_win(self):
        data, facts = fixture()
        reader = instruction(0x600, '4a7900000900', 'TST.W', '(0x900).l')
        facts[0x600] = replace(reader, references=(InstructionReference(0x900, 'READ', 0),))
        self.assertEqual((), self.run_model(data, facts)[0])
        data, facts = fixture()
        facts[0x8FE] = instruction(0x8FE, '203c12345678', 'MOVE.L', '#0x12345678|D0')
        self.assertEqual((), self.run_model(data, facts)[0])
        self.assertEqual((), self.run_model(protected_ranges=((0x900, 0x902),))[0])
        self.assertEqual((), self.run_model(protected_stream_ranges=((0x700, 0x706),))[0])
        for region in ((0x700, 0x706), (0x280, 0x288)):
            self.assertEqual([0x900], [c.target for c in self.run_model(protected_ranges=(region,))[0]])
        data, facts = fixture()
        data[0x702:0x706] = (0x700).to_bytes(4, 'big')
        self.assertEqual((), self.run_model(data, facts)[0])

    def test_absolute_word_addresses_are_sign_extended_before_matching_ram(self):
        self.assertEqual(0xFFE000, absolute('(0xe000).w'))
        self.assertEqual(0xFFE000, absolute('(0xffffe000).w'))
        self.assertEqual(0xFFE000, absolute('(-0x2000).w'))
        self.assertEqual(0xE000, absolute('(0xe000).l'))

    def test_callbacks_must_be_even_rom_addresses_and_not_padding(self):
        data, facts = fixture()
        for target in (0x901, 0xFFE000, 0x100, 0x800):
            changed = bytearray(data); changed[0x702:0x706] = target.to_bytes(4, 'big')
            changed[0x800:0x802] = b'\0\0'
            self.assertEqual((), self.run_model(changed, facts)[0])

    def test_loops_and_command_budget_terminate_without_speculative_resync(self):
        data, facts = fixture()
        data[0x700:0x706] = bytes.fromhex('000200000700')
        self.assertEqual((), self.run_model(data, facts)[0])
        data[0x700:0x706] = bytes.fromhex('000200000720')
        data[0x720:0x726] = bytes.fromhex('000200000740')
        data[0x740:0x746] = bytes.fromhex('000100000a00')
        callbacks, _, stops = self.run_model(data, facts, max_commands=2)
        self.assertEqual((), callbacks)
        self.assertTrue(any(s[-1] == 'command_limit' for s in stops))


if __name__ == '__main__':
    unittest.main()
