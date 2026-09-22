from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.m68k_abstract import (
    AbstractState,
    AbstractValue,
    TruthValue,
    ValueKind,
    discover_packed_orphan_candidates,
    discover_ram_handler_candidates,
    interpret_known_cfg,
    transfer_instruction,
)
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class M68kAbstractTests(unittest.TestCase):
    def test_join_preserves_small_sets_and_widens_growing_ranges(self) -> None:
        first = AbstractValue.small_set({0, 4})
        second = AbstractValue.small_set({8, 12})
        joined = first.join(second)
        self.assertEqual(ValueKind.SMALL_SET, joined.kind)
        self.assertEqual((0, 4, 8, 12), joined.values)

        interval = AbstractValue.interval(4, 12, 4)
        widened = interval.widen(AbstractValue.interval(0, 16, 4))
        self.assertEqual(ValueKind.RANGE, widened.kind)
        self.assertEqual((0, 0xFFFFFFFF, 4), (
            widened.lower, widened.upper, widened.step
        ))

    def test_state_join_merges_registers_and_drops_one_sided_memory(self) -> None:
        left = (
            AbstractState.initial()
            .with_register("d0", AbstractValue.constant(4))
            .with_memory(0xFFFA7E, AbstractValue.constant(0x10E88))
        )
        right = AbstractState.initial().with_register(
            "d0", AbstractValue.constant(8)
        )
        joined = left.join(right)

        self.assertEqual((4, 8), joined.register("d0").values)
        self.assertEqual((), joined.memory)

    def test_finds_rom_addresses_written_to_work_ram(self) -> None:
        payload = bytearray(cartridge(size=0x12000))
        payload[30 * 4:30 * 4 + 4] = (0xFFFA7C).to_bytes(4, "big")
        image = parse_megadrive(bytes(payload))
        instruction = replace(
            fact(0x10004, "MOVE.L", "#0x10e88|(0xfffffa7e).w"),
            raw=bytes.fromhex("21 FC 00 01 0E 88 FA 7E"),
            length=8,
        )
        candidates = discover_ram_handler_candidates(
            image, {instruction.physical_offset: instruction}
        )

        self.assertEqual(1, len(candidates))
        self.assertEqual(0x10E88, candidates[0].address)
        self.assertEqual(0xFFFA7E, candidates[0].storage_address)
        self.assertEqual("proven", candidates[0].confidence)

    def test_small_bitmask_preserves_exact_selector_values(self) -> None:
        masked = AbstractValue.unknown().bitwise_and(0xC)

        self.assertEqual((0, 4, 8, 12), masked.values)

    def test_move_reads_memory_value_instead_of_treating_address_as_value(self) -> None:
        instruction = fact(0x200, "MOVE.W", "(0xffffd2a6).w|D0w")

        state = transfer_instruction(instruction, AbstractState.initial())

        self.assertEqual(ValueKind.UNKNOWN, state.register("d0").kind)

    def test_moveq_and_compare_update_condition_codes(self) -> None:
        move = fact(0x200, "MOVEQ", "0x0|D0")
        moved = transfer_instruction(move, AbstractState.initial())

        self.assertEqual(TruthValue.TRUE, moved.flag("Z"))
        self.assertEqual(TruthValue.FALSE, moved.flag("N"))
        self.assertEqual(TruthValue.FALSE, moved.flag("V"))
        self.assertEqual(TruthValue.FALSE, moved.flag("C"))
        self.assertEqual(TruthValue.UNKNOWN, moved.flag("X"))

        compare = fact(0x202, "CMPI.W", "#0x0|D0w")
        compared = transfer_instruction(compare, moved)
        self.assertEqual(TruthValue.TRUE, compared.flag("Z"))
        self.assertEqual(TruthValue.FALSE, compared.flag("C"))

    def test_and_with_constant_mask_preserves_possible_submasks(self) -> None:
        instruction = fact(0x200, "AND.W", "(0x3c,A0)|D0w")
        initial = AbstractState.initial().with_register(
            "d0", AbstractValue.constant(0x7C)
        )

        state = transfer_instruction(instruction, initial)

        self.assertEqual(ValueKind.SMALL_SET, state.register("d0").kind)
        self.assertEqual(32, len(state.register("d0").values))
        self.assertEqual((0, 0x7C), (
            state.register("d0").values[0], state.register("d0").values[-1]
        ))

    def test_finds_short_packed_function_after_return_but_rejects_table(self) -> None:
        payload = bytearray(cartridge(size=0x500))
        payload[0x202:0x208] = bytes.fromhex("70 04 4E 71 4E 75")
        payload[0x20A:0x210] = bytes.fromhex("00 01 00 03 00 07")
        image = parse_megadrive(bytes(payload))
        first_return = replace(
            fact(0x200, "RTS", ""),
            raw=bytes.fromhex("4E 75"),
            flow_type="TERMINATOR",
        )
        second_return = replace(
            fact(0x208, "RTS", ""),
            raw=bytes.fromhex("4E 75"),
            flow_type="TERMINATOR",
            references=(InstructionReference(0x20A, "DATA", 0),),
        )
        known_after_table = fact(0x210, "NOP", "")

        candidates = discover_packed_orphan_candidates(image, {
            item.physical_offset: item
            for item in (
                first_return, second_return, known_after_table
            )
        })

        self.assertEqual((0x202,), tuple(item.address for item in candidates))

    def test_packed_orphan_accepts_cmpi_entry_with_later_return(self) -> None:
        payload = bytearray(cartridge(size=0x500))
        payload[0x202:0x220] = bytes.fromhex(
            "0C 42 00 0F 67 08 70 01 51 C8 FF FC "
            "60 02 4E 71 4E 75 4E 71 4E 71 4E 71 4E 71 4E 71 4E 71"
        )
        image = parse_megadrive(bytes(payload))
        preceding = replace(
            fact(0x200, "BRA.B", "0x000001f0", flows=(0x1F0,)),
            raw=bytes.fromhex("60 EE"),
            flow_type="UNCONDITIONAL_JUMP",
        )
        following = fact(0x220, "NOP", "")

        candidates = discover_packed_orphan_candidates(image, {
            item.physical_offset: item for item in (preceding, following)
        })

        self.assertEqual((0x202,), tuple(item.address for item in candidates))

    def test_interpreter_resolves_register_indirect_jump(self) -> None:
        image = parse_megadrive(cartridge(size=0x500))
        load = replace(
            fact(0x200, "LEA", "(0x300).l|A3"),
            raw=image.data[0x200:0x206],
            length=6,
            flow_type="FALL_THROUGH",
        )
        jump = replace(
            fact(0x206, "JMP", "(A3)"),
            raw=image.data[0x206:0x208],
            length=2,
            flow_type="COMPUTED_JUMP",
        )
        result = interpret_known_cfg(
            image, {load.physical_offset: load, jump.physical_offset: jump}
        )

        self.assertEqual(1, len(result.indirect_edges))
        self.assertEqual(0x206, result.indirect_edges[0].source_address)
        self.assertEqual(0x300, result.indirect_edges[0].target_address)

    def test_interpreter_resolves_pc_indexed_call_from_masked_register(self) -> None:
        payload = bytearray(cartridge(size=0x500))
        for target in (0x220, 0x224, 0x228, 0x22C):
            payload[target:target + 4] = bytes.fromhex("60 00 00 02")
        image = parse_megadrive(bytes(payload))
        mask = replace(
            fact(0x200, "ANDI.W", "#0xc|D0w"),
            raw=bytes.fromhex("02 40 00 0C"),
            length=4,
            flow_type="FALL_THROUGH",
        )
        call = replace(
            fact(0x204, "JSR", "(0x220,PC,D0w*0x1)"),
            raw=bytes.fromhex("4E BB 00 1A"),
            length=4,
            flow_type="COMPUTED_CALL",
        )
        result = interpret_known_cfg(
            image, {mask.physical_offset: mask, call.physical_offset: call}
        )

        self.assertEqual(
            (0x220, 0x224, 0x228, 0x22C),
            tuple(edge.target_address for edge in result.indirect_edges),
        )
        self.assertEqual(
            {"proven"},
            {edge.confidence for edge in result.indirect_edges},
        )

    def test_known_branch_outcome_keeps_both_cfg_successors(self) -> None:
        image = parse_megadrive(cartridge(size=0x500))
        move = replace(
            fact(0x200, "MOVEQ", "0x0|D0"),
            raw=bytes.fromhex("70 00"),
        )
        branch = replace(
            fact(0x202, "BEQ.B", "0x00000208", flows=(0x208,)),
            raw=bytes.fromhex("67 04"),
            flow_type="CONDITIONAL_JUMP",
        )
        fallthrough = replace(
            fact(0x204, "RTS", ""),
            raw=bytes.fromhex("4E 75"),
            flow_type="TERMINATOR",
        )
        target = replace(
            fact(0x208, "RTS", ""),
            raw=bytes.fromhex("4E 75"),
            flow_type="TERMINATOR",
        )

        result = interpret_known_cfg(image, {
            item.physical_offset: item
            for item in (move, branch, fallthrough, target)
        })

        self.assertIn(0x204, result.reached_addresses)
        self.assertIn(0x208, result.reached_addresses)
        self.assertEqual(TruthValue.TRUE, result.branch_decisions[0].outcome)

    def test_direct_calls_jumps_dbcc_and_returns_shape_cfg(self) -> None:
        image = parse_megadrive(cartridge(size=0x500))

        def control(
            address: int,
            mnemonic: str,
            operands: str,
            length: int,
            flow_type: str,
            flows: tuple[int, ...] = (),
        ):
            return replace(
                fact(address, mnemonic, operands, flows=flows),
                raw=bytes(length),
                length=length,
                flow_type=flow_type,
            )

        instructions = (
            control(
                0x200, "BSR.W", "0x00000220", 4,
                "UNCONDITIONAL_CALL", (0x220,),
            ),
            control(
                0x204, "JSR", "(0x224).l", 6,
                "UNCONDITIONAL_CALL", (0x224,),
            ),
            control(
                0x20A, "DBF", "D0w|0x00000218", 4,
                "CONDITIONAL_JUMP", (0x218,),
            ),
            control(
                0x20E, "BRA.W", "0x00000230", 4,
                "UNCONDITIONAL_JUMP", (0x230,),
            ),
            control(
                0x218, "JMP", "(0x234).l", 6,
                "UNCONDITIONAL_JUMP", (0x234,),
            ),
            control(0x220, "RTS", "", 2, "TERMINATOR"),
            control(0x224, "RTE", "", 2, "TERMINATOR"),
            control(0x230, "RTS", "", 2, "TERMINATOR"),
            control(0x234, "RTE", "", 2, "TERMINATOR"),
        )

        result = interpret_known_cfg(image, {
            item.physical_offset: item for item in instructions
        })

        self.assertTrue(
            {0x200, 0x204, 0x20A, 0x20E, 0x218, 0x220, 0x224,
             0x230, 0x234} <= set(result.reached_addresses)
        )
        self.assertNotIn(0x212, result.reached_addresses)


if __name__ == "__main__":
    unittest.main()
