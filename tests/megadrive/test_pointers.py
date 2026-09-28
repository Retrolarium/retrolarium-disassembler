from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.facts import InstructionFact, InstructionReference
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_pointers import (
    detect_pointer_candidates,
    discover_dispatch_table_seeds,
)
from test_megadrive import cartridge
from test_megadrive_z80 import fact


def dispatch_image(*targets: int):
    data = bytearray(cartridge(size=0x800))
    data[0x300:0x320] = bytes(0x20)
    for index, target in enumerate(targets):
        offset = 0x300 + index * 4
        data[offset:offset + 4] = target.to_bytes(4, "big")
    return parse_megadrive(bytes(data))


def dispatch_facts(index_source: str = "D0w|A0") -> dict[int, InstructionFact]:
    index_mnemonic = "MOVEA.W" if index_source.startswith("D") else "LEA"
    items = (
        fact(0x200, index_mnemonic, index_source),
        replace(fact(0x202, "MOVEA.L", "(0x300,A0)|A0"), length=4),
        replace(fact(0x206, "JSR", "(A0)"), flow_type="COMPUTED_CALL"),
        replace(fact(0x208, "RTS", ""), flow_type="TERMINATOR"),
    )
    return {item.physical_offset: item for item in items}


def word_dispatch_image():
    data = bytearray(cartridge(size=0x800))
    targets = (0x340, 0x350, 0x280, 0x360)
    data[0x300:0x308] = b"".join(((target - 0x340) & 0xFFFF).to_bytes(2, "big") for target in targets)
    data[0x308:0x30A] = bytes.fromhex("FF FF")
    for target in targets:
        data[target:target + 2] = bytes.fromhex("4E75")
    items = (
        replace(fact(0x200, "MOVEA.W", "(0x300,PC,D2w*0x1)|A4"), length=4),
        replace(fact(0x204, "ADDA.L", "#0x340|A4"), length=6),
        replace(fact(0x20A, "JMP", "(A4)"), flow_type="COMPUTED_JUMP"),
    )
    return parse_megadrive(bytes(data)), {item.physical_offset: item for item in items}, targets


class MegaDrivePointerTests(unittest.TestCase):
    def test_pc_dispatch_accepts_address_register_word_indices(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)
        data = bytearray(image.data)
        for target in (0x400, 0x410, 0x420):
            data[target:target + 2] = bytes.fromhex("4E 75")
        image = parse_megadrive(bytes(data))
        facts = dispatch_facts()
        del facts[0x200]
        facts[0x202] = replace(facts[0x202], operands="(0x300,PC,A1w*0x1)|A4")
        facts[0x206] = replace(facts[0x206], operands="(A4)")
        self.assertEqual((0x400, 0x410, 0x420), tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)))
        image, facts, targets = word_dispatch_image()
        facts[0x200] = replace(facts[0x200], operands="(0x300,PC,A2w*0x1)|A4")
        self.assertEqual(targets, tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)))

    def test_relative_dispatch_stops_at_first_forward_handler_before_it_decodes(self) -> None:
        data = bytearray(cartridge(size=0x800))
        data[0x300:0x306] = bytes.fromhex("00 04 00 0A 00 08")
        data[0x30C:0x30E] = bytes.fromhex("4E 75")
        facts = {
            0x200: replace(fact(0x200, "LEA", "(0x300,PC,D2w*0x1)|A4"), length=4),
            0x204: fact(0x204, "ADDA.W", "(A4)|A4"),
            0x206: replace(fact(0x206, "JMP", "(A4)"), flow_type="COMPUTED_JUMP"),
        }
        # The first handler's $0008 opcode also looks like an offset to $30C.
        # It must never become a third table entry, even before backend decode.
        seeds = discover_dispatch_table_seeds(parse_megadrive(bytes(data)), facts)
        self.assertEqual((0x304, 0x30C), tuple(seed.address for seed in seeds))

    def test_entry_relative_dispatch_uses_each_signed_word_address_as_base(self) -> None:
        image, _, targets = word_dispatch_image()
        data = bytearray(image.data)
        data[0x300:0x308] = b"".join(((target - 0x300 - i * 2) & 0xFFFF).to_bytes(2, "big")
                                     for i, target in enumerate(targets))
        facts = {
            0x200: replace(fact(0x200, "LEA", "(0x300,PC,D2w*0x1)|A4"), length=4),
            0x204: fact(0x204, "ADDA.W", "(A4)|A4"),
            0x206: replace(fact(0x206, "JMP", "(A4)"), flow_type="COMPUTED_JUMP"),
        }
        image = parse_megadrive(bytes(data))
        self.assertEqual(targets, tuple(seed.address for seed in discover_dispatch_table_seeds(image, facts)))
        for target in targets:
            facts[target] = replace(fact(target, "RTS", ""), flow_type="TERMINATOR")
        table = next(item for item in detect_pointer_candidates(image, facts)
                     if item.candidate_id.startswith("Ptr_s16be-dispatch_entry"))
        self.assertEqual("accepted", table.status)
        self.assertEqual(targets, tuple(entry.target for entry in table.entries))
        self.assertEqual((0x300, 0x302, 0x304, 0x306), tuple(entry.base_address for entry in table.entries))
        self.assertEqual("megadrive.s16be.target-entry_address", table.schema_id)
        for mnemonic, operands in (("ADDA.L", "(A4)|A4"), ("ADDA.W", "(A3)|A4"),
                                  ("ADDA.W", "(A4)+|A4"), ("ADDA.W", "(A4)|A3")):
            with self.subTest(mnemonic=mnemonic, operands=operands):
                changed = dict(facts)
                changed[0x204] = replace(changed[0x204], mnemonic=mnemonic, operands=operands)
                self.assertEqual((), discover_dispatch_table_seeds(image, changed))

    def test_pc_indexed_long_dispatch_recovers_handlers_without_address_index_setup(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)
        facts = dispatch_facts()
        del facts[0x200]
        facts[0x202] = replace(facts[0x202], operands="(0x300,PC,D1w*0x1)|A4")
        facts[0x206] = replace(facts[0x206], operands="(A4)")
        self.assertEqual((0x400, 0x410, 0x420), tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)
        ))
        for target in (0x400, 0x410, 0x420):
            facts[target] = replace(fact(target, "RTS", ""), flow_type="TERMINATOR")
        table = next(item for item in detect_pointer_candidates(image, facts)
                     if item.candidate_id.startswith("Ptr_u32be-dispatch"))
        self.assertEqual("accepted", table.status)
        self.assertIn("pc_relative_data_register_word_index", table.evidence)

    def test_pc_indexed_long_dispatch_requires_supported_index_and_matching_jump(self) -> None:
        for operands, call in (
            ("(0x300,PC,D1l*0x1)|A4", "(A4)"),
            ("(0x300).l|A4", "(A4)"),
            ("(0x300,PC,D1w*0x1)|A4", "(A3)"),
        ):
            with self.subTest(operands=operands, call=call):
                facts = dispatch_facts()
                del facts[0x200]
                facts[0x202] = replace(facts[0x202], operands=operands)
                facts[0x206] = replace(facts[0x206], operands=call)
                self.assertEqual((), discover_dispatch_table_seeds(
                    dispatch_image(0x400, 0x410, 0x420), facts))

    def test_signed_word_dispatch_seeds_forward_and_backward_handlers(self) -> None:
        image, facts, targets = word_dispatch_image()
        self.assertEqual(targets, tuple(seed.address for seed in discover_dispatch_table_seeds(image, facts)))
        candidate = next(item for item in detect_pointer_candidates(image, facts)
                         if item.schema_id == "megadrive.s16be.target-code_base")
        self.assertEqual("candidate", candidate.status)
        self.assertEqual((0x300, 0x308), (candidate.physical_start, candidate.physical_end))
        self.assertEqual(0x340, candidate.entries[2].base_address)
        self.assertEqual(0xFF40, candidate.entries[2].raw_value)
        for target in targets:
            facts[target] = replace(fact(target, "RTS", ""), flow_type="TERMINATOR")
        candidate = next(item for item in detect_pointer_candidates(image, facts)
                         if item.schema_id == "megadrive.s16be.target-code_base")
        self.assertEqual("accepted", candidate.status)

    def test_relative_dispatch_requires_consistent_registers_and_index(self) -> None:
        for address, mnemonic, operands in (
            (0x200, "MOVEA.W", "(0x300).l|A4"),
            (0x204, "ADDA.L", "#0x340|A3"),
            (0x204, "ADDA.L", "D0|A4"),
            (0x20A, "JMP", "(A3)"),
        ):
            with self.subTest(operands=operands):
                image, facts, _ = word_dispatch_image()
                facts[address] = replace(facts[address], mnemonic=mnemonic, operands=operands)
                self.assertEqual((), discover_dispatch_table_seeds(image, facts))

    def test_relative_dispatch_does_not_swallow_forward_code_base(self) -> None:
        image, facts, _ = word_dispatch_image()
        data = bytearray(image.data)
        data[0x300:0x340] = bytes.fromhex("00 00") * 32
        seeds = discover_dispatch_table_seeds(parse_megadrive(bytes(data)), facts)
        self.assertEqual(32, len(seeds))
        self.assertEqual({0x340}, {seed.address for seed in seeds})

    def test_relative_dispatch_stops_at_invalid_or_instruction_interior_target(self) -> None:
        # Odd address, unmapped address, own table, interior of a decoded instruction.
        for raw in (0xFFFF, 0xFC00, 0xFFC4, 0xFF42):
            with self.subTest(raw=raw):
                image, facts, _ = word_dispatch_image()
                data = bytearray(image.data)
                data[0x304:0x306] = raw.to_bytes(2, "big")
                facts[0x280] = replace(fact(0x280, "NOP", ""), length=4)
                seeds = discover_dispatch_table_seeds(parse_megadrive(bytes(data)), facts)
                self.assertEqual((0x340, 0x350), tuple(seed.address for seed in seeds))

    def test_indexed_movea_dispatch_table_seeds_handler_targets(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)

        seeds = discover_dispatch_table_seeds(image, dispatch_facts())

        self.assertEqual((0x400, 0x410, 0x420), tuple(
            seed.address for seed in seeds
        ))
        self.assertEqual(
            {"indexed_pointer_table_target"}, {seed.kind for seed in seeds}
        )
        self.assertEqual({0x202}, {seed.source_address for seed in seeds})

    def test_dispatch_table_is_accepted_once_targets_decode(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)
        facts = dispatch_facts()
        undecoded = {
            item.physical_start: item
            for item in detect_pointer_candidates(image, facts)
            if item.candidate_id.startswith("Ptr_u32be-dispatch")
        }
        self.assertEqual("candidate", undecoded[0x300].status)

        for target in (0x400, 0x410, 0x420):
            facts[target] = replace(
                fact(target, "RTS", ""), flow_type="TERMINATOR"
            )
        decoded = {
            item.physical_start: item
            for item in detect_pointer_candidates(image, facts)
            if item.status == "accepted"
        }

        table = decoded[0x300]
        self.assertEqual("megadrive.u32be.absolute", table.schema_id)
        self.assertEqual(0x30C, table.physical_end)
        self.assertEqual((0x400, 0x410, 0x420), tuple(
            entry.target for entry in table.entries
        ))

    def test_dispatch_table_recovers_handlers_beyond_64_entries(self) -> None:
        data = bytearray(cartridge(size=0x1000))
        targets = tuple(0x800 + 2 * index for index in range(100))
        data[0x300:0x490] = b"".join(target.to_bytes(4, "big") for target in targets)
        data[0x490:0x494] = bytes.fromhex("4E75 4E75")
        for target in targets:
            data[target:target + 2] = bytes.fromhex("4E75")
        image = parse_megadrive(bytes(data))
        facts = dispatch_facts()
        seeds = discover_dispatch_table_seeds(image, facts)
        self.assertEqual(targets, tuple(seed.address for seed in seeds))
        facts.update({target: replace(fact(target, "RTS", ""), flow_type="TERMINATOR")
                      for target in targets})
        table = next(item for item in detect_pointer_candidates(image, facts)
                     if item.candidate_id.startswith("Ptr_u32be-dispatch"))
        self.assertEqual("accepted", table.status)
        self.assertEqual(0x490, table.physical_end)

    def test_inferred_indirect_reference_does_not_split_dispatch_table(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)
        facts = dispatch_facts()
        facts[0x210] = fact(
            0x210, "MOVE.W", "(A0)+|(A1)+",
            references=(InstructionReference(0x308, "READ", 0),),
        )
        self.assertEqual((0x400, 0x410, 0x420), tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)
        ))
        # The destination operand explicitly addresses a separate table.
        facts[0x212] = fact(
            0x212, "MOVE.W", "(A0)|(0x308).l",
            references=(InstructionReference(0x308, "DATA", 1),),
        )
        self.assertEqual((0x400, 0x410), tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)
        ))

    def test_dispatch_table_requires_data_register_index(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)

        seeds = discover_dispatch_table_seeds(
            image, dispatch_facts("(0x1000).l|A0")
        )

        self.assertEqual((), seeds)

    def test_scalar_immediates_do_not_truncate_absolute_dispatch(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420, 0x430)
        for mnemonic, operands in (
            ("MOVE.W", "#0x308|(A0)+"),
            ("MOVE.L", "#0x308|(0xe,A5)"),
            ("ANDI.W", "#0x308|D1w"),
        ):
            with self.subTest(operands=operands):
                facts = dispatch_facts()
                facts[0x210] = fact(
                    0x210, mnemonic, operands,
                    references=(InstructionReference(0x308, "DATA", 0),),
                )
                self.assertEqual((0x400, 0x410, 0x420, 0x430), tuple(
                    seed.address for seed in discover_dispatch_table_seeds(image, facts)))

        # The memory destination, unlike the literal source, names an object.
        facts[0x210] = fact(
            0x210, "MOVE.W", "#0x308|(0x308).l",
            references=(InstructionReference(0x308, "DATA", 0),
                        InstructionReference(0x308, "DATA", 1)),
        )
        self.assertEqual((0x400, 0x410), tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)))

    def test_scalar_immediate_does_not_truncate_relative_dispatch(self) -> None:
        image, facts, targets = word_dispatch_image()
        facts[0x220] = fact(
            0x220, "MOVE.W", "#0x304|(A1)+",
            references=(InstructionReference(0x304, "DATA", 0),),
        )
        self.assertEqual(targets, tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)))
        facts[0x220] = fact(
            0x220, "LEA", "(0x304).l|A1",
            references=(InstructionReference(0x304, "DATA", 0),),
        )
        self.assertEqual(targets[:2], tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)))

    def test_dispatch_table_stops_at_odd_or_out_of_rom_target(self) -> None:
        for bad_target in (0x411, 0x100, 0x10000):
            with self.subTest(target=bad_target):
                image = dispatch_image(0x400, bad_target, 0x420)
                seeds = discover_dispatch_table_seeds(image, dispatch_facts())
                self.assertEqual((), seeds)

    def test_dispatch_table_stops_before_code_and_self_targets(self) -> None:
        image = dispatch_image(0x400, 0x410, 0x420, 0x430)
        facts = dispatch_facts()
        facts[0x308] = fact(0x308, "NOP", "")
        self.assertEqual((0x400, 0x410), tuple(
            seed.address
            for seed in discover_dispatch_table_seeds(image, facts)
        ))

        image = dispatch_image(0x400, 0x410, 0x304)
        self.assertEqual((0x400, 0x410), tuple(
            seed.address
            for seed in discover_dispatch_table_seeds(image, dispatch_facts())
        ))

    def test_dispatch_table_ignores_base_register_displacement_refs(
        self,
    ) -> None:
        image = dispatch_image(0x400, 0x400, 0x410, 0x420)
        facts = dispatch_facts()
        # Ghidra tags struct accesses like (0x304,A5) as DATA refs to $304.
        for address, displacement in ((0x210, 0x304), (0x212, 0x308)):
            facts[address] = fact(
                address,
                "MOVE.L",
                f"({displacement:#x},A5)|D1",
                references=(InstructionReference(displacement, "DATA", 0),),
            )

        self.assertEqual((0x400, 0x400, 0x410, 0x420), tuple(
            seed.address
            for seed in discover_dispatch_table_seeds(image, facts)
        ))

        # A scalar inferred in the destination register is not a ROM boundary.
        facts[0x214] = fact(
            0x214, "MOVE.W", "(0x56,A0)|D0w",
            references=(InstructionReference(0x308, "DATA", 1),),
        )
        self.assertEqual((0x400, 0x400, 0x410, 0x420), tuple(
            seed.address for seed in discover_dispatch_table_seeds(image, facts)))

        # An absolute reference still bounds the table.
        facts[0x214] = fact(
            0x214,
            "MOVE.L",
            "(0x308).l|D1",
            references=(InstructionReference(0x308, "DATA", 0),),
        )
        self.assertEqual((0x400, 0x400), tuple(
            seed.address
            for seed in discover_dispatch_table_seeds(image, facts)
        ))

    def test_recovers_counted_animation_offsets_into_ram_copy(self) -> None:
        data = bytearray(cartridge(size=0x1200))
        data[0x220:0x23C] = bytes.fromhex(
            "41 F9 00 00 04 00 43 F9 00 FF 00 00 "
            "30 3C 02 FF 22 D8 51 C8 FF FC 4E F9 00 FF 00 00"
        )
        data[0x500:0x50A] = bytes.fromhex(
            "00 00 05 04 02 03 06 00 06 08"
        )
        image = parse_megadrive(bytes(data))
        facts = {
            0x280: replace(
                fact(0x280, "MOVEA.L", "(0x8,A0)|A1"), length=4
            ),
            0x284: replace(
                fact(0x284, "MOVEA.L", "(0x0,A1,D0w*0x1)|A1"), length=4
            ),
            0x288: replace(
                fact(0x288, "MOVEQ", "-0x1|D1"), length=2
            ),
            0x28A: replace(
                fact(0x28A, "MOVE.W", "(0x2,A1,D0w*0x1)|D1w"), length=4
            ),
            0x290: replace(
                fact(0x290, "MOVE.L", "#0x500|(0x8,A0)"), length=6
            ),
        }

        accepted = {
            (item.schema_id, item.physical_start): item
            for item in detect_pointer_candidates(image, facts)
            if item.status == "accepted"
        }

        root = accepted[("megadrive.u32be.absolute", 0x500)]
        sequence = accepted[
            ("megadrive.counted-u16be.ram-copy-offset", 0x504)
        ]
        self.assertEqual((0x504,), tuple(entry.target for entry in root.entries))
        self.assertEqual((0xA00, 0xA08), tuple(
            entry.target for entry in sequence.entries
        ))
        self.assertEqual(0x400, sequence.entries[0].base_address)

    def test_accepts_loader_proven_counted_ram_trampoline_table(self) -> None:
        data = bytearray(cartridge(size=0x500))
        data[0x220:0x238] = bytes.fromhex(
            "41 FA 00 3E 43 F8 FF 00 30 18 32 FC 4E F9 "
            "72 00 32 18 22 C1 51 C8 FF F4"
        )
        targets = (0x280, 0x290, 0x2A0, 0x2B0)
        data[0x260:0x26A] = (
            (len(targets) - 1).to_bytes(2, "big")
            + b"".join(target.to_bytes(2, "big") for target in targets)
        )
        image = parse_megadrive(bytes(data))
        facts = {target: fact(target, "RTS", "") for target in targets}

        candidates = detect_pointer_candidates(image, facts)
        counted = next(
            item for item in candidates
            if item.schema_id == "megadrive.counted-u16be.absolute"
        )

        self.assertEqual("accepted", counted.status)
        self.assertEqual((0x260, 0x26A), (
            counted.physical_start, counted.physical_end
        ))
        self.assertEqual(targets, tuple(entry.target for entry in counted.entries))

    def test_accepts_absolute_and_table_relative_oracle_tables(self) -> None:
        data = bytearray(cartridge())
        targets = (0x200, 0x206, 0x23C, 0x23E)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in targets
        )
        data[0x250:0x258] = b"".join(
            (target - 0x250).to_bytes(2, "big", signed=True)
            for target in targets
        )
        image = parse_megadrive(bytes(data))
        table_references = (
            InstructionReference(0x240, "DATA", 0),
            InstructionReference(0x250, "DATA", 1),
        )
        facts: dict[int, InstructionFact] = {
            target: fact(target, "RTS", "") for target in targets
        }
        facts[0x200] = replace(
            facts[0x200], references=table_references
        )

        candidates = detect_pointer_candidates(image, facts)
        accepted = {
            (item.schema_id, item.physical_start): item
            for item in candidates
            if item.status == "accepted"
        }

        absolute = accepted[("megadrive.u32be.absolute", 0x240)]
        relative = accepted[("megadrive.s16be.target-table_base", 0x250)]
        self.assertEqual(targets, tuple(entry.target for entry in absolute.entries))
        self.assertEqual(targets, tuple(entry.target for entry in relative.entries))
        self.assertEqual(0x250, relative.entries[-1].base_address)
        self.assertIn(
            ("megadrive.m68k-vectors.u32be-masked24", 4), accepted
        )

    def test_unreferenced_code_looking_table_remains_candidate(self) -> None:
        data = bytearray(cartridge())
        targets = (0x200, 0x206, 0x23C, 0x23E)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in targets
        )
        image = parse_megadrive(bytes(data))
        facts = {target: fact(target, "RTS", "") for target in targets}

        candidates = detect_pointer_candidates(image, facts)
        table = next(
            item for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.physical_start == 0x240
        )

        self.assertEqual("candidate", table.status)
        self.assertIn("scan_only_no_table_reference", table.evidence)

    def test_accepts_forward_data_pointers_read_by_indexed_long_moves(self) -> None:
        data = bytearray(cartridge())
        first_targets = (0x300, 0x310, 0x320, 0x330)
        second_targets = (0x340, 0x350, 0x360, 0x370)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in first_targets
        )
        data[0x250:0x260] = b"".join(
            target.to_bytes(4, "big") for target in second_targets
        )
        image = parse_megadrive(bytes(data))
        facts = {
            0x200: replace(
                fact(0x200, "MOVE.L", "(0x240,PC,D0w*0x1)|D1"),
                references=(InstructionReference(0x240, "DATA", 0),),
            ),
            0x202: replace(
                fact(0x202, "MOVE.L", "(0x250,PC,D0w*0x1)|D1"),
                references=(InstructionReference(0x250, "DATA", 0),),
            ),
        }

        candidates = detect_pointer_candidates(image, facts)
        accepted = {
            item.physical_start: item
            for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.status == "accepted"
        }

        self.assertEqual({0x240, 0x250}, accepted.keys())
        self.assertEqual(first_targets, tuple(
            entry.target for entry in accepted[0x240].entries
        ))
        self.assertIn(
            "table_read_by_indexed_move_l", accepted[0x240].evidence
        )

    def test_accepts_read_referenced_u32_data_table(self) -> None:
        data = bytearray(cartridge())
        first_targets = (0x300, 0x310, 0x320, 0x330)
        second_targets = (0x340, 0x350, 0x360, 0x370)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in first_targets
        )
        data[0x250:0x260] = b"".join(
            target.to_bytes(4, "big") for target in second_targets
        )
        image = parse_megadrive(bytes(data))
        facts = {
            0x200: replace(
                fact(0x200, "MOVE.L", "(0x240,PC,D0w*0x1)|D1"),
                references=(InstructionReference(0x240, "READ", 0),),
            ),
            0x202: replace(
                fact(0x202, "MOVE.L", "(0x250,PC,D0w*0x1)|D1"),
                references=(InstructionReference(0x250, "READ", 0),),
            ),
        }

        candidates = detect_pointer_candidates(image, facts)
        table = next(
            item for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.physical_start == 0x240
        )

        self.assertEqual("accepted", table.status)
        self.assertEqual(0x250, table.physical_end)
        self.assertIn("table_start_referenced_by_instruction", table.evidence)

    def test_splits_adjacent_s16_relative_data_tables(self) -> None:
        data = bytearray(cartridge())
        first_targets = (0x300, 0x310, 0x320, 0x330)
        second_targets = (0x340, 0x350, 0x360, 0x370)
        data[0x280:0x288] = b"".join(
            (target - 0x280).to_bytes(2, "big", signed=True)
            for target in first_targets
        )
        data[0x288:0x290] = b"".join(
            (target - 0x288).to_bytes(2, "big", signed=True)
            for target in second_targets
        )
        image = parse_megadrive(bytes(data))
        facts = {
            0x200: replace(
                fact(0x200, "MOVE.W", "(0x280,PC,D0w*0x1)|D1w"),
                references=(InstructionReference(0x280, "READ", 0),),
            ),
            0x202: replace(
                fact(0x202, "MOVE.W", "(0x288,PC,D0w*0x1)|D1w"),
                references=(InstructionReference(0x288, "READ", 0),),
            ),
            0x290: fact(0x290, "RTS", ""),
        }

        candidates = detect_pointer_candidates(image, facts)
        tables = {
            item.physical_start: item
            for item in candidates
            if item.schema_id == "megadrive.s16be.target-table_base"
            and item.physical_start in {0x280, 0x288}
        }

        self.assertEqual({0x280, 0x288}, tables.keys())
        self.assertEqual(0x288, tables[0x280].physical_end)
        self.assertEqual(0x290, tables[0x288].physical_end)
        for table, targets in (
            (tables[0x280], first_targets),
            (tables[0x288], second_targets),
        ):
            self.assertEqual("accepted", table.status)
            self.assertEqual(targets, tuple(
                entry.target for entry in table.entries
            ))
            self.assertIn("table_read_by_indexed_word", table.evidence)

    def test_indexed_long_numeric_values_before_table_stay_candidate(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x290] = b"".join(
            value.to_bytes(4, "big") for value in (0x100, 0x120, 0x140, 0x160)
        )
        image = parse_megadrive(bytes(data))
        source = replace(
            fact(0x200, "MOVE.L", "(0x280,PC,D0w*0x1)|D1"),
            references=(InstructionReference(0x280, "DATA", 0),),
        )

        candidates = detect_pointer_candidates(image, {0x200: source})
        table = next(
            item for item in candidates
            if item.schema_id == "megadrive.u32be.absolute"
            and item.physical_start == 0x280
        )

        self.assertEqual("candidate", table.status)
        self.assertNotIn("all_targets_follow_table", table.evidence)

    def test_mapped_looking_words_are_not_auto_accepted(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x288] = bytes.fromhex("02 00 02 20 02 40 02 60")
        image = parse_megadrive(bytes(data))
        facts = {0x200: fact(0x200, "RTS", "")}

        accepted_ranges = {
            (item.physical_start, item.physical_end)
            for item in detect_pointer_candidates(image, facts)
            if item.status == "accepted"
        }

        self.assertNotIn((0x280, 0x288), accepted_ranges)

    def test_referenced_mixed_descriptor_stays_a_candidate(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x288] = bytes.fromhex("02 00 00 02 02 20 00 04")
        image = parse_megadrive(bytes(data))
        reference = InstructionReference(0x280, "DATA", 0)
        source = replace(
            fact(0x200, "LEA", "(0x7c,PC)|A0"), references=(reference,)
        )
        facts = {
            0x200: source,
            0x220: fact(0x220, "RTS", ""),
        }

        candidates = detect_pointer_candidates(image, facts)
        matching = [
            item
            for item in candidates
            if item.schema_id == "megadrive.u16be.absolute"
            and item.physical_start == 0x280
        ]

        self.assertTrue(matching)
        self.assertEqual("candidate", matching[0].status)


if __name__ == "__main__":
    unittest.main()
