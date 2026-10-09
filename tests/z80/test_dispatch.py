"""Dispatch recovery must follow executable evidence, not pointer-shaped data."""

from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from retrolarium_disassembler.z80.dispatch import discover_z80_dispatch_tables
from megadrive.builders import fact


def instruction(address: int, raw: bytes):
    return replace(
        fact(address, "NOP", ""), raw=raw, length=len(raw),
    )


class Z80DispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = bytearray(0x100)
        self.payload[0x28:0x35] = bytes.fromhex(
            "4F 06 00 09 09 00 00 00 7E 23 66 6F C9"
        )
        self.payload[0x60:0x67] = bytes.fromhex(
            "21 80 00 EF 1A E9 00"
        )
        self.targets = (0xA0, 0xA4, 0xA8, 0xAC)
        for index, target in enumerate(self.targets):
            offset = 0x80 + index * 2
            self.payload[offset:offset + 2] = target.to_bytes(2, "little")
        self.payload[0x88:0x8A] = bytes.fromhex("FF FF")
        self.facts = {
            item.cpu_address: item
            for item in (
                instruction(0x60, bytes.fromhex("21 80 00")),
                instruction(0x63, b"\xef"),
                instruction(0x64, b"\x1a"),
                instruction(0x65, b"\xe9"),
            )
        }

    def test_recovers_word_table_from_lookup_and_indirect_jump(self) -> None:
        tables = discover_z80_dispatch_tables(bytes(self.payload), self.facts)

        self.assertEqual(1, len(tables))
        self.assertEqual((0x80, 0x88), (
            tables[0].logical_start, tables[0].logical_end
        ))
        self.assertEqual(self.targets, tables[0].targets)
        self.assertEqual((0x60, 0x28), (
            tables[0].dispatch_address, tables[0].lookup_address
        ))

    def test_rejects_unproven_lookup_or_jump(self) -> None:
        without_jump = {
            address: item for address, item in self.facts.items()
            if address != 0x65
        }
        self.assertEqual(
            (), discover_z80_dispatch_tables(bytes(self.payload), without_jump)
        )
        self.payload[0x2B] = 0
        self.assertEqual(
            (), discover_z80_dispatch_tables(bytes(self.payload), self.facts)
        )

    def test_inferred_jump_to_table_does_not_make_its_words_code(self) -> None:
        self.facts[0x65] = replace(
            self.facts[0x65], flow_type="COMPUTED_JUMP", flows=(0x80,)
        )
        for address in range(0x80, 0x88):
            self.facts[address] = instruction(address, self.payload[address:address + 1])
        tables = discover_z80_dispatch_tables(bytes(self.payload), self.facts)
        self.assertEqual(1, len(tables))
        self.assertEqual(self.targets, tables[0].targets)

    def test_recovered_target_preserves_following_code_boundary(self) -> None:
        self.facts[0x65] = replace(
            self.facts[0x65], flow_type="COMPUTED_JUMP", flows=(0x80,)
        )
        self.facts[0x80] = instruction(0x80, bytes.fromhex("A0 00"))
        # A handler jumps to decoded code just after the four table words.
        self.facts[0xAC] = replace(
            instruction(0xAC, bytes.fromhex("C3 88 00")),
            flow_type="UNCONDITIONAL_JUMP", flows=(0x88,),
        )
        self.facts[0x88] = instruction(0x88, bytes.fromhex("3E 01"))
        tables = discover_z80_dispatch_tables(self._overrun_payload(), self.facts)
        self.assertEqual(1, len(tables))
        self.assertEqual((0x80, 0x88), (tables[0].logical_start, tables[0].logical_end))
        self.assertEqual(self.targets, tables[0].targets)

    def test_explicit_jump_to_table_still_rejects_table(self) -> None:
        self.facts[0x65] = replace(
            self.facts[0x65], flow_type="UNCONDITIONAL_JUMP", flows=(0x80,)
        )
        self.facts[0x80] = instruction(0x80, b"\x00")
        self.assertEqual((), discover_z80_dispatch_tables(bytes(self.payload), self.facts))

    def test_rejects_unbounded_pointer_values(self) -> None:
        self.payload[0x86:0x88] = bytes.fromhex("FF FF")
        self.assertEqual(
            (), discover_z80_dispatch_tables(bytes(self.payload), self.facts)
        )

    def test_subtract_before_lookup_bounds_adjacent_tables(self) -> None:
        self.payload[0x5E:0x60] = bytes.fromhex("D6 FC")
        self.payload[0x88:0x8A] = (0xB0).to_bytes(2, "little")
        self.facts[0x5E] = instruction(0x5E, bytes.fromhex("D6 FC"))

        tables = discover_z80_dispatch_tables(bytes(self.payload), self.facts)

        self.assertEqual(1, len(tables))
        self.assertEqual((0x80, 0x88), (
            tables[0].logical_start, tables[0].logical_end
        ))
        self.assertEqual(self.targets, tables[0].targets)

    def _overrun_payload(self) -> bytes:
        # A large image makes 3E 01 32 00 1C look like valid pointers.
        payload = bytearray(0x2000)
        payload[:0x100] = self.payload
        payload[0x88:0x8D] = bytes.fromhex("3E 01 32 00 1C")
        return bytes(payload)

    def test_table_stops_before_following_decoded_code(self) -> None:
        self.facts[0x88] = instruction(0x88, bytes.fromhex("3E 01"))
        self.facts[0x8A] = instruction(0x8A, bytes.fromhex("32 00 1C"))

        tables = discover_z80_dispatch_tables(self._overrun_payload(), self.facts)

        self.assertEqual(1, len(tables))
        self.assertEqual((0x80, 0x88), (
            tables[0].logical_start, tables[0].logical_end
        ))
        self.assertEqual(self.targets, tables[0].targets)

    def test_table_stops_before_following_flow_target(self) -> None:
        self.facts[0x90] = replace(
            instruction(0x90, bytes.fromhex("C3 88 00")), flows=(0x88,)
        )

        tables = discover_z80_dispatch_tables(self._overrun_payload(), self.facts)

        self.assertEqual(1, len(tables))
        self.assertEqual(self.targets, tables[0].targets)

    def test_two_dispatch_sites_share_one_table(self) -> None:
        self.payload[0x70:0x75] = bytes.fromhex("21 80 00 EF E9")
        self.facts[0x70] = instruction(0x70, bytes.fromhex("21 80 00"))
        self.facts[0x73] = instruction(0x73, b"\xef")
        self.facts[0x74] = instruction(0x74, b"\xe9")

        tables = discover_z80_dispatch_tables(bytes(self.payload), self.facts)

        self.assertEqual(1, len(tables))
        self.assertEqual((0x80, 0x88), (
            tables[0].logical_start, tables[0].logical_end
        ))
        self.assertEqual(self.targets, tables[0].targets)
        self.assertEqual(0x60, tables[0].dispatch_address)
        self.assertEqual((0x60, 0x70), tables[0].dispatch_addresses)


if __name__ == "__main__":
    unittest.main()
