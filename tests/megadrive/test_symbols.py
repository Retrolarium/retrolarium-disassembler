from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_core.megadrive import parse_megadrive
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.megadrive_pointers import detect_pointer_candidates
from retrolarium_kit.megadrive_symbols import generate_symbols
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class MegaDriveSymbolTests(unittest.TestCase):
    def test_ignores_data_references_inside_long_ff_padding(self) -> None:
        data = bytearray(cartridge())
        data[0x280:0x340] = b"\xFF" * 0xC0
        image = parse_megadrive(bytes(data))
        source = replace(
            fact(0x200, "MOVE.L", "#0x2a0|D0"),
            references=(
                InstructionReference(0x260, "DATA", 0),
                InstructionReference(0x2A0, "DATA", 0),
            ),
        )

        symbols = generate_symbols(image, {0x200: source}, ())
        by_address = {symbol.logical_address: symbol for symbol in symbols}

        self.assertIn(0x260, by_address)
        self.assertNotIn(0x2A0, by_address)

    def test_movem_pc_displacement_skips_register_mask(self) -> None:
        image = parse_megadrive(cartridge(size=0x1000))
        instruction = replace(
            fact(0x8A0, "MOVEM.W", "(0x30,PC)|{ D0 D1 D2 D3 D4 D5}"),
            raw=bytes.fromhex("4C BA 00 3F 00 30"), length=6,
        )
        symbols = generate_symbols(image, {0x8A0: instruction}, ())
        by_address = {symbol.logical_address: symbol for symbol in symbols}
        self.assertEqual("off_M68K_0008D4", by_address[0x8D4].name)
        self.assertNotIn(0x8D2, by_address)
        self.assertNotIn(0x8E1, by_address)

    def test_pc_indexed_jsr_to_branch_table_gets_table_symbol(self) -> None:
        image = parse_megadrive(cartridge())
        call = replace(
            fact(0x240, "JSR", "(0x248,PC,D0w*0x1)"),
            raw=bytes.fromhex("4E BB 00 06"), length=4,
            flow_type="COMPUTED_CALL",
        )
        first_entry = replace(
            fact(0x248, "BRA.W", "0x300", flows=(0x300,)),
            raw=bytes.fromhex("60 00 00 B6"), length=4,
        )
        symbols = generate_symbols(
            image, {0x240: call, 0x248: first_entry}, ()
        )
        by_address = {symbol.logical_address: symbol for symbol in symbols}
        self.assertEqual("tbl_M68K_000248", by_address[0x248].name)

    def test_names_are_address_stable_and_evidence_classified(self) -> None:
        data = bytearray(cartridge())
        targets = (0x200, 0x206, 0x23C, 0x23E)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in targets
        )
        image = parse_megadrive(bytes(data))
        entry = replace(
            fact(0x200, "BSR.W", "0x206", flows=(0x206,)),
            flow_type="UNCONDITIONAL_CALL",
            references=(
                InstructionReference(0x240, "DATA", 0),
                InstructionReference(0x250, "DATA", 0),
            ),
        )
        branch = replace(
            fact(0x204, "BRA.B", "0x23c", flows=(0x23C,)),
            flow_type="UNCONDITIONAL_JUMP",
        )
        facts = {
            item.cpu_address: item
            for item in (
                entry,
                branch,
                fact(0x206, "RTS", ""),
                fact(0x23C, "BRA.B", "0x23c", flows=(0x23C,)),
                fact(0x23E, "RTE", ""),
            )
        }
        pointers = detect_pointer_candidates(image, facts)

        symbols = generate_symbols(image, facts, pointers)
        by_address = {symbol.logical_address: symbol for symbol in symbols}

        self.assertEqual("Entry_M68K_000200", by_address[0x200].name)
        self.assertIn("Vec_M68K_Reset_000200", by_address[0x200].aliases)
        self.assertEqual("sub_M68K_000206", by_address[0x206].name)
        self.assertEqual("loc_M68K_00023C", by_address[0x23C].name)
        self.assertEqual("tbl_M68K_000240", by_address[0x240].name)
        self.assertEqual("off_M68K_000250", by_address[0x250].name)


if __name__ == "__main__":
    unittest.main()
