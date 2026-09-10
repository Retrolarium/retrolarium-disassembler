from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_pointers import detect_pointer_candidates
from retrolarium_kit.megadrive_symbols import generate_symbols
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class MegaDriveSymbolTests(unittest.TestCase):
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
        self.assertEqual("Sub_M68K_000206", by_address[0x206].name)
        self.assertEqual("Loc_M68K_00023C", by_address[0x23C].name)
        self.assertEqual("Tbl_M68K_000240", by_address[0x240].name)


if __name__ == "__main__":
    unittest.main()
