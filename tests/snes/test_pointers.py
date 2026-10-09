from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_core.snes import (
    HIROM_HEADER_OFFSET,
    LOROM_HEADER_OFFSET,
    cartridge_checksum,
    parse_snes,
)
from retrolarium_kit.snes_analysis import analyze_snes
from retrolarium_kit.snes_pointers import (
    accepted_pointer_tables,
    detect_pointer_candidates,
)
from retrolarium_kit.snes_symbols import generate_symbols
from helpers import cartridge


PROBE = bytes.fromhex(
    "78 18 FB C2 30 A9 34 12 A2 78 56 E2 20 A9 12 20 "
    "1B 90 22 23 90 00 20 4E 90 80 09 C2 20 A9 BC 9A "
    "E2 20 60 6B CB 80 FD 40 40 00 90 1B 90 24 90 27 "
    "90 00 90 00 23 90 00 27 90 00 00 1B 24 27 90 90 "
    "90 90 00 00 00 00 BA FF D5 FF DE FF E1 FF 4B AB C2 "
    "30 A9 00 02 8D 42 21 A2 00 00 E2 20 BD 72 90 8D 41 "
    "21 8A 8D 40 21 C2 20 E8 E0 06 00 D0 EC E2 20 60 E8 "
    "12 C4 F4 2F FA"
)


def probe_image(mapping: str):
    data = bytearray(cartridge(mapping))
    physical = 0x1000 if mapping == "lorom" else 0x9000
    data[physical : physical + len(PROBE)] = PROBE
    header = LOROM_HEADER_OFFSET if mapping == "lorom" else HIROM_HEADER_OFFSET
    data[header + 0x20 : header + 0x40] = bytes(0x20)
    vectors = {
        0x24: 0x9027,
        0x26: 0x9027,
        0x28: 0x9027,
        0x2A: 0x9027,
        0x2E: 0x9028,
        0x34: 0x9027,
        0x38: 0x9027,
        0x3A: 0x9027,
        0x3C: 0x9000,
        0x3E: 0x9028,
    }
    for offset, value in vectors.items():
        data[header + offset : header + offset + 2] = value.to_bytes(2, "little")
    data[header + 0x1C : header + 0x20] = bytes(4)
    checksum = (cartridge_checksum(data) + 0x1FE) & 0xFFFF
    data[header + 0x1C : header + 0x1E] = (checksum ^ 0xFFFF).to_bytes(
        2, "little"
    )
    data[header + 0x1E : header + 0x20] = checksum.to_bytes(2, "little")
    return parse_snes(bytes(data))


class SnesPointerTests(unittest.TestCase):
    def test_recovers_all_probe_schemas_in_both_mappings(self) -> None:
        expected = {
            "snes.u16le.current-bank": (0x9029, (0x9000, 0x901B, 0x9024, 0x9027)),
            "snes.u24le.far": (0x9031, (0x9000, 0x9023, 0x9027)),
            "snes.split-lo-hi-bank": (0x903A, (0x9000, 0x901B, 0x9024, 0x9027)),
            "snes.s16le.table-base": (0x9046, (0x9000, 0x901B, 0x9024, 0x9027)),
        }
        layouts = {}
        for mapping in ("lorom", "hirom"):
            image = probe_image(mapping)
            candidates = accepted_pointer_tables(
                detect_pointer_candidates(image, analyze_snes(image))
            )
            by_schema = {
                candidate.schema_id: candidate
                for candidate in candidates
                if candidate.schema_id != "snes.vectors.u16le.bank00"
            }
            self.assertEqual(set(expected), set(by_schema))
            for schema_id, (logical, targets) in expected.items():
                self.assertEqual(logical, by_schema[schema_id].logical_start)
                self.assertEqual(
                    targets,
                    tuple(entry.target for entry in by_schema[schema_id].entries),
                )
            layouts[mapping] = {
                schema: candidate.physical_start
                for schema, candidate in by_schema.items()
            }
        self.assertNotEqual(layouts["lorom"], layouts["hirom"])

    def test_symbols_are_logically_stable_across_lorom_and_hirom(self) -> None:
        generated = []
        for mapping in ("lorom", "hirom"):
            image = probe_image(mapping)
            analysis = analyze_snes(image)
            pointers = detect_pointer_candidates(image, analysis)
            symbols = generate_symbols(image, analysis, pointers)
            generated.append(
                {(symbol.name, symbol.kind, symbol.logical_address) for symbol in symbols}
            )
            by_address = {symbol.logical_address: symbol for symbol in symbols}
            self.assertEqual("entry", by_address[0x9000].kind)
            self.assertEqual("subroutine", by_address[0x901B].kind)
            self.assertEqual("subroutine", by_address[0x9023].kind)
            self.assertEqual("table", by_address[0x9029].kind)
            self.assertTrue(by_address[0x9027].aliases)
        self.assertEqual(generated[0], generated[1])


if __name__ == "__main__":
    unittest.main()
