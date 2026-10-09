from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_core.snes import (
    HIROM_HEADER_OFFSET,
    LOROM_HEADER_OFFSET,
    cartridge_checksum,
    parse_snes,
)
from retrolarium_disassembler.snes.analysis import analyze_snes
from retrolarium_disassembler.snes.pointers import (
    accepted_pointer_tables,
    detect_pointer_candidates,
)
from retrolarium_disassembler.snes.symbols import generate_symbols
from helpers import cartridge
from snes.builders import probe_image


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
