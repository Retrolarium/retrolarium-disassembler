from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.snes_analysis import analyze_snes
from retrolarium_kit.snes_spc700 import detect_spc700_copies, payload_for_copy
from test_snes_pointers import probe_image


class SnesSpc700Tests(unittest.TestCase):
    def test_recovers_proven_upload_in_both_mappings(self) -> None:
        layouts = {}
        for mapping in ("lorom", "hirom"):
            image = probe_image(mapping)
            copies = detect_spc700_copies(image, analyze_snes(image))
            self.assertEqual(1, len(copies))
            copy = copies[0]
            self.assertEqual(0x009072, copy.source_start)
            self.assertEqual(0x0200, copy.target_start)
            self.assertEqual(6, copy.size)
            self.assertEqual(bytes.fromhex("E8 12 C4 F4 2F FA"), payload_for_copy(image, copy))
            self.assertEqual("proven-static-copy", copy.confidence)
            layouts[mapping] = copy.source_physical_start
        self.assertNotEqual(layouts["lorom"], layouts["hirom"])

    def test_rejects_upload_when_length_proof_is_removed(self) -> None:
        image = probe_image("lorom")
        data = bytearray(image.container_data)
        # CPX #$0006 at logical $00906A / physical $00106A.
        data[0x106B:0x106D] = b"\x00\x00"
        from retrolarium_kit.snes import parse_snes

        modified = parse_snes(bytes(data))
        self.assertEqual((), detect_spc700_copies(modified, analyze_snes(modified)))


if __name__ == "__main__":
    unittest.main()
