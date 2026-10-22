from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.benchmarks.sonic_cd import overlay_header, reference_instructions


class SonicCdBenchmarkTests(unittest.TestCase):
    def test_mmd_header_maps_file_offset_and_all_file_backed_entries(self):
        image = bytearray(0x120)
        image[2:6] = (0xFF2000).to_bytes(4, "big")
        image[8:12] = (0xFF2000).to_bytes(4, "big")
        image[12:16] = (0xFF2004).to_bytes(4, "big")
        image[16:20] = (0xFF3000).to_bytes(4, "big")
        self.assertEqual((0xFF1F00, (0xFF2000, 0xFF2004)), overlay_header(bytes(image)))

    def test_first_pass_branch_operand_is_verified_against_disc_bytes(self):
        image = bytes.fromhex("67084E754E71")
        listing = "\n".join(
            (
                "00001000 6700        \tbeq.s Target",
                "00001002 4E75        \trts",
                "00001004 4E71        \tNOP",
                "00001006 4E75        \trts",  # outside the file
                "00001000 4E71        \tnop",  # conflicting opcode
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reference.lst"
            path.write_text(listing, encoding="utf-8")
            found, _, stats = reference_instructions(path, image, 0x1000)
        self.assertEqual({0: bytes.fromhex("6708"), 2: bytes.fromhex("4E75"), 4: bytes.fromhex("4E71")}, found)
        self.assertEqual(1, stats["unmapped"])
        self.assertEqual(1, stats["opcode_conflicts"])


if __name__ == "__main__":
    unittest.main()
