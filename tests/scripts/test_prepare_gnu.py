from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.references.prepare_gnu import normalize_listing, prepare, section_bases
from tools.benchmarks.source import read_listing


class GnuReferenceTests(unittest.TestCase):
    def test_section_mapping_relocations_wrapping_macros_and_data(self):
        rom = bytes.fromhex("60024eb9000000104e714e7523456789")
        text = ("1               \t.section .text\n"
                "2 0000 6000      \t BRA.b Target\n"
                "3 0002 4EB9 0000 \t JSR Target\n"
                "3      0000\n"
                "4 0008 4E71      \t>>> NOP\n"
                "5 000a 4E75      \t RTS\n"
                "6 000c 2345 6789 \t .incbin \"data.bin\"\n")
        normalized, expected = normalize_listing(text, rom, {".text": 0})
        self.assertEqual({0: rom[:2], 2: rom[2:8], 8: rom[8:10], 10: rom[10:12]}, expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "normalized.lst"
            path.write_text(normalized)
            actual, uncertain = read_listing(path, rom)
        self.assertEqual(expected, actual)
        self.assertFalse(uncertain)
        link_map = " .text 0x00000200 0x20 obj/main.o\n .text 0x00003000 0x10 obj/other.o\n"
        self.assertEqual({".text": 512}, section_bases(link_map, "obj/main.o"))
        with self.assertRaisesRegex(ValueError, "not found"):
            section_bases(link_map, "absent.o")

    def test_long_instruction_end_before_a_gap_is_not_truncated(self):
        rom = bytes.fromhex("23fc1234567800c000044e714e75")
        text = ("1 0000 23FC 1234 \t MOVE.l #0x12345678,0xc00004\n"
                "1      5678 00C0\n1      0004\n"
                "2 000c 4E75      \t RTS\n")
        normalized, expected = normalize_listing(text, rom, {".text": 0})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "listing.lst"
            path.write_text(normalized)
            actual, uncertain = read_listing(path, rom)
        self.assertEqual(rom[:10], expected[0])
        self.assertEqual(expected, actual)
        self.assertFalse(uncertain)

    def test_unsupported_mapping_and_wrong_opcode_fail(self):
        with self.assertRaisesRegex(ValueError, "unmapped"):
            normalize_listing("1 0000 4E75\t RTS\n", b"\x4e\x75", {})
        with self.assertRaisesRegex(ValueError, "differs"):
            normalize_listing("1 0000 4E75\t RTS\n", b"\x4e\x71", {".text": 0})
        with self.assertRaisesRegex(ValueError, "section stack"):
            normalize_listing("1\t .pushsection .text\n", b"", {})

    def test_upstream_and_flattened_rom_must_both_match_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, upstream, flat = (root / name for name in ("original", "upstream", "flat"))
            original.write_bytes(b"original")
            upstream.write_bytes(b"other")
            flat.write_bytes(b"original")
            with self.assertRaisesRegex(ValueError, "byte-identical"):
                prepare(name="case", original=original, upstream_binary=upstream,
                        flattened_binary=flat, source=root / "source", listing=root / "listing",
                        link_map=root / "map", object_name="obj/main.o", output=root / "out")


if __name__ == "__main__":
    unittest.main()
