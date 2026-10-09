from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.benchmarks.sega32x import fixed_window_entries


class Sega32xVectorTests(unittest.TestCase):
    def test_vector_stub_page_stops_at_metadata(self):
        data = bytearray(0x800)
        data[0x100:0x108] = b"SEGA 32X"
        data[4:8] = (0x400).to_bytes(4, "big")
        data[8:12] = (0x880410).to_bytes(4, "big")
        data[0x200:0x216] = bytes.fromhex("4EF9008804004E754E714EF90088041012344EF90088")
        base, size, entries = fixed_window_entries(bytes(data))
        self.assertEqual((0x880000, 0x800), (base, size))
        self.assertEqual({0x880200, 0x880206, 0x880208, 0x88020A, 0x880400, 0x880410}, set(entries))

    def test_ram_jump_does_not_truncate_vector_page(self):
        data = bytearray(0x800)
        data[0x100:0x108] = b"SEGA 32X"
        code = bytes.fromhex("4EF9008804004EF8C02A4E714EF900FFC0364E754EF900880410")
        data[0x200:0x200 + len(code)] = code
        _, _, entries = fixed_window_entries(bytes(data))
        self.assertEqual({0x880200, 0x880206, 0x88020A, 0x88020C,
                          0x880212, 0x880214, 0x880400, 0x880410}, set(entries))

    def test_rejects_non_32x_input(self):
        with self.assertRaises(ValueError):
            fixed_window_entries(bytes(0x800))
