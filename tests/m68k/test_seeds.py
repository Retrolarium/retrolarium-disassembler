from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_disasm.m68k.seeds import (
    discover_dense_branch_table_seeds,
    discover_indexed_branch_table_seeds,
    discover_ram_copy_regions,
    discover_ram_copy_seeds,
    discover_ram_trampoline_seeds,
    discover_vector_seeds,
)
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge


def image_with(payload: dict[int, bytes], *, size: int = 0x500):
    data = bytearray(cartridge(size=size))
    for offset, value in payload.items():
        data[offset:offset + len(value)] = value
    return parse_megadrive(bytes(data))


class M68kSeedTests(unittest.TestCase):
    def test_vectors_become_python_decoder_roots(self) -> None:
        seeds = discover_vector_seeds(parse_megadrive(cartridge(size=0x500)))

        self.assertEqual((0x200, 0x240), tuple(seed.address for seed in seeds))
        self.assertEqual({"vector"}, {seed.kind for seed in seeds})
        self.assertEqual({"proven"}, {seed.confidence for seed in seeds})

    def test_recognizes_complete_ram_copy_idiom_and_rejects_near_miss(self) -> None:
        copy_loop = bytes.fromhex(
            "41 F9 00 00 03 00 43 F9 00 FF 00 00 "
            "30 3C 00 01 22 D8 51 C8 FF FC 4E F9 00 FF 00 00"
        )
        valid = discover_ram_copy_seeds(image_with({0x220: copy_loop}))
        regions = discover_ram_copy_regions(image_with({0x220: copy_loop}))
        broken = bytearray(copy_loop)
        broken[20:22] = bytes.fromhex("FF FA")
        invalid = discover_ram_copy_seeds(image_with({0x220: bytes(broken)}))

        self.assertEqual((0x300,), tuple(seed.address for seed in valid))
        self.assertEqual("ram_copy_origin", valid[0].kind)
        self.assertEqual(
            (0x300, 0x308, 0xFF0000, 0xFF0008),
            (
                regions[0].source_start,
                regions[0].source_end,
                regions[0].destination_start,
                regions[0].destination_end,
            ),
        )
        self.assertEqual((), invalid)

    def test_recognizes_pc_indexed_and_dense_branch_tables(self) -> None:
        indexed_table = bytes.fromhex(
            "60 00 00 3E 60 00 00 4A 4E 75"
        )
        dense_table = bytes.fromhex(
            "60 00 00 3E 60 00 00 3E 60 00 00 3E 60 00 00 3E 4E 75"
        )
        image = image_with({
            0x220: bytes.fromhex("4E BB 00 1E"),
            0x240: indexed_table,
            0x300: dense_table,
        })

        indexed = discover_indexed_branch_table_seeds(image)
        dense = discover_dense_branch_table_seeds(image)

        self.assertEqual(
            {0x240, 0x244, 0x280, 0x290},
            {seed.address for seed in indexed},
        )
        self.assertTrue(
            {0x300, 0x304, 0x308, 0x30C, 0x340, 0x344, 0x348, 0x34C}
            <= {seed.address for seed in dense}
        )

    def test_recognizes_pc_indexed_short_branch_table(self) -> None:
        image = image_with({
            0x220: bytes.fromhex("4E FB 00 1E"),
            0x240: bytes.fromhex("60 3E 60 4C 4E 75"),
        })

        seeds = discover_indexed_branch_table_seeds(image)

        self.assertEqual(
            {0x240, 0x242, 0x280, 0x290},
            {seed.address for seed in seeds},
        )

    def test_recognizes_counted_ram_trampoline_builder(self) -> None:
        loader = bytes.fromhex(
            "41 FA 00 3E 43 F8 FF 00 30 18 32 FC 4E F9 "
            "72 00 32 18 22 C1 51 C8 FF F4"
        )
        table = bytes.fromhex("00 03 02 80 02 90 02 A0 02 B0")
        seeds = discover_ram_trampoline_seeds(image_with({
            0x220: loader,
            0x260: table,
        }))

        self.assertEqual(
            (0x280, 0x290, 0x2A0, 0x2B0),
            tuple(seed.address for seed in seeds),
        )
        self.assertEqual(
            {"ram_trampoline_target"}, {seed.kind for seed in seeds}
        )


if __name__ == "__main__":
    unittest.main()
