from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.megadrive import (
    MegaDriveError,
    cartridge_checksum,
    image_manifest,
    m68k_to_rom_offset,
    parse_megadrive,
    rom_offset_to_m68k,
    stamp_cartridge_checksum,
)
from retrolarium_kit.facts import (
    FactError,
    load_megadrive_ghidra_facts,
    parse_address,
)


def cartridge(
    *,
    size: int = 0x400,
    declared_end: int | None = None,
    checksum: bool = True,
) -> bytes:
    data = bytearray(size)
    data[0:4] = (0x01000000).to_bytes(4, "big")
    data[4:8] = (0x200).to_bytes(4, "big")
    data[8:12] = (0x01000240).to_bytes(4, "big")
    data[0x100:0x110] = b"SEGA MEGA DRIVE "
    data[0x120:0x150] = b"RETROLARIUM PROBE".ljust(48)
    data[0x150:0x180] = b"RETROLARIUM PROBE".ljust(48)
    data[0x180:0x18E] = b"GM TEST-001-00"
    data[0x190:0x1A0] = b"J".ljust(16)
    data[0x1A0:0x1A4] = (0).to_bytes(4, "big")
    data[0x1A4:0x1A8] = (
        size - 1 if declared_end is None else declared_end
    ).to_bytes(4, "big")
    data[0x1A8:0x1AC] = (0xFF0000).to_bytes(4, "big")
    data[0x1AC:0x1B0] = (0xFFFFFF).to_bytes(4, "big")
    data[0x1F0:0x200] = b"JUE".ljust(16)
    data[0x200:] = bytes(index & 0xFF for index in range(size - 0x200))
    if checksum:
        data[0x18E:0x190] = cartridge_checksum(data).to_bytes(2, "big")
    return bytes(data)


class MegaDriveTests(unittest.TestCase):
    def test_only_speculative_facts_allow_alternate_overlapping_decodes(self):
        image = parse_megadrive(cartridge())
        header = "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
        rows = ["ROM\tram\t0200\t4\t00010203\tORI.B\t\t\tFALL_THROUGH\t\t\n",
                "ROM\tram\t0202\t4\t02030405\tORI.B\t\t\tFALL_THROUGH\t\t\n"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probes.tsv"
            path.write_text(header + "".join(rows), encoding="utf-8")
            with self.assertRaisesRegex(FactError, "overlapping instruction"):
                load_megadrive_ghidra_facts(path, image)
            self.assertEqual({0x200, 0x202}, set(load_megadrive_ghidra_facts(path, image, speculative=True)))
            path.write_text(header + rows[0] + rows[0], encoding="utf-8")
            with self.assertRaisesRegex(FactError, "duplicate physical instruction"):
                load_megadrive_ghidra_facts(path, image, speculative=True)
            path.write_text(header + rows[1].replace("02030405", "FFFFFFFF"), encoding="utf-8")
            with self.assertRaisesRegex(FactError, "backend bytes disagree"):
                load_megadrive_ghidra_facts(path, image, speculative=True)

    def test_normalizes_backend_address_notations(self) -> None:
        self.assertEqual(0x4000, parse_address("ram:4000"))
        self.assertEqual(0xC000, parse_address("PRG0::c000"))
        self.assertEqual(0x258, parse_address("0x00000258"))

    def test_imports_m68k_facts_only_after_rom_byte_validation(self) -> None:
        image = parse_megadrive(cartridge())
        header = (
            "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\t"
            "flows\tflow_type\tsymbol\tfunction\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instructions.tsv"
            path.write_text(
                header
                + "ROM\tram\t0200\t2\t00 01\tori.b\t#0x1|D0\t"
                "00000204\tFALL_THROUGH\tVector_Reset\t\n",
                encoding="utf-8",
                newline="\n",
            )
            facts = load_megadrive_ghidra_facts(path, image)
            self.assertEqual(0x200, facts[0x200].physical_offset)
            self.assertEqual((0x204,), facts[0x200].flows)

            path.write_text(
                header
                + "RAM\tram\t0200\t2\t00 01\tori.b\t#0x1|D0\t"
                "\tFALL_THROUGH\t\t\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(FactError, "unexpected Ghidra block"):
                load_megadrive_ghidra_facts(path, image)

    def test_parses_header_vectors_regions_and_big_endian_checksum(self) -> None:
        image = parse_megadrive(cartridge())

        self.assertEqual(0x01000000, image.initial_stack_pointer)
        self.assertEqual(0x200, image.reset_vector)
        self.assertEqual(0x200, image.reset_address)
        self.assertEqual("reset", image.vector_table[1].name)
        self.assertEqual(0x01000240, image.vector_table[2].raw_value)
        self.assertEqual(0x240, image.vector_table[2].address)
        self.assertEqual("RETROLARIUM PROBE", image.header.domestic_title)
        self.assertEqual("GM TEST-001-00", image.header.product_code)
        self.assertEqual("valid", image.checksum_status)
        self.assertEqual((0x100, 0x100, 0x200), tuple(r.size for r in image.regions))
        self.assertEqual(0x200, m68k_to_rom_offset(image, 0x200))
        self.assertEqual(0x200, rom_offset_to_m68k(image, 0x200))

        manifest = image_manifest(image)
        self.assertEqual("retrolarium.megadrive.image", manifest["schema"])
        self.assertEqual("big", manifest["byte_order"])
        self.assertEqual(0x240, manifest["vectors"][2]["address"])
        self.assertEqual([], manifest["warnings"])

    def test_preserves_homebrew_capacity_header_and_missing_checksum(self) -> None:
        image = parse_megadrive(
            cartridge(size=0x401, declared_end=0x3FFFFF, checksum=False)
        )

        self.assertEqual(0x400, image.actual_rom_end)
        self.assertEqual("absent", image.checksum_status)
        self.assertEqual(2, len(image.warnings))
        self.assertIn("0x3FFFFF", image.warnings[0])
        self.assertEqual(
            int.from_bytes(image.data[-1:] + b"\0", "big"),
            (
                cartridge_checksum(image.data)
                - cartridge_checksum(image.data[:-1])
            )
            & 0xFFFF,
        )

    def test_reports_checksum_mismatch_without_losing_the_image(self) -> None:
        data = bytearray(cartridge())
        data[-1] ^= 0xFF
        image = parse_megadrive(bytes(data))

        self.assertEqual("mismatch", image.checksum_status)
        self.assertIn("computed value", image.warnings[-1])

    def test_stamps_edited_cartridge_but_preserves_zero_edit(self) -> None:
        original = cartridge()
        self.assertEqual(original, stamp_cartridge_checksum(original))
        edited = bytearray(original)
        edited[0x300] ^= 1
        stamped = stamp_cartridge_checksum(bytes(edited))
        self.assertEqual("valid", parse_megadrive(stamped).checksum_status)
        self.assertEqual(bytes(edited[0x200:]), stamped[0x200:])
        self.assertNotEqual(bytes(edited[0x18E:0x190]), stamped[0x18E:0x190])
        with self.assertRaises(MegaDriveError):
            stamp_cartridge_checksum(b"not a cartridge")

    def test_rejects_missing_signature_and_invalid_reset_vector(self) -> None:
        data = bytearray(cartridge())
        data[0x100:0x104] = b"NOPE"
        with self.assertRaises(MegaDriveError):
            parse_megadrive(bytes(data))

        data = bytearray(cartridge())
        data[4:8] = (0x201).to_bytes(4, "big")
        with self.assertRaises(MegaDriveError):
            parse_megadrive(bytes(data))

    def test_address_projection_rejects_unbacked_capacity(self) -> None:
        image = parse_megadrive(cartridge(declared_end=0x3FFFFF))

        with self.assertRaises(MegaDriveError):
            m68k_to_rom_offset(image, 0x2000)
        with self.assertRaises(MegaDriveError):
            rom_offset_to_m68k(image, len(image.data))


if __name__ == "__main__":
    unittest.main()
