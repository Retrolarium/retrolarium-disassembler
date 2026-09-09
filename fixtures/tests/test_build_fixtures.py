from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_fixtures.py"
SPEC = importlib.util.spec_from_file_location("build_fixtures", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
build_fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_fixtures)

UCON64_SCRIPT = SCRIPT.parents[1] / "docker" / "snes" / "ucon64.py"
UCON64_SPEC = importlib.util.spec_from_file_location("ucon64_compat", UCON64_SCRIPT)
assert UCON64_SPEC is not None and UCON64_SPEC.loader is not None
ucon64_compat = importlib.util.module_from_spec(UCON64_SPEC)
UCON64_SPEC.loader.exec_module(ucon64_compat)


class FixtureBuildTests(unittest.TestCase):
    def test_config_contains_unique_projects(self) -> None:
        config = build_fixtures.load_config()
        projects = build_fixtures.project_map(config)
        self.assertEqual(8, len(projects))

    def test_lock_matches_project_sources(self) -> None:
        config = build_fixtures.load_config()
        lock = build_fixtures.load_lock()
        build_fixtures.validate_lock(config, lock)
        self.assertEqual(
            set(build_fixtures.project_map(config)),
            set(build_fixtures.repository_map(lock)),
        )

    def test_within_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(build_fixtures.FixtureError):
                build_fixtures.within(Path(directory), "../outside")

    def test_nes_validation_accepts_ines_and_hashes_it(self) -> None:
        project = {
            "id": "test.nes",
            "platform": "nes",
            "expected_size": 20,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.nes"
            path.write_bytes(b"NES\x1a" + bytes(16))
            result = build_fixtures.validate_rom(project, path)
        self.assertEqual(20, result["size"])
        self.assertEqual(64, len(result["sha256"]))

    def test_nes_validation_rejects_wrong_header(self) -> None:
        project = {
            "id": "test.nes",
            "platform": "nes",
            "expected_size": 20,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.nes"
            path.write_bytes(bytes(20))
            with self.assertRaises(build_fixtures.FixtureError):
                build_fixtures.validate_rom(project, path)

    def test_validation_rejects_wrong_hash(self) -> None:
        project = {
            "id": "test.nes",
            "platform": "nes",
            "expected_size": 20,
            "expected_sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.nes"
            path.write_bytes(b"NES\x1a" + bytes(16))
            with self.assertRaises(build_fixtures.FixtureError):
                build_fixtures.validate_rom(project, path)

    def test_asm68k_adapter_lowers_legacy_syntax(self) -> None:
        source_text = """Root:
@Entry: macro name
VALUE_\\name: rs.b 1
    endm
    @Entry One
    purge @Entry
@Entry macro name
    dc.l \\name
    endm
    @Entry Two
Blob: hex FE00ff
Fraction: equ SIZE*10/1024%10
    move.w #-SPEED/2, d0
    inform 0, \"Size: %d\", *
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test.68k"
            source.write_text(source_text, encoding="utf-8")
            build_fixtures.adapt_asm68k_for_clownassembler(Path(directory))
            result = source.read_text(encoding="utf-8")

        self.assertIn("__rt_Root_Entry: macro", result)
        self.assertIn("__rt_Root_Entry One", result)
        self.assertIn("purge __rt_Root_Entry", result)
        self.assertIn("__rt_Root_Entry macro", result)
        self.assertIn("__rt_Root_Entry Two", result)
        self.assertIn("dc.b $FE,$00,$ff", result)
        self.assertIn("#(-(SPEED/2))", result)
        self.assertIn("; retrolarium: omitted build diagnostic", result)
        self.assertNotIn("%10", result)

    def test_snes_checksum_replaces_arbitrary_placeholder(self) -> None:
        header = 0x7FC0
        data = bytearray(0x8000)
        data[header + 0x15] = 0x20
        data[header + 0x1C:header + 0x20] = b"bad!"
        checksum = ucon64_compat.patch_checksum(data, header)
        complement = int.from_bytes(data[header + 0x1C:header + 0x1E], "little")
        stored = int.from_bytes(data[header + 0x1E:header + 0x20], "little")
        self.assertEqual(checksum, stored)
        self.assertEqual(0xFFFF, checksum ^ complement)
        self.assertEqual(checksum, sum(data) & 0xFFFF)


if __name__ == "__main__":
    unittest.main()
