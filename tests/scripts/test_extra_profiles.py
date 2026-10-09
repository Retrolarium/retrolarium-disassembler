from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.benchmarks.extra_reference import benchmark, comparable
from tools.references.extra_profiles import (
    PROFILES, TJE_SHA1, Identity, classify_build, confirm_existing, genesis_checksum,
    inspect_sega_cd_image, landstalker_build, normalise_vasm_listing, option_overrides,
    parse_simple_yaml, prepare_profile, quackshot_name, read_header, scan_roms,
    sega_cd_applicability, select_split_input, vasm_absolute_pc_labels,
    nemesis_cli_compress,
)
from tools.references.prepare_extra import PROFILES as FIRST_BATCH
from tools.benchmarks.source import read_listing


REFERENCES = Path(__file__).resolve().parents[2] / "references"


def make_rom(serial="GM 00001234-00", region="JUE", size=0x1000, *, valid=True, swap=False, patch=None):
    data = bytearray(size)
    body = bytes(range(256)) * (size // 256 + 1)
    data[0x200:] = body[:size - 0x200]
    if swap:  # different contents, same additive checksum
        data[0x200:0x202], data[0x202:0x204] = data[0x202:0x204], data[0x200:0x202]
    data[0x100:0x110] = b"SEGA MEGA DRIVE "
    data[0x180:0x18E] = serial.ljust(14).encode()
    data[0x1F0:0x200] = region.ljust(16).encode()
    checksum = genesis_checksum(bytes(data))
    if patch is not None:  # a hack that kept the original header checksum
        data[patch] ^= 0xFF
    data[0x18E:0x190] = (checksum if valid else checksum ^ 0x1111).to_bytes(2, "big")
    return bytes(data)


def identity_of(rom: bytes) -> Identity:
    header = read_header(rom)
    return Identity(header.serial, header.checksum, header.region, header.size)


class HeaderAndSelectionTests(unittest.TestCase):
    def test_nemesis_cli_rejects_a_successful_tool_with_wrong_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool, source, target = root / "tool.exe", root / "plain.bin", root / "packed.bin"
            tool.write_bytes(b"tool")
            source.write_bytes(bytes(range(32)))
            target.write_bytes(b"stale")

            def incorrect_tool(command, **kwargs):
                self.assertFalse(target.exists()) if command[1] == "-ca" else None
                Path(command[-1]).write_bytes(b"wrong")
                return type("Result", (), {"returncode": 0})()

            with patch("tools.references.extra_profiles.subprocess.run", side_effect=incorrect_tool):
                with self.assertRaisesRegex(RuntimeError, "round-trip mismatch"):
                    nemesis_cli_compress(tool, source, target)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_header_fields_and_checksum_validity(self):
        rom = make_rom()
        header = read_header(rom)
        self.assertEqual(("GM 00001234-00", "JUE", 0x1000), (header.serial, header.region, header.size))
        self.assertTrue(header.checksum_valid)
        self.assertFalse(read_header(make_rom(valid=False)).checksum_valid)
        identity = identity_of(rom)
        self.assertTrue(identity.claims(header))
        other = Identity(identity.serial, identity.checksum, "E", identity.size)
        self.assertFalse(other.claims(header))
        self.assertEqual(["region 'JUE' != 'E'"], other.differences(header))

    def test_split_input_uses_contents_not_filenames(self):
        original = make_rom()
        self.write("Totally unrelated name.gen", original)
        self.write("copy/Same bytes elsewhere.bin", original)
        self.write("Game (U) [!].gen", make_rom(patch=0x400))           # hack, stale checksum
        self.write("Game (U) [b].bin", original + bytes(0x1000))       # overdump
        self.write("notes.txt", original)                              # not a ROM suffix
        pool, problems = scan_roms([self.root])
        self.assertEqual([], problems)
        chosen = select_split_input(pool, identity_of(original))
        self.assertEqual(hashlib.sha256(original).hexdigest(), chosen.sha256)

    def test_split_input_rejects_missing_and_ambiguous_originals(self):
        original = make_rom()
        self.write("hack.gen", make_rom(patch=0x400))
        pool, _ = scan_roms([self.root])
        with self.assertRaisesRegex(ValueError, "no clean original"):
            select_split_input(pool, identity_of(original))
        self.write("a.gen", original)
        self.write("b.gen", make_rom(swap=True))
        pool, _ = scan_roms([self.root])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            select_split_input(pool, identity_of(original))

    def test_classification_of_assembled_rom(self):
        built = make_rom()
        identity = identity_of(built)
        self.write("unrelated.gen", make_rom(serial="GM 00009999-00"))
        pool, _ = scan_roms([self.root])
        self.assertEqual("upstream-only", classify_build(built, identity, pool)["status"])
        self.write("same-release-different-bytes.gen", make_rom(swap=True))
        pool, _ = scan_roms([self.root])
        result = classify_build(built, identity, pool)
        self.assertEqual("original-mismatch", result["status"])
        self.assertEqual("0x000200", result["mismatched_originals"][0]["first_differing_offset"])
        self.write("exact.gen", built)
        pool, _ = scan_roms([self.root])
        result = classify_build(built, identity, pool)
        self.assertEqual("verified-original", result["status"])
        self.assertEqual([str((self.root / "exact.gen").resolve())], result["matching_original_roms"])

    def test_related_release_is_reported_but_not_accepted(self):
        built = make_rom(serial="GM 00001234-01", size=0x1000)
        self.write("rev01-bigger.gen", make_rom(serial="GM 00001234-01", size=0x2000))
        self.write("rev00.gen", make_rom(serial="GM 00001234-00"))
        pool, _ = scan_roms([self.root])
        result = classify_build(built, identity_of(built), pool)
        self.assertEqual("original-mismatch", result["status"])
        self.assertEqual(1, len(result["mismatched_originals"]))
        self.assertEqual(1, len(result["related_supplied_roms"]))

    def test_inventory_hash_mismatch_excludes_candidate(self):
        path = self.write("roms/game.gen", make_rom())
        inventory = self.write("inventory.json", json.dumps(
            [{"path": str(path), "sha256": "0" * 64},
             {"path": str(self.root / "missing.gen"), "sha256": "1" * 64}]).encode())
        pool, problems = scan_roms([self.root / "roms"], inventory)
        self.assertEqual([], pool)
        self.assertEqual(["SHA-256 differs from inventory; excluded",
                          "listed original is missing or not a cartridge file"],
                         [item["problem"] for item in problems])

    def test_confirm_existing_matches_by_hash_without_rebuild(self):
        dest = self.root / "kid-chameleon-us"
        dest.mkdir()
        binary = make_rom(serial="GM MK-1010 -00")
        (dest / "reference.bin").write_bytes(binary)
        (dest / "reference-m68k.lst").write_bytes(b"listing\n")
        record = {"name": "kid-chameleon-us", "status": "upstream-only", "matching_original_roms": [],
                  "binary_sha256": hashlib.sha256(binary).hexdigest(),
                  "listing_sha256": hashlib.sha256(b"listing\n").hexdigest()}
        (dest / "result.json").write_text(json.dumps(record), encoding="utf-8")
        self.write("roms/Kid Chameleon/whatever.gen", binary)
        self.write("roms/Kid Chameleon/Chameleon Kid (J) [!].gen", make_rom(serial="GM MK-1010 -00", swap=True))
        pool, _ = scan_roms([self.root / "roms"])
        result = confirm_existing(dest, pool, ["roms"])
        self.assertEqual("verified-original", result["status"])
        self.assertEqual(1, len(result["independent_confirmation"]["matching_roms"]))
        (dest / "reference.bin").write_bytes(binary + b"\0\0")
        with self.assertRaisesRegex(ValueError, "recorded SHA-256"):
            confirm_existing(dest, pool, ["roms"])


class UpstreamConfigurationTests(unittest.TestCase):
    OPTIONS = ("\nbugfixes = 0\t\t\t; if 1, include bug fixes\r\n"
               "revision = 1\t\t\t; 0 = Japanese; 1 = English; 2 = Portuguese\r\n")

    def test_option_override_is_scoped_and_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ps3.options.asm"
            path.write_bytes(self.OPTIONS.encode())
            with option_overrides(Path(directory), {"ps3.options.asm": {"revision": "0", "bugfixes": "0"}}) as applied:
                text = path.read_text(encoding="utf-8")
                self.assertIn("revision = 0\t\t\t; 0 = Japanese", text)
                self.assertEqual({"revision": "1", "bugfixes": "0"}, applied["ps3.options.asm"]["pinned_values"])
            self.assertEqual(self.OPTIONS.encode(), path.read_bytes())
            with self.assertRaises(RuntimeError):
                with option_overrides(Path(directory), {"ps3.options.asm": {"revision": "2"}}):
                    raise RuntimeError("assembly failed")
            self.assertEqual(self.OPTIONS.encode(), path.read_bytes())
            with self.assertRaisesRegex(ValueError, "expected one 'cross_patch ='"):
                with option_overrides(Path(directory), {"ps3.options.asm": {"cross_patch": "0"}}):
                    pass
            self.assertEqual(self.OPTIONS.encode(), path.read_bytes())

    def test_build_yaml_subset_and_expanded_rejection(self):
        text = ("Builds:\n    US:\n        Source: landstalker_us.asm\n        Target: landstalker_us.bin\n"
                "        Buildopts: /p /d /o ae-,l_\n        Defines:\n            REGION: 0\n"
                "            EXPANDED: 0\n    US_EXPANDED:\n        Source: landstalker_us_expanded.asm\n"
                "        Buildopts: /p\n        Defines:\n            EXPANDED: 1\n")
        self.assertEqual("0", parse_simple_yaml(text)["Builds"]["US"]["Defines"]["REGION"])
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "build.yaml").write_text(text, encoding="utf-8")
            build = landstalker_build(Path(directory), "US")
            self.assertEqual({"REGION": "0", "EXPANDED": "0"}, build["defines"])
            self.assertEqual("/p /d /o ae-,l_", build["buildopts"])
            with self.assertRaisesRegex(ValueError, "expanded"):
                landstalker_build(Path(directory), "US_EXPANDED")
            with self.assertRaisesRegex(ValueError, "no FR build"):
                landstalker_build(Path(directory), "FR")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_simple_yaml("A:\n    B: 1\n    B: 2\n")

    @unittest.skipUnless((REFERENCES / "landstalker_disasm/build.yaml").is_file(), "reference checkout absent")
    def test_pinned_landstalker_profiles_match_build_scripts(self):
        root = REFERENCES / "landstalker_disasm"
        japanese = landstalker_build(root, "JP")
        self.assertEqual("landstalker_jp.asm", japanese["source"])
        self.assertEqual(("1", "0", "1"), tuple(japanese["defines"][key]
                                                for key in ("REGION", "FIX_COLL_1", "REFRESH_GOLD_CTR")))
        german = landstalker_build(root, "DE")
        self.assertEqual(("4", "0"), (german["defines"]["REGION"], german["defines"]["REFRESH_GOLD_CTR"]))

    def test_quackshot_level_name_conversion(self):
        table = {"A": 11, "0": 1, " ": 59}
        self.assertEqual(bytes.fromhex("200B2001203B"), quackshot_name("A0?\r\n", table))


class ListingTests(unittest.TestCase):
    LISTING = [
        "F00:0001       \torg\t$0",
        "F00:0002       Start:",
        "F00:0003       \tmoveq\t#0,d0",
        "               S01:00000000:  70 00",
        "F00:0004       Table\tdc.w\t$1234",
        "               S01:00000002:  12 34",
        "F00:0005       \tmove.l\t#$12345678,($00FF0000).l",
        "               S01:00000004:  23 FC 12 34 56 78 00 FF",
        "               S01:0000000C:  00 00",
        "F00:0006       Loop\trts",
        "               S01:0000000E:  4E 75",
        "",
        "Symbols by name:",
        "Loop                            A:0000000E",
    ]
    ROM = bytes.fromhex("70001234" "23FC1234567800FF0000" "4E75")

    def read(self, lines, rom):
        with tempfile.TemporaryDirectory() as directory:
            listing, output = Path(directory) / "in.lst", Path(directory) / "out.lst"
            listing.write_text("\n".join(lines) + "\n", encoding="utf-8")
            found, uncertain, stats = normalise_vasm_listing(listing, rom, output)
            recovered, recovered_open = read_listing(output, rom)
            text = output.read_text(encoding="utf-8")
        return found, uncertain, stats, recovered, recovered_open, text

    def test_vasm_listing_round_trips_instructions_labels_and_data(self):
        found, uncertain, stats, recovered, recovered_open, text = self.read(self.LISTING, self.ROM)
        self.assertEqual({0: self.ROM[0:2], 4: self.ROM[4:14], 14: self.ROM[14:16]}, found)
        self.assertEqual(found, recovered)
        self.assertFalse(uncertain or recovered_open)
        self.assertEqual(3, stats["reference_instructions"])
        for label in ("Start:", "Table:", "Loop:"):
            self.assertIn(label, text)

    def test_vasm_listing_must_agree_with_rom_and_contain_code(self):
        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.read(self.LISTING, self.ROM[:3] + b"\xff" + self.ROM[4:])
        with self.assertRaisesRegex(ValueError, "no recognised M68K"):
            self.read(self.LISTING[:1] + self.LISTING[4:6], self.ROM)
        with self.assertRaisesRegex(ValueError, "several sections"):
            self.read(self.LISTING + ["F00:0007       \tnop", "               S02:00000000:  4E 71"], self.ROM)
        with self.assertRaisesRegex(ValueError, "non-contiguous"):
            self.read(self.LISTING[:8] + ["               S01:0000000D:  00 00"], self.ROM)


def sega_cd_image(serial, region, raw=False):
    area = bytearray(0x800)
    area[0:16] = b"SEGADISCSYSTEM  "
    area[0x100:0x110] = b"SEGA MEGA DRIVE "
    area[0x180:0x190] = serial.ljust(16).encode()
    area[0x1F0:0x200] = region.ljust(16).encode()
    if raw:
        return bytes.fromhex("00FFFFFFFFFFFFFFFFFFFF00") + b"\0\0\0\x01" + bytes(area) + bytes(0x120)
    return bytes(area)


class SegaCdTests(unittest.TestCase):
    image = staticmethod(sega_cd_image)

    def inspect(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disc.iso"
            path.write_bytes(data)
            return inspect_sega_cd_image(path)

    def test_japanese_disc_is_a_different_release(self):
        japanese = sega_cd_applicability(self.inspect(self.image("GM T-33024 -00", "J")))
        self.assertFalse(japanese["same_release"])
        self.assertFalse(japanese["comparison_valid"])
        same = sega_cd_applicability(self.inspect(self.image("GM MK-4656 -00", "E", raw=True)))
        self.assertEqual("raw-2352", same["disc_identity"]["layout"])
        self.assertTrue(same["same_release"])
        self.assertFalse(same["comparison_valid"])
        with self.assertRaisesRegex(ValueError, "not a Sega CD"):
            self.inspect(bytes(0x1000))


class ProfileTableTests(unittest.TestCase):
    def test_numeric_pc_adapter_preserves_comments_and_register_offsets(self):
        source = ' move.w $170e0(pc,d0.l),d0 ; $abcd(pc)\n lea $20(a0),a1\n dc.b "$123(pc)"\n'
        translated, count = vasm_absolute_pc_labels(source)
        self.assertEqual(1, count)
        self.assertEqual(' move.w (__rl_rom_base+$170e0)(pc,d0.l),d0 ; $abcd(pc)\n lea $20(a0),a1\n dc.b "$123(pc)"\n', translated)

    def test_default_vasm_listing_retains_continuation_bytes(self):
        rom = bytes.fromhex("23FC12345678000100004E75")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vasm.lst"
            out = Path(directory) / "normal.lst"
            path.write_text("00:00000000 23FC123456780001\t 1: move.l #$12345678,($10000).l\n"
                            "00:00000008 0000\n00:0000000A 4E75\t 2: rts\n", encoding="utf-8")
            found, uncertain, _ = normalise_vasm_listing(path, rom, out)
            self.assertEqual({0: rom[:10], 10: rom[10:]}, found)
            self.assertFalse(uncertain)
            self.assertEqual((found, uncertain), read_listing(out, rom))

    def test_first_batch_is_unchanged_and_names_are_disjoint(self):
        self.assertEqual({"altered-beast-ue-rev02", "spinball-us", "mean-bean", "shining-force-us",
                          "shining-force-2-us", "kid-chameleon-us"}, set(FIRST_BATCH))
        self.assertFalse(set(FIRST_BATCH) & set(PROFILES))

    def test_every_profile_is_explicit(self):
        for profile in PROFILES.values():
            with self.subTest(profile.name):
                self.assertRegex(profile.commit, r"^[0-9a-f]{40}$")
                if profile.family == "unsupported":
                    self.assertTrue(profile.reason)
                    continue
                self.assertIsNotNone(profile.identity)
                self.assertTrue(profile.entry or profile.variant)
                self.assertTrue(profile.identity.serial.startswith("GM "))
        # Regional variants must differ in at least one checked header field.
        identities = [profile.identity for profile in PROFILES.values() if profile.identity]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertIn("revision", PROFILES["phantasy-star-3-j"].overrides["ps3.options.asm"])
        self.assertEqual("0", PROFILES["phantasy-star-4-j"].overrides["ps4.options.asm"]["revision"])

    def test_unsupported_profiles_write_honest_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disc = root / "sfcd-j.iso"
            disc.write_bytes(sega_cd_image("GM T-33024 -00", "J"))
            result = prepare_profile("shining-force-cd", root / "refs", root / "out/sfcd", [],
                                     {"sega_cd_image": disc})
            self.assertEqual("unsupported", result["status"])
            self.assertFalse(result["applicability"]["same_release"])
            self.assertTrue((root / "out/sfcd/result.json").is_file())
            result = prepare_profile("toejam-earl-rev02", root / "refs", root / "out/tje", [], {})
            self.assertEqual("unsupported", result["status"])
            self.assertEqual([], result["supplied_revisions"])
        self.assertIn("85e8d0a4fac591b25b77c35680ac4175976f251b", TJE_SHA1)

    def test_missing_checkout_is_blocked_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = prepare_profile("landstalker-us", root / "refs", root / "out", [], {})
            self.assertEqual("blocked", result["status"])
            self.assertNotIn("binary_sha256", result)


class BenchmarkAdapterTests(unittest.TestCase):
    def test_only_verified_originals_are_scored(self):
        self.assertIn("not a verified original", comparable({"status": "upstream-only"}))
        self.assertIn("not a verified original", comparable({"status": "original-mismatch",
                                                             "matching_original_roms": ["x"]}))
        unit = {"status": "verified-original", "matching_original_roms": ["x"], "matches_upstream": True,
                "reference_instructions": 0}
        self.assertIn("no instructions", comparable(unit))
        unit["reference_instructions"] = 5
        self.assertIsNone(comparable(unit))
        unit["listing_provenance"] = {"instructions_outside_rom": 1}
        self.assertIn("outside the ROM", comparable(unit))

    def test_changed_listing_is_an_error_and_skips_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom = make_rom()
            (root / "main.s").write_text(" nop\n", encoding="utf-8")
            (root / "reference.bin").write_bytes(rom)
            (root / "original.gen").write_bytes(rom)
            (root / "reference-m68k.lst").write_text("changed\n", encoding="utf-8")
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            units = [{"name": "case", "status": "verified-original", "matches_upstream": True,
                      "matching_original_roms": [str(root / "original.gen")], "reference_instructions": 1,
                      "uncertain_instruction_addresses": 0, "source": str(root / "main.s"),
                      "source_sha256": digest(root / "main.s"), "binary": str(root / "reference.bin"),
                      "binary_sha256": digest(root / "reference.bin"),
                      "listing": str(root / "reference-m68k.lst"), "listing_sha256": "0" * 64},
                     {"name": "other", "status": "upstream-only"}]
            (root / "manifest.json").write_text(json.dumps({"units": units}), encoding="utf-8")
            report = benchmark(root, root / "projects", root / "comparison")
            self.assertEqual("normalized reference listing hash changed", report["cases"][0]["error"])
            self.assertEqual(["other"], [item["name"] for item in report["not_comparable"]])
            self.assertTrue((root / "comparison/summary.md").is_file())


if __name__ == "__main__":
    unittest.main()
