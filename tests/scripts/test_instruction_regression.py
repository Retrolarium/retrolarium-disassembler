from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from instruction_regression import audit_listings, compare_instruction_sets, main, read_complete_listing


def line(address, encoded, source):
    return f"   1/{address:8X} : {encoded.ljust(21)}{source}"


class InstructionRegressionTests(unittest.TestCase):
    def test_net_gain_cannot_hide_a_lost_instruction(self):
        reference = {0: b"\x4e\x71", 2: b"\x70\x00", 4: b"\x4e\x75"}
        result = compare_instruction_sets(reference, {0: reference[0]}, {2: reference[2], 4: reference[4]})
        self.assertEqual(("regressed", 1, 1, 2),
                         (result["status"], result["net_delta"], result["lost_count"], result["gained_count"]))
        self.assertEqual(0, result["lost"][0]["offset"])

    def test_shared_opcode_prefix_with_changed_length_is_a_loss(self):
        expected = bytes.fromhex("33fc000100a11100")
        result = compare_instruction_sets({0: expected}, {0: expected}, {0: expected[:6]})
        self.assertEqual("regressed", result["status"])
        self.assertEqual(1, result["after"]["different_encodings"])

    def test_labels_and_order_do_not_affect_set_identity(self):
        reference = {0: b"\x4e\x71", 2: b"\x4e\x75"}
        result = compare_instruction_sets(reference, reference, dict(reversed(list(reference.items()))))
        self.assertEqual("preserved", result["status"])
        self.assertEqual(result["before_matched_sha256"], result["after_matched_sha256"])

    def test_unknown_instruction_length_is_not_a_full_match(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.lst"
            path.write_text(line(0, "33FC 0001 00A1", "move.w #1,($a11100).l"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown instruction lengths"):
                read_complete_listing(path, bytes.fromhex("33fc000100a11100"))

    def fixture(self, folder):
        folder = Path(folder)
        rom = folder / "rom.bin"
        rom.write_bytes(bytes.fromhex("4e714e75"))
        reference, before, after = (folder / (name + ".lst") for name in ("ref", "before", "after"))
        text = "\n".join([line(0, "4E71", "nop"), line(2, "4E75", "rts")])
        reference.write_text(text, encoding="utf-8")
        before.write_text(text, encoding="utf-8")
        after.write_text(line(0, "4E71 4E75", "dc.w $4e71,$4e75"), encoding="utf-8")
        return rom, reference, before, after

    def test_emitting_same_bytes_as_data_is_still_code_loss(self):
        with tempfile.TemporaryDirectory() as folder:
            rom, reference, before, after = self.fixture(folder)
            result = audit_listings(rom, reference, before, after, rom, rom)
        self.assertEqual("exact", result["rebuild_status"])
        self.assertEqual(("regressed", 2), (result["status"], result["lost_count"]))

    def test_rebuild_difference_and_listing_byte_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            rom, reference, before, after = self.fixture(folder)
            changed = Path(folder) / "changed.bin"
            changed.write_bytes(b"\0" * 4)
            with self.assertRaisesRegex(ValueError, "rebuilt image differs"):
                audit_listings(rom, reference, before, after, rom, changed)
            after.write_text(line(0, "4E75", "rts"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "disagrees with ROM"):
                audit_listings(rom, reference, before, after, rom, rom)

    def test_overlay_addresses_normalize_and_below_base_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "overlay.lst"
            path.write_text(line(0x200000, "4E75", "rts"), encoding="utf-8")
            self.assertEqual({0: bytes.fromhex("4e75")}, read_complete_listing(path, bytes.fromhex("4e75"), 0x200000))
            with self.assertRaisesRegex(ValueError, "disagrees with ROM"):
                read_complete_listing(path, bytes.fromhex("4e75"), 0x200002)

    def test_empty_or_unrecognized_reference_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            rom, reference, before, after = self.fixture(folder)
            reference.write_text("not an AS listing", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reference listing has no complete instructions"):
                audit_listings(rom, reference, before, after, rom, rom)

    def test_cli_regression_failure_writes_reviewable_report(self):
        with tempfile.TemporaryDirectory() as folder:
            rom, reference, before, after = self.fixture(folder)
            output = Path(folder) / "result.json"
            arguments = dict(rom=rom, reference=reference, before=before, after=after,
                             **{"before-rom": rom, "after-rom": rom, "output": output})
            argv = [value for name, path in arguments.items() for value in ("--" + name, str(path))]
            self.assertEqual(1, main(argv))
            self.assertEqual(2, json.loads(output.read_text())["lost_count"])
            rom.unlink()
            self.assertEqual(2, main(argv))
            self.assertEqual("invalid", json.loads(output.read_text())["status"])


if __name__ == "__main__":
    unittest.main()
