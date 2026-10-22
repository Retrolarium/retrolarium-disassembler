import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.references.prepare_quackshot import extract_assets, prepare


class QuackShotReferenceTests(unittest.TestCase):
    def test_extract_only_verified_asset_bytes_into_staged_tree(self):
        rom = b"prefix-ASSET-suffix"
        item = {"path": "src/font.bin", "offset": 7, "size": 5, "sha256": hashlib.sha256(b"ASSET").hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Generated includes need not exist in a pristine upstream clone.
            self.assertEqual([item], extract_assets(root, rom, {"assets": [item]}))
            self.assertEqual(b"ASSET", (root / "src/font.bin").read_bytes())
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                extract_assets(root, b"prefix-OTHER-suffix", {"assets": [item]})
            self.assertEqual(b"ASSET", (root / "src/font.bin").read_bytes())

    def test_invalid_ranges_and_paths_cannot_copy_code_or_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stage"
            root.mkdir()
            for path in ("../escape.bin", "qs.s", "src/../../escape.bin"):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "escapes"):
                    extract_assets(
                        root,
                        b"DATA",
                        {
                            "assets": [
                                {"path": path, "offset": 0, "size": 4, "sha256": hashlib.sha256(b"DATA").hexdigest()}
                            ]
                        },
                    )
            for offset, size in ((-1, 4), (0, 0), (2, 4)):
                with self.subTest(offset=offset, size=size), self.assertRaisesRegex(ValueError, "exceeds ROM"):
                    extract_assets(
                        root,
                        b"DATA",
                        {"assets": [{"path": "src/file.bin", "offset": offset, "size": size, "sha256": "irrelevant"}]},
                    )
            self.assertEqual([], list(root.rglob("*.bin")))

    def test_wrong_revision_is_rejected_before_git_or_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom = root / "wrong.bin"
            rom.write_bytes(b"not the pinned original")
            output = root / "output"
            with self.assertRaisesRegex(ValueError, "pinned retail REV01"):
                prepare(root / "absent-checkout", rom, output, root / "absent-tools")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
