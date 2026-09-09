from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest
import zipfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.toolchain import ToolchainError, load_lock, safe_extract


class ToolchainTests(unittest.TestCase):
    def test_disassembly_lock_is_complete(self) -> None:
        lock = load_lock()
        self.assertEqual("12.1.3", lock["ghidra"]["version"])
        self.assertEqual(64, len(lock["ghidra"]["sha256"]))
        self.assertEqual(64, len(lock["nes_loader"]["sha256"]))

    def test_zip_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.txt", "bad")
            with self.assertRaises(ToolchainError):
                safe_extract(archive, root / "output")


if __name__ == "__main__":
    unittest.main()
