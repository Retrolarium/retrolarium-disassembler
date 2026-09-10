from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.toolchain import (
    ToolchainError,
    install_snes_backend,
    load_lock,
    safe_extract,
)


class ToolchainTests(unittest.TestCase):
    def test_disassembly_lock_is_complete(self) -> None:
        lock = load_lock()
        self.assertEqual("12.1.3", lock["ghidra"]["version"])
        self.assertEqual(64, len(lock["ghidra"]["sha256"]))
        self.assertEqual(64, len(lock["nes_loader"]["sha256"]))
        self.assertEqual("MIT", lock["snes_backend"]["license"])
        self.assertEqual("65816:LE:24:snes", lock["snes_backend"]["language_id"])
        self.assertEqual(64, len(lock["snes_backend"]["sha256"]))

    def test_zip_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.txt", "bad")
            with self.assertRaises(ToolchainError):
                safe_extract(archive, root / "output")

    def test_installs_only_pinned_snes_language_and_license(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = "ghidra-snes-pinned"
            archive = root / "backend.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(
                    f"{source_root}/data/languages/65816.slaspec",
                    "define endian=little;",
                )
                bundle.writestr(
                    f"{source_root}/data/languages/65816.ldefs",
                    'id="65816:LE:24:snes"',
                )
                bundle.writestr(f"{source_root}/LICENSE", "MIT License")
                bundle.writestr(
                    f"{source_root}/src/main/java/UnwantedLoader.java", "loader"
                )
            ghidra = root / "ghidra"
            support = ghidra / "support"
            support.mkdir(parents=True)
            compiler = support / ("sleigh.bat" if sys.platform == "win32" else "sleigh")
            compiler.write_text("compiler", encoding="utf-8")
            expected = {
                "name": "Retrolarium65816",
                "source_directory": source_root,
                "commit": "1" * 40,
                "language_id": "65816:LE:24:snes",
            }

            def compile_language(command: list[str], **_: object):
                Path(command[1]).with_suffix(".sla").write_bytes(b"compiled")
                return type("Result", (), {"returncode": 0, "stdout": "ok"})()

            with patch(
                "retrolarium_kit.toolchain.subprocess.run",
                side_effect=compile_language,
            ):
                install_snes_backend(
                    ghidra, archive, expected, root / "staging"
                )

            installed = ghidra / "Ghidra" / "Extensions" / "Retrolarium65816"
            self.assertTrue((installed / "data/languages/65816.sla").is_file())
            self.assertEqual(
                "MIT License",
                (installed / "LICENSE.upstream").read_text(encoding="utf-8"),
            )
            self.assertFalse((installed / "src").exists())


if __name__ == "__main__":
    unittest.main()
