"""The CLI's guard of the output folder: the input ROM and edited sources."""

from __future__ import annotations

import os
import sys
from pathlib import Path
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_disassembler.cli import RUN_MARKER, OutputError, guard_output, guarded_output


class OutputGuardTests(unittest.TestCase):
    def test_a_rom_inside_the_output_folder_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "work"
            rom = output / "generated" / "assets" / "header.bin"
            rom.parent.mkdir(parents=True)
            rom.write_bytes(b"NES\x1a")
            with self.assertRaises(OutputError):
                guard_output(rom, output, replace=False)
            # Beside the project, at the folder's top, it is safe.
            guard_output(output / "game.nes", output, replace=False)

    def test_sources_edited_since_the_last_run_need_replace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rom = output / "game.nes"
            source = output / "generated" / "src" / "main.asm"
            source.parent.mkdir(parents=True)
            source.write_text("; generated\n", encoding="utf-8")
            manifest = output / "retrolarium-project.json"
            manifest.write_text("{}", encoding="utf-8")
            then = time.time() - 60
            os.utime(manifest, (then, then))
            os.utime(source, (then, then))
            guard_output(rom, output, replace=False)
            source.write_text("; edited by hand\n", encoding="utf-8")
            with self.assertRaisesRegex(OutputError, "--replace"):
                guard_output(rom, output, replace=False)
            guard_output(rom, output, replace=True)

    def project(self, output: Path) -> tuple[Path, Path]:
        source = output / "generated" / "src" / "main.asm"
        source.parent.mkdir(parents=True)
        source.write_text("; generated\n", encoding="utf-8")
        manifest = output / "retrolarium-project.json"
        manifest.write_text("{}", encoding="utf-8")
        then = time.time() - 60
        os.utime(manifest, (then, then))
        os.utime(source, (then, then))
        return output / "game.nes", source

    def test_an_unfinished_run_is_reported_as_such(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rom, source = self.project(output)
            with self.assertRaises(KeyboardInterrupt):
                with guarded_output(rom, output, replace=False):
                    source.write_text("; half rewritten\n", encoding="utf-8")
                    raise KeyboardInterrupt
            self.assertTrue((output / RUN_MARKER).is_file())
            with self.assertRaisesRegex(OutputError, "did not finish") as caught:
                guard_output(rom, output, replace=False)
            self.assertNotIn("changed since", str(caught.exception))
            with guarded_output(rom, output, replace=True):
                pass
            self.assertFalse((output / RUN_MARKER).exists())

    def test_a_failed_run_that_rewrote_nothing_does_not_block_the_next(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rom, _source = self.project(output)
            with self.assertRaises(RuntimeError):
                with guarded_output(rom, output, replace=False):
                    raise RuntimeError("Ghidra failed")
            self.assertTrue((output / RUN_MARKER).is_file())
            guard_output(rom, output, replace=False)

    def test_a_finished_run_removes_its_mark(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            with guarded_output(output.parent / "game.nes", output, replace=False):
                self.assertTrue((output / RUN_MARKER).is_file())
            self.assertFalse((output / RUN_MARKER).exists())


if __name__ == "__main__":
    unittest.main()
