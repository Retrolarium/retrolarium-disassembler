"""CI resolves the checked-in Core commit, rejecting floating revisions."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / "tools/core_pin.py"


class CorePinTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".github").mkdir()
        self.pin = self.root / ".github/core-ref"
        self.output = self.root / "actions-output"

    def run_pin(self):
        return subprocess.run(
            [sys.executable, "-B", str(TOOL)],
            cwd=self.root,
            env=dict(os.environ, GITHUB_OUTPUT=str(self.output)),
            capture_output=True,
            text=True,
        )

    def test_the_checked_in_commit_is_the_actions_output(self):
        self.pin.write_text("a" * 40 + "\n", encoding="utf-8")
        result = self.run_pin()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("sha=" + "a" * 40 + "\n", self.output.read_text(encoding="utf-8"))

    def test_updating_the_file_changes_the_resolved_commit(self):
        for sha in ("a" * 40, "b" * 40):
            self.pin.write_text(sha + "\n", encoding="utf-8")
            self.assertEqual(0, self.run_pin().returncode)
        self.assertEqual(["sha=" + "a" * 40, "sha=" + "b" * 40], self.output.read_text().splitlines())

    def test_missing_short_and_floating_pins_are_refused(self):
        self.assertNotEqual(0, self.run_pin().returncode)
        for invalid in ("main", "abc1234", "a" * 40 + "\nsha=main", "g" * 40):
            with self.subTest(pin=invalid):
                self.pin.write_text(invalid, encoding="utf-8")
                self.assertNotEqual(0, self.run_pin().returncode)
        self.assertFalse(self.output.exists())
