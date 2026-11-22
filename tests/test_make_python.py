"""The public make entrypoint selects Python for its requested host."""

import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "GNU make is not installed")
class MakePythonTests(unittest.TestCase):
    def command(self, host, override=None):
        environment = dict(os.environ)
        environment.pop("PYTHON", None)
        environment.pop("MAKEFLAGS", None)
        command = ["make", "--no-print-directory", "-n", "test-python", "OS=" + host]
        if override is not None:
            command.append("PYTHON=" + override)
        return subprocess.check_output(command, cwd=ROOT, env=environment, text=True).splitlines()

    def test_windows_uses_the_installed_python_command(self):
        self.assertIn("python tools/test.py --suite python", self.command("Windows_NT"))

    def test_posix_uses_python3_without_requiring_a_python_alias(self):
        for host in ("Linux", "Darwin", ""):
            with self.subTest(host=host):
                self.assertIn("python3 tools/test.py --suite python", self.command(host))

    def test_an_explicit_interpreter_wins_on_both_hosts(self):
        for host in ("Windows_NT", "Linux"):
            with self.subTest(host=host):
                self.assertIn(
                    "chosen-python tools/test.py --suite python",
                    self.command(host, "chosen-python"),
                )
