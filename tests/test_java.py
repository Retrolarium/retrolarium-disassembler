from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from retrolarium_disassembler.java import JavaError, java_environment
from retrolarium_disassembler.toolchain import ToolchainError, install_toolchain


class JavaPreflightTest(unittest.TestCase):
    def test_no_jdk_fails_before_any_download(self) -> None:
        with patch("retrolarium_disassembler.toolchain.java_environment", side_effect=JavaError("JDK 21 required")):
            with patch("retrolarium_disassembler.toolchain.download") as download:
                with self.assertRaisesRegex(ToolchainError, "JDK 21"):
                    install_toolchain(Path("unused"))
                download.assert_not_called()

    def test_old_java_or_jre_only_is_refused_and_a_jdk_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "bin").mkdir()
            suffix = ".exe" if os.name == "nt" else ""
            java, javac = [home / "bin" / (name + suffix) for name in ("java", "javac")]
            java.write_bytes(b"")
            with (
                patch.dict(os.environ, {"JAVA_HOME": str(home)}),
                patch("retrolarium_disassembler.java.shutil.which", return_value=None),
            ):
                for major in (17, 21):
                    javac.write_bytes(b"")
                    result = subprocess.CompletedProcess([], 0, "", f'openjdk version "{major}.0.1"\njavac {major}.0.1')
                    with patch("retrolarium_disassembler.java.subprocess.run", return_value=result):
                        if major < 21:
                            with self.assertRaisesRegex(JavaError, "JDK 21"):
                                java_environment()
                        else:
                            self.assertEqual(str(home), java_environment()["JAVA_HOME"])
                javac.unlink()
                with patch("retrolarium_disassembler.java.subprocess.run", return_value=result):
                    with self.assertRaisesRegex(JavaError, "javac.*missing"):
                        java_environment()
