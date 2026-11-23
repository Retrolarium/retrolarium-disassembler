"""Source archives locate Core without relying on this developer's checkout."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class ArchiveInstallationTest(unittest.TestCase):
    def test_archive_suffixes_and_missing_core_have_predictable_results(self) -> None:
        package = Path(__file__).resolve().parents[1] / "src/retrolarium_disassembler/__init__.py"
        for suffix in ("", "-main", "-0.5.0", None):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "retrolarium-disassembler-main/src"
                (source / "retrolarium_disassembler").mkdir(parents=True)
                shutil.copy2(package, source / "retrolarium_disassembler/__init__.py")
                if suffix is not None:
                    core = root / ("retrolarium-core" + suffix) / "python/retrolarium_core"
                    core.mkdir(parents=True)
                    (core / "__init__.py").write_text("SYNTHETIC_CORE = True\n", encoding="utf-8")
                code = (
                    "import sys; sys.path.insert(0,sys.argv[1]); "
                    "import retrolarium_disassembler; import retrolarium_core; "
                    "assert retrolarium_core.SYNTHETIC_CORE"
                )
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-c", code, str(source)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                )
                if suffix is None:
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("python -m pip install -e PATH_TO_CORE", result.stderr)
                else:
                    self.assertEqual(0, result.returncode, result.stderr)
