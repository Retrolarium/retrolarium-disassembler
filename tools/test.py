"""Run this checkout's tests with Python on Windows, Linux or macOS."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT.parent / "retrolarium-core/python"
if (CORE / "retrolarium_core/testing.py").is_file():
    sys.path.insert(0, str(CORE))
try:
    from retrolarium_core.testing import main
except ImportError as error:
    raise SystemExit(
        "The test runner needs the current retrolarium-core beside this checkout (or installed)."
    ) from error

if __name__ == "__main__":
    raise SystemExit(main(ROOT))
