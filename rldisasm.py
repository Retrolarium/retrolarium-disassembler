#!/usr/bin/env python3
"""Run Retrolarium Disassembler directly from a source checkout."""

from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

try:
    from retrolarium_disassembler.cli import main  # noqa: E402
except ImportError as error:
    if error.name == "retrolarium_core":
        raise SystemExit(str(error)) from None
    raise


if __name__ == "__main__":
    raise SystemExit(main())
