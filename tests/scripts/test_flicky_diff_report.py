from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from flicky_diff_report import _code


class FlickyDiffReportTests(unittest.TestCase):
    def test_code_uses_instruction_after_location_directive(self) -> None:
        lines = [
            "                org     $10000",
            "EntryPoint:",
            "                move    #$2700,sr",
        ]

        self.assertEqual("move    #$2700,sr", _code(lines))


if __name__ == "__main__":
    unittest.main()
