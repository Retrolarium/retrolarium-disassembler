from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from source_benchmark import instruction_quality


class SourceBenchmarkTests(unittest.TestCase):
    def test_instruction_quality_reports_recall_precision_and_f1(self) -> None:
        self.assertEqual(
            {
                "instruction_recall_percentage": 80.0,
                "instruction_precision_percentage": 88.89,
                "instruction_f1_percentage": 84.21,
            },
            instruction_quality(80, 100, 90),
        )

    def test_empty_instruction_sets_are_perfect(self) -> None:
        self.assertEqual(
            {
                "instruction_recall_percentage": 100.0,
                "instruction_precision_percentage": 100.0,
                "instruction_f1_percentage": 100.0,
            },
            instruction_quality(0, 0, 0),
        )


if __name__ == "__main__":
    unittest.main()
