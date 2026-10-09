from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.benchmarks.megadrive_goal_check import check_goal, evaluate_case


class MegaDriveGoalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = {
            "name": "test ROM", "minimum_source_recall_percentage": 95,
            "reference_instructions": 100, "rom_sha256": "a" * 64,
        }
        self.report = {
            "reference_rom_sha256": "a" * 64, "reference_instructions": 100,
            "source_emission": {"matching_reference_instructions": 95, "mnemonic_instructions": 95},
        }
        self.verification = {
            "status": "exact", "artifact": {"sha256": "a" * 64, "size": 1024},
            "expected": {"sha256": "a" * 64, "size": 1024},
        }

    def test_supports_both_benchmark_formats(self) -> None:
        self.assertTrue(evaluate_case(self.case, self.report, self.verification)["passed"])
        nested = {"instruction_comparison": self.report}
        self.report["source_emission"]["emitted_mnemonic_instructions"] = self.report["source_emission"].pop("mnemonic_instructions")
        result = evaluate_case({**self.case, "comparison_key": "instruction_comparison"}, nested, self.verification)
        self.assertTrue(result["passed"])
        self.assertEqual(100, result["source_precision_percentage"])

    def test_does_not_pass_rounded_percentage_below_threshold(self) -> None:
        self.case["reference_instructions"] = self.report["reference_instructions"] = 20001
        self.report["source_emission"] = {"matching_reference_instructions": 19000, "mnemonic_instructions": 19000}
        result = evaluate_case(self.case, self.report, self.verification)
        self.assertEqual(95, result["source_recall_percentage"])
        self.assertFalse(result["passed"])

    def test_rejects_changed_reference_and_wrong_rom(self) -> None:
        self.case["reference_instructions"] = 101
        self.assertFalse(evaluate_case(self.case, self.report, self.verification)["passed"])
        self.case["reference_instructions"] = 100
        self.report["reference_rom_sha256"] = "b" * 64
        self.assertFalse(evaluate_case(self.case, self.report, self.verification)["passed"])
        self.report["reference_rom_sha256"] = "a" * 64
        self.verification["status"] = "not-run"
        self.assertFalse(evaluate_case(self.case, self.report, self.verification)["passed"])

    def test_missing_report_and_empty_goal_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "goal.json"
            config.write_text(json.dumps({"cases": [{**self.case, "report_path": "absent.json", "verification_path": "absent.json"}]}))
            result = check_goal(config, root)
            self.assertFalse(result["goal_achieved"])
            self.assertIn("error", result["cases"][0])
            config.write_text('{"cases": []}')
            self.assertFalse(check_goal(config, root)["goal_achieved"])


if __name__ == "__main__":
    unittest.main()
