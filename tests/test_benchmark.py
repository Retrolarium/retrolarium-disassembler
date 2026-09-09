from __future__ import annotations

import json
import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.benchmark import BenchmarkError, score_pointer_report


class BenchmarkTests(unittest.TestCase):
    def write_inputs(self, root: Path, report_hash: str = "abc") -> tuple[Path, Path]:
        report = {
            "schema_version": 1,
            "input_sha256": report_hash,
            "candidates": [
                {
                    "id": "found",
                    "schema_id": "nes.u16le",
                    "physical_start": 16,
                    "physical_end": 24,
                    "status": "accepted",
                    "entries": [{"target": value} for value in (0xC100, 0xC110)],
                },
                {
                    "id": "not-promoted",
                    "schema_id": "nes.u16le",
                    "physical_start": 32,
                    "physical_end": 40,
                    "status": "candidate",
                    "entries": [{"target": 0xC200}],
                },
            ],
        }
        oracle = {
            "schema_version": 1,
            "fixture_id": "synthetic",
            "input_sha256": "abc",
            "coverage": "complete_for_evaluated_schemas",
            "evaluated_schemas": ["nes.u16le"],
            "pointer_tables": [
                {
                    "id": "expected",
                    "schema_id": "nes.u16le",
                    "physical_start": 16,
                    "physical_end": 24,
                    "entries": [{"target": value} for value in (0xC100, 0xC110)],
                }
            ],
        }
        report_path = root / "report.json"
        oracle_path = root / "oracle.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
        return report_path, oracle_path

    def test_scores_ranges_and_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, oracle = self.write_inputs(Path(directory))
            result = score_pointer_report(report, oracle)

        self.assertEqual(1.0, result["tables"]["precision"])
        self.assertEqual(1.0, result["tables"]["recall"])
        self.assertEqual(1.0, result["targets"]["accuracy"])

    def test_rejects_cross_rom_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, oracle = self.write_inputs(Path(directory), report_hash="different")
            with self.assertRaises(BenchmarkError):
                score_pointer_report(report, oracle)


if __name__ == "__main__":
    unittest.main()
