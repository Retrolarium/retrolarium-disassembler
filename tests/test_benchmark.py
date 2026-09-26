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

    def write_megadrive(
        self, root: Path, candidates: list[dict[str, object]],
        expected: list[dict[str, object]],
    ) -> tuple[Path, Path]:
        report_path = root / "report.json"
        oracle_path = root / "oracle.json"
        report_path.write_text(json.dumps({
            "schema_version": 1, "input_sha256": "abc", "candidates": candidates,
        }), encoding="utf-8")
        oracle_path.write_text(json.dumps({
            "schema_version": 1, "fixture_id": "synthetic", "input_sha256": "abc",
            "coverage": "complete_for_evaluated_schemas",
            "evaluated_schemas": ["megadrive.u32be.absolute"],
            "pointer_tables": expected,
        }), encoding="utf-8")
        return report_path, oracle_path

    @staticmethod
    def table(identifier: str, start: int, end: int, score: float = 1.0,
              status: str = "accepted") -> dict[str, object]:
        return {
            "id": identifier, "schema_id": "megadrive.u32be.absolute",
            "physical_start": start, "physical_end": end, "status": status,
            "score": score, "entry_size": 4,
            "entries": [{"target": 0x1000 + offset} for offset in range(start, end, 4)],
        }

    def test_scores_only_tables_the_emitter_selects(self) -> None:
        candidates = [
            self.table("winner", 0x400, 0x410, score=0.9),
            self.table("overlapped", 0x408, 0x418, score=0.5),
            self.table("header", 0x100, 0x110, score=1.0),
            self.table("in-z80", 0x800, 0x810, score=1.0),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, oracle = self.write_megadrive(
                root, candidates, [self.table("expected", 0x400, 0x410)]
            )
            project = root / "retrolarium-project.json"
            project.write_text(json.dumps({"source": {"assets": [
                {"kind": "z80_program", "rom_file_offset": 0x800, "size": 0x100},
            ]}}), encoding="utf-8")
            result = score_pointer_report(report, oracle, project)

        self.assertEqual(4, result["tables"]["accepted"])
        self.assertEqual(1, result["tables"]["selected"])
        self.assertEqual(1.0, result["tables"]["precision"])
        self.assertEqual(1.0, result["tables"]["recall"])
        self.assertEqual([], result["false_positive_candidates"])

    def test_scores_range_overlap_for_inexact_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, oracle = self.write_megadrive(
                Path(directory),
                [self.table("short", 0x400, 0x40C), self.table("elsewhere", 0x600, 0x604)],
                [self.table("expected", 0x400, 0x410)],
            )
            result = score_pointer_report(report, oracle)

        self.assertEqual(0, result["tables"]["true_positive"])
        self.assertEqual(1, result["tables"]["partial"])
        self.assertEqual(
            [{
                "oracle_id": "expected", "candidate_id": "short", "overlap_bytes": 12,
                "oracle_range": [0x400, 0x410], "candidate_range": [0x400, 0x40C],
                "shared_targets": 3,
            }],
            result["partial_matches"],
        )
        self.assertEqual(
            {"expected": 16, "selected": 16, "overlapping": 12,
             "precision": 0.75, "recall": 0.75},
            result["bytes"],
        )

    def test_rejects_cross_rom_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, oracle = self.write_inputs(Path(directory), report_hash="different")
            with self.assertRaises(BenchmarkError):
                score_pointer_report(report, oracle)


if __name__ == "__main__":
    unittest.main()
