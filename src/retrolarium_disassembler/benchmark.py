"""Post-analysis scoring against isolated, ROM-bound oracle metadata."""

from __future__ import annotations

import json
from pathlib import Path


class BenchmarkError(ValueError):
    """A benchmark input is invalid or belongs to another ROM."""


def _load_object(path: Path, kind: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"cannot read {kind} {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise BenchmarkError(f"unsupported {kind} schema: {path}")
    return value


def _table_key(value: dict[str, object]) -> tuple[str, int, int]:
    try:
        return (
            str(value["schema_id"]),
            int(value["physical_start"]),
            int(value["physical_end"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BenchmarkError("pointer table has an invalid range or schema") from exc


def _targets(value: dict[str, object]) -> tuple[int, ...]:
    entries = value.get("entries")
    if not isinstance(entries, list):
        raise BenchmarkError("pointer table has no entries array")
    try:
        return tuple(int(entry["target"]) for entry in entries)
    except (KeyError, TypeError, ValueError) as exc:
        raise BenchmarkError("pointer table entry has no numeric target") from exc


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


def score_pointer_report(report_path: Path, oracle_path: Path) -> dict[str, object]:
    report = _load_object(report_path, "pointer report")
    oracle = _load_object(oracle_path, "pointer oracle")
    report_hash = report.get("input_sha256")
    oracle_hash = oracle.get("input_sha256")
    if (
        not isinstance(report_hash, str)
        or not isinstance(oracle_hash, str)
        or report_hash != oracle_hash
    ):
        raise BenchmarkError("pointer report and oracle refer to different ROM hashes")
    if oracle.get("coverage") != "complete_for_evaluated_schemas":
        raise BenchmarkError("pointer oracle does not declare complete evaluated coverage")

    schemas = oracle.get("evaluated_schemas")
    if not isinstance(schemas, list) or not all(isinstance(item, str) for item in schemas):
        raise BenchmarkError("pointer oracle has no evaluated_schemas array")
    schema_set = set(schemas)
    expected_values = oracle.get("pointer_tables")
    candidate_values = report.get("candidates")
    if not isinstance(expected_values, list) or not isinstance(candidate_values, list):
        raise BenchmarkError("pointer benchmark inputs have no table arrays")
    if not all(isinstance(value, dict) for value in expected_values + candidate_values):
        raise BenchmarkError("pointer table arrays must contain objects")

    expected = {_table_key(value): value for value in expected_values}
    if len(expected) != len(expected_values):
        raise BenchmarkError("pointer oracle contains duplicate table ranges")
    accepted_values = [
        value
        for value in candidate_values
        if value.get("status") == "accepted" and value.get("schema_id") in schema_set
    ]
    accepted = {_table_key(value): value for value in accepted_values}
    if len(accepted) != len(accepted_values):
        raise BenchmarkError("pointer report contains duplicate accepted table ranges")

    matched_keys = sorted(expected.keys() & accepted.keys())
    false_keys = sorted(accepted.keys() - expected.keys())
    missed_keys = sorted(expected.keys() - accepted.keys())
    matches = []
    exact_target_tables = 0
    for key in matched_keys:
        target_match = _targets(expected[key]) == _targets(accepted[key])
        exact_target_tables += int(target_match)
        matches.append(
            {
                "oracle_id": expected[key].get("id"),
                "candidate_id": accepted[key].get("id"),
                "targets_exact": target_match,
            }
        )

    true_positive = len(matched_keys)
    return {
        "schema_version": 1,
        "task": "benchmark.pointer_tables",
        "fixture_id": oracle.get("fixture_id"),
        "input_sha256": report_hash,
        "evaluated_schemas": schemas,
        "tables": {
            "expected": len(expected),
            "accepted": len(accepted),
            "true_positive": true_positive,
            "false_positive": len(false_keys),
            "missed": len(missed_keys),
            "precision": _ratio(true_positive, len(accepted)),
            "recall": _ratio(true_positive, len(expected)),
        },
        "targets": {
            "matched_tables": true_positive,
            "exact_tables": exact_target_tables,
            "accuracy": _ratio(exact_target_tables, true_positive),
        },
        "matches": matches,
        "false_positive_candidates": [accepted[key].get("id") for key in false_keys],
        "missed_oracle_tables": [expected[key].get("id") for key in missed_keys],
    }


def write_benchmark(path: Path, result: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
