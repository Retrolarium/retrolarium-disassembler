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


# Mirrors megadrive_emit._selected_tables: tables below the cartridge header
# are never emitted as pointer data.
MEGADRIVE_TABLE_MINIMUM_START = 0x200


def _number(value: dict[str, object], key: str, default: float) -> float:
    raw = value.get(key, default)
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise BenchmarkError(f"pointer table has an invalid {key}") from exc


def _project_asset_ranges(project_path: Path) -> tuple[tuple[int, int], ...]:
    """Collect emitted Z80 program ranges, which block pointer tables."""
    try:
        project = json.loads(project_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"cannot read project manifest {project_path}: {exc}") from exc
    assets = []
    pending = [project]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("kind") == "z80_program":
                assets.append(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    ranges = []
    for asset in assets:
        try:
            start = int(asset["rom_file_offset"])
            ranges.append((start, start + int(asset["size"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise BenchmarkError("project Z80 asset has an invalid range") from exc
    return tuple(ranges)


def select_emitted_tables(
    candidates: list[dict[str, object]],
    asset_ranges: tuple[tuple[int, int], ...] = (),
) -> list[dict[str, object]]:
    """Return the accepted tables the source emitter would actually place.

    Mega Drive reports replay the emitter's greedy non-overlapping selection;
    other platforms emit every accepted table.
    """
    accepted = [value for value in candidates if value.get("status") == "accepted"]
    if not any(str(value.get("schema_id", "")).startswith("megadrive.") for value in candidates):
        return accepted
    ordered = sorted(
        accepted,
        key=lambda value: (
            -_number(value, "score", 0),
            _table_key(value)[1],
            -_number(value, "entry_size", 0),
        ),
    )
    selected = []
    occupied: list[tuple[int, int]] = []
    for value in ordered:
        _, start, end = _table_key(value)
        if start < MEGADRIVE_TABLE_MINIMUM_START:
            continue
        if any(start < right and left < end for left, right in (*asset_ranges, *occupied)):
            continue
        selected.append(value)
        occupied.append((start, end))
    return selected


def _overlap(left: tuple[str, int, int], right: tuple[str, int, int]) -> int:
    if left[0] != right[0]:
        return 0
    return max(0, min(left[2], right[2]) - max(left[1], right[1]))


def _covered_bytes(keys: list[tuple[str, int, int]]) -> dict[str, list[tuple[int, int]]]:
    merged: dict[str, list[tuple[int, int]]] = {}
    for schema, start, end in sorted(keys):
        spans = merged.setdefault(schema, [])
        if spans and start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        elif end > start:
            spans.append((start, end))
    return merged


def _span_total(spans: dict[str, list[tuple[int, int]]]) -> int:
    return sum(end - start for items in spans.values() for start, end in items)


def _span_intersection(left: dict[str, list[tuple[int, int]]], right: dict[str, list[tuple[int, int]]]) -> int:
    total = 0
    for schema, spans in left.items():
        for start, end in spans:
            for other_start, other_end in right.get(schema, ()):
                total += max(0, min(end, other_end) - max(start, other_start))
    return total


def score_pointer_report(report_path: Path, oracle_path: Path, project_path: Path | None = None) -> dict[str, object]:
    report = _load_object(report_path, "pointer report")
    oracle = _load_object(oracle_path, "pointer oracle")
    report_hash = report.get("input_sha256")
    oracle_hash = oracle.get("input_sha256")
    if not isinstance(report_hash, str) or not isinstance(oracle_hash, str) or report_hash != oracle_hash:
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
    accepted_count = sum(
        value.get("status") == "accepted" and value.get("schema_id") in schema_set for value in candidate_values
    )
    asset_ranges = _project_asset_ranges(project_path) if project_path else ()
    selected_values = [
        value for value in select_emitted_tables(candidate_values, asset_ranges) if value.get("schema_id") in schema_set
    ]
    accepted = {_table_key(value): value for value in selected_values}
    if len(accepted) != len(selected_values):
        raise BenchmarkError("pointer report contains duplicate accepted table ranges")

    matched_keys = sorted(expected.keys() & accepted.keys())
    false_keys = sorted(accepted.keys() - expected.keys())
    missed_keys = sorted(expected.keys() - accepted.keys())

    # Pair inexact ranges one-to-one by largest same-schema byte overlap so a
    # table that is off by one entry is reported as partial, not as unrelated.
    pairs = sorted(
        (
            (-_overlap(found, wanted), found, wanted)
            for found in false_keys
            for wanted in missed_keys
            if _overlap(found, wanted)
        )
    )
    paired_found: set[tuple[str, int, int]] = set()
    paired_wanted: set[tuple[str, int, int]] = set()
    partial_matches = []
    for negative_overlap, found, wanted in pairs:
        if found in paired_found or wanted in paired_wanted:
            continue
        paired_found.add(found)
        paired_wanted.add(wanted)
        found_targets = _targets(accepted[found])
        wanted_targets = set(_targets(expected[wanted]))
        partial_matches.append(
            {
                "oracle_id": expected[wanted].get("id"),
                "candidate_id": accepted[found].get("id"),
                "overlap_bytes": -negative_overlap,
                "oracle_range": [wanted[1], wanted[2]],
                "candidate_range": [found[1], found[2]],
                "shared_targets": sum(target in wanted_targets for target in found_targets),
            }
        )
    expected_bytes = _covered_bytes(list(expected))
    selected_bytes = _covered_bytes(list(accepted))
    overlapping_bytes = _span_intersection(expected_bytes, selected_bytes)
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
            "accepted": accepted_count,
            "selected": len(accepted),
            "true_positive": true_positive,
            "partial": len(partial_matches),
            "false_positive": len(false_keys),
            "missed": len(missed_keys),
            "precision": _ratio(true_positive, len(accepted)),
            "recall": _ratio(true_positive, len(expected)),
        },
        "bytes": {
            "expected": _span_total(expected_bytes),
            "selected": _span_total(selected_bytes),
            "overlapping": overlapping_bytes,
            "precision": _ratio(overlapping_bytes, _span_total(selected_bytes)),
            "recall": _ratio(overlapping_bytes, _span_total(expected_bytes)),
        },
        "targets": {
            "matched_tables": true_positive,
            "exact_tables": exact_target_tables,
            "accuracy": _ratio(exact_target_tables, true_positive),
        },
        "matches": matches,
        "partial_matches": partial_matches,
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
