"""Check ROM source coverage goals using post-generation benchmark reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def evaluate_case(case: dict, report: dict, verification: dict) -> dict:
    comparison = report[case["comparison_key"]] if case.get("comparison_key") else report
    emission = comparison["source_emission"]
    reference_count = comparison["reference_instructions"]
    matching = emission["matching_reference_instructions"]
    generated = emission.get("mnemonic_instructions", emission.get("emitted_mnemonic_instructions"))
    if (not isinstance(reference_count, int) or reference_count <= 0
            or not isinstance(generated, int) or generated <= 0
            or not isinstance(matching, int) or not 0 <= matching <= min(reference_count, generated)):
        raise ValueError("invalid source instruction counts")
    minimum = case["minimum_source_recall_percentage"]
    if not 0 < minimum <= 100:
        raise ValueError("source recall goal must be in (0, 100]")
    expected_hash = case["rom_sha256"]
    report_hash = report.get("reference_rom_sha256") or report.get("instruction_comparison", {}).get("reference_rom_sha256")
    exact = (
        verification.get("status") == "exact"
        and verification["artifact"]["sha256"] == expected_hash
        and verification["expected"]["sha256"] == expected_hash
        and verification["artifact"]["size"] == verification["expected"]["size"]
        and report_hash == expected_hash
    )
    same_reference = reference_count == case["reference_instructions"]
    # Compare counts before rounding; displayed 95.00% may still be below 95%.
    covered = 100 * matching >= minimum * reference_count
    return {
        "name": case["name"],
        "matching_source_instructions": matching,
        "reference_instructions": reference_count,
        "source_recall_percentage": round(100 * matching / reference_count, 2),
        "source_precision_percentage": round(100 * matching / generated, 2),
        "minimum_source_recall_percentage": minimum,
        "exact_rom": exact,
        "same_reference": same_reference,
        "passed": exact and same_reference and covered,
    }


def check_goal(config: Path, workspace: Path) -> dict:
    settings = json.loads(config.read_text(encoding="utf-8"))
    results = []
    for case in settings["cases"]:
        try:
            report = json.loads((workspace / case["report_path"]).read_text(encoding="utf-8"))
            verification = json.loads((workspace / case["verification_path"]).read_text(encoding="utf-8"))
            results.append(evaluate_case(case, report, verification))
        except (OSError, ValueError, KeyError, TypeError) as error:
            results.append({"name": case["name"], "passed": False, "error": str(error)})
    return {"goal_achieved": bool(results) and all(row["passed"] for row in results), "cases": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check_goal(args.config, args.workspace)
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    raise SystemExit(0 if result["goal_achieved"] else 1)


if __name__ == "__main__":
    main()
