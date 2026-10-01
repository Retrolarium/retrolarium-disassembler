"""Evaluate ROM-only Mega Drive disassembly against the extra reference corpus.

The analyzer receives only the original ROM. Reference listings, symbols and
addresses are read after the project exists, for scoring only. Only units
whose reference build is byte-identical to a supplied original are scored;
every other unit is listed with the reason it is not comparable.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import sys

from flicky_html_diff import write_html
from sonic_corpus_benchmark import annotate_groups, below_source_recall_target, compare, digest
from source_benchmark import read_listing


KIT = Path(__file__).resolve().parents[1]


def comparable(unit: dict) -> str | None:
    """Return why a prepared unit cannot be scored, or None."""
    if unit.get("status") != "verified-original" or not unit.get("matching_original_roms"):
        return f"reference status is {unit.get('status')!r}, not a verified original"
    if not unit.get("matches_upstream"):
        return "flattened source was not proven identical to the upstream build"
    if not unit.get("reference_instructions") or unit.get("uncertain_instruction_addresses"):
        return "reference listing has no instructions or unresolved lengths"
    if unit.get("listing_provenance", {}).get("instructions_outside_rom"):
        return "reference listing has instructions outside the ROM mapping"
    return None


def original_rom(unit: dict) -> Path:
    for path in map(Path, unit["matching_original_roms"]):
        if path.is_file() and digest(path) == unit["binary_sha256"]:
            return path
    raise ValueError("no recorded original ROM is present with the recorded SHA-256")


def disassemble(rom: Path, project: Path, ghidra_home: Path | None) -> None:
    command = [sys.executable, str(KIT / "rltool.py"), "megadrive", "disassemble", str(rom), "--output", str(project)]
    if ghidra_home:
        command += ["--ghidra-home", str(ghidra_home)]
    project.parent.mkdir(parents=True, exist_ok=True)
    with (project.parent / f"{project.name}.disassemble.log").open("wb") as log:
        if subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode:
            raise RuntimeError(f"ROM-only disassembly failed: {log.name}")


def evaluate(unit: dict, project: Path, dest: Path, toolchain_cache: Path, result: dict) -> dict:
    """Fill ``result`` in place so partial metrics survive a later failure."""
    result.update(rom_sha256=unit["binary_sha256"], reference_source_sha256=unit["source_sha256"],
                  reference_listing_sha256=unit["listing_sha256"])
    if digest(Path(unit["source"])) != unit["source_sha256"]:
        raise ValueError("reference source hash changed")
    if digest(Path(unit["binary"])) != unit["binary_sha256"]:
        raise ValueError("reference ROM hash changed")
    rom_path = original_rom(unit)
    rom = rom_path.read_bytes()
    normalized = Path(unit["listing"])
    if digest(normalized) != unit["listing_sha256"]:
        raise ValueError("normalized reference listing hash changed")
    known, known_open = read_listing(normalized, rom)
    if len(known) != unit["reference_instructions"] or known_open:
        raise ValueError("normalized reference listing no longer yields the recorded instructions")
    manifest = project / "retrolarium-project.json"
    if not manifest.is_file():
        raise ValueError(f"ROM disassembly did not produce a project: {project}")
    from retrolarium_kit.project import build_project, verify_project
    build_project(manifest, toolchain_cache=toolchain_cache)
    verification = verify_project(manifest)
    result["rebuild_status"] = verification["status"]
    facts = json.loads((project / "analysis/m68k/instructions.json").read_text(encoding="utf-8"))
    if facts["input_sha256"] != unit["binary_sha256"]:
        raise ValueError("analysis input hash does not match the reference original")
    actual = {item["physical_offset"]: bytes.fromhex(item["bytes"]) for item in facts["instructions"]}
    result["analysis"] = compare(known, known_open, actual)
    generated_listing = project / "generated/build/retrolarium-main.lst"
    emitted, emitted_open = read_listing(generated_listing, rom)
    result["source_emission"] = compare(known, known_open, emitted)
    result["emitted_listing_open_ended_lengths"] = len(emitted_open)
    for key in ("missing_groups", "extra_groups"):
        annotate_groups(result["source_emission"][key], normalized)
    result["analysis_facts_sha256"] = digest(project / "analysis/m68k/instructions.json")
    result["generated_listing_sha256"] = digest(generated_listing)
    passes = json.loads((project / "analysis/m68k/decoder-passes.json").read_text(encoding="utf-8"))
    result["decoder_passes"] = len(passes["passes"])
    result["decoder_converged"] = passes["converged"]
    if verification["status"] != "exact":
        # Metrics above stay visible; an inexact rebuild still fails the case.
        raise ValueError("generated project does not reproduce the original ROM")
    # Preserve measured metrics before generating a potentially large HTML.
    # An interrupted report must not hide a completed, exact ROM comparison.
    result["html_status"] = "pending"
    (dest / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    counts = write_html(Path(unit["source"]).parent, project / "generated", dest / "opcode-differences.html",
                        differences_only=True, opcodes_only=True, rom=rom_path,
                        reference_listing=normalized, title=unit["name"])
    result["html_status_counts"] = dict(counts)
    result["html_status"] = "complete"
    for key in ("missing", "extra"):
        lines = ["start\tend_exclusive\tinstructions\treference_context"]
        lines.extend(f"${group['start']:06X}\t${group['end']:06X}\t{group['instructions']}\t"
                     f"{group.get('reference_context', '')}"
                     for group in result["source_emission"][key + "_groups"])
        (dest / f"{key}-groups.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def benchmark(corpus: Path, projects: Path, output: Path, *, only: frozenset[str] = frozenset(),
              run_disassembly: bool = False, ghidra_home: Path | None = None) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    unknown = only - {unit["name"] for unit in manifest["units"]}
    if unknown:
        raise ValueError(f"unknown corpus profiles: {', '.join(sorted(unknown))}")
    sys.path.insert(0, str(KIT / "src"))
    output.mkdir(parents=True, exist_ok=True)
    cases, skipped = [], []
    for unit in manifest["units"]:
        name = unit["name"]
        if only and name not in only:
            continue
        reason = comparable(unit)
        if reason:
            skipped.append({"name": name, "status": unit.get("status"), "reason": reason})
            continue
        print(f"Comparing {name}...", flush=True)
        dest = output / name
        dest.mkdir(parents=True, exist_ok=True)
        project = projects / name
        result = {"name": name}
        try:
            if run_disassembly and not (project / "retrolarium-project.json").is_file():
                disassemble(original_rom(unit), project, ghidra_home)
            evaluate(unit, project, dest, output / "toolchain-cache", result)
        except (ValueError, RuntimeError, OSError, KeyError) as error:
            result["error"] = str(error)
        cases.append(result)
        (dest / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=KIT, capture_output=True, text=True)
    report = {"schema": "retrolarium.extra-reference-benchmark", "schema_version": 1,
              "measured_at": datetime.now(timezone.utc).isoformat(),
              "checkout_commit": revision.stdout.strip() if revision.returncode == 0 else None,
              "scope": "M68K instructions: same physical offset, length and bytes. Z80 is not scored.",
              "cases": cases, "not_comparable": skipped}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rows = ["# Extra references: automatic ROM disassembly", "",
            "A match is a 68000 instruction with the same physical address, length and bytes.", "",
            "| ROM | Reference | Analysis | ASM | Precision ASM | ROM rebuild | Differences |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- |"]
    for case in cases:
        if "source_emission" in case and "error" not in case:
            source, analysis = case["source_emission"], case["analysis"]
            rows.append(f"| {case['name']} | {analysis['reference_instructions']} | "
                        f"{analysis['instruction_recall_percentage']}% | {source['instruction_recall_percentage']}% | "
                        f"{source['instruction_precision_percentage']}% | {case['rebuild_status']} | "
                        f"[HTML]({case['name']}/opcode-differences.html) |")
        else:
            rows.append(f"| {case['name']} | — | — | — | — | {case.get('rebuild_status', '—')} | {case.get('error')} |")
    if skipped:
        rows += ["", "Not compared:", "", *[f"- {item['name']}: {item['reason']}" for item in skipped]]
    (output / "summary.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("build/extra-references"))
    parser.add_argument("--projects", type=Path, default=Path("build/extra-disassembly"))
    parser.add_argument("--output", type=Path, default=Path("build/extra-comparison"))
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--run-disassembly", action="store_true",
                        help="run 'rltool.py megadrive disassemble' for units without a project")
    parser.add_argument("--ghidra-home", type=Path)
    parser.add_argument("--minimum-source-recall", type=Decimal, metavar="PERCENT",
                        help="optional gate; no floor is applied unless given")
    args = parser.parse_args()
    if args.minimum_source_recall is not None and not 0 <= args.minimum_source_recall <= 100:
        parser.error("--minimum-source-recall must be between 0 and 100")
    args.output.mkdir(parents=True, exist_ok=True)
    report = benchmark(args.corpus.resolve(), args.projects.resolve(), args.output.resolve(),
                       only=frozenset(args.only), run_disassembly=args.run_disassembly,
                       ghidra_home=args.ghidra_home and args.ghidra_home.resolve())
    print(json.dumps([{key: case.get(key) for key in ("name", "rebuild_status", "error")}
                      for case in report["cases"]], indent=2))
    if any("error" in case for case in report["cases"]):
        raise SystemExit(1)
    if args.minimum_source_recall is not None:
        below = [case["name"] for case in report["cases"]
                 if below_source_recall_target(case, args.minimum_source_recall)]
        if below:
            print(f"Below {args.minimum_source_recall}% source recall: {', '.join(below)}", file=sys.stderr)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
