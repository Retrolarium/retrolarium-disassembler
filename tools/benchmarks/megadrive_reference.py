"""Compare a generated Mega Drive project with an AS reference profile."""

from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path

from flatten_asm_source import flatten_source
from source_benchmark import instruction_quality, read_listing, same_instruction, source_metrics


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _modules(path: Path) -> list[dict[str, object]]:
    layout = json.loads(path.read_text(encoding="utf-8"))
    modules = []
    for item in layout["modules"]:
        modules.append({
            "file": item["file"], "subsystem": item["subsystem"],
            "start": int(item["start"], 16), "end": int(item["end"], 16),
            "reference_instructions": 0, "matching_instructions": 0,
            "missed_instructions": 0, "extra_instructions": 0,
        })
    modules.sort(key=lambda item: item["start"])
    if any(left["end"] >= right["start"] for left, right in zip(modules, modules[1:])):
        raise ValueError("reference ROM layout has overlapping modules")
    return modules


def _group_missed(missed: set[int], known: dict[int, bytes], modules: list[dict[str, object]]) -> list[dict[str, object]]:
    starts = [item["start"] for item in modules]
    groups: list[dict[str, object]] = []
    for address in sorted(missed):
        index = bisect_right(starts, address) - 1
        owner = modules[index] if index >= 0 and address <= modules[index]["end"] else None
        module = owner["file"] if owner else "unknown"
        if groups and groups[-1]["file"] == module and address <= groups[-1]["last_address"] + 12:
            group = groups[-1]
            group["last_address"] = address
            group["end"] = address + len(known[address])
            group["instruction_count"] += 1
        else:
            groups.append({
                "start": address, "end": address + len(known[address]),
                "last_address": address, "instruction_count": 1, "file": module,
            })
    for group in groups:
        del group["last_address"]
    return sorted(groups, key=lambda item: (-item["instruction_count"], item["start"]))


def benchmark(reference: Path, generated: Path, rom: Path, listing: Path, layout: Path, output: Path) -> dict[str, object]:
    reference = reference.resolve()
    generated = generated.resolve()
    output = output.resolve()
    rom_bytes = rom.read_bytes()
    manifest = json.loads((generated.parent / "retrolarium-project.json").read_text(encoding="utf-8"))
    if manifest["input"]["sha256"] != _sha256(rom_bytes):
        raise ValueError("reference ROM differs from generated project input")
    known, known_open = read_listing(listing, rom_bytes)
    facts = json.loads((generated.parent / "analysis/m68k/instructions.json").read_text(encoding="utf-8"))["instructions"]
    analyzed = {item["physical_offset"]: bytes.fromhex(item["bytes"]) for item in facts}

    def matches(address: int, actual: bytes, actual_open: bool = False) -> bool:
        return same_instruction(
            known[address], actual,
            expected_open=address in known_open, actual_open=actual_open,
        )

    matching = {address for address in known.keys() & analyzed.keys() if matches(address, analyzed[address])}
    missed = known.keys() - analyzed.keys()
    extra = analyzed.keys() - known.keys()
    disagreements = (known.keys() & analyzed.keys()) - matching
    modules = _modules(layout)
    module_starts = [item["start"] for item in modules]
    for category, addresses in (
        ("reference_instructions", known), ("matching_instructions", matching),
        ("missed_instructions", missed), ("extra_instructions", extra),
    ):
        for address in addresses:
            index = bisect_right(module_starts, address) - 1
            if index >= 0 and address <= modules[index]["end"]:
                modules[index][category] += 1
    for module in modules:
        module["recall_percentage"] = round(
            100 * module["matching_instructions"] / module["reference_instructions"], 2
        ) if module["reference_instructions"] else None
    reference_text, reference_origins = flatten_source(reference, "src/main.s")
    generated_text, generated_origins = flatten_source(generated, "src/main.s")
    groups = _group_missed(missed, known, modules)
    report: dict[str, object] = {
        "schema": "retrolarium.megadrive.reference-benchmark",
        "schema_version": 1,
        "reference_rom_sha256": _sha256(rom_bytes),
        "reference_listing": str(listing.resolve()),
        "reference_instructions": len(known),
        "generated_instructions": len(analyzed),
        "matching_instructions": len(matching),
        "missed_instructions": len(missed),
        "extra_instructions": len(extra),
        "different_encodings_at_same_address": len(disagreements),
        **instruction_quality(len(matching), len(known), len(analyzed)),
        "reference_source_files": len(reference_origins),
        "generated_source_files": len(generated_origins),
        "reference_source_metrics": source_metrics(reference_text),
        "generated_source_metrics": source_metrics(generated_text),
        "missed_group_count": len(groups),
        "modules": modules,
    }
    source_listing = generated / "build/retrolarium-main.lst"
    if source_listing.is_file():
        rebuilt = (generated / "rebuilt.bin").read_bytes()
        emitted, emitted_open = read_listing(source_listing, rebuilt)
        emitted_matches = sum(
            address in known and matches(address, raw, address in emitted_open)
            for address, raw in emitted.items()
        )
        report["source_emission"] = {
            "mnemonic_instructions": len(emitted),
            "matching_reference_instructions": emitted_matches,
            **instruction_quality(emitted_matches, len(known), len(emitted)),
        }
    output.mkdir(parents=True, exist_ok=True)
    (output / "reference-main.s").write_text(reference_text, encoding="utf-8", newline="\n")
    (output / "generated-main.s").write_text(generated_text, encoding="utf-8", newline="\n")
    (output / "reference-source-map.json").write_text(json.dumps(reference_origins, indent=2) + "\n", encoding="utf-8")
    (output / "generated-source-map.json").write_text(json.dumps(generated_origins, indent=2) + "\n", encoding="utf-8")
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "missed-groups.json").write_text(json.dumps(groups, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Mega Drive reference comparison", "",
        f"Reference instructions: {len(known)}; matching: {len(matching)}; "
        f"missed: {len(missed)}; extra: {len(extra)}.",
        f"Recall: {report['instruction_recall_percentage']}%; "
        f"precision: {report['instruction_precision_percentage']}%.",
        "", "## Largest missed instruction groups", "",
        "| ROM span | Instructions | Reference module |",
        "| --- | ---: | --- |",
    ]
    for group in groups[:50]:
        lines.append(
            f"| {group['start']:06X}–{group['end'] - 1:06X} | "
            f"{group['instruction_count']} | {group['file']} |"
        )
    lines += ["", "## Modules with most missed instructions", "",
              "| Module | Reference | Matching | Missed | Recall |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for item in sorted(modules, key=lambda row: -row["missed_instructions"])[:50]:
        lines.append(
            f"| {item['file']} | {item['reference_instructions']} | "
            f"{item['matching_instructions']} | {item['missed_instructions']} | "
            f"{item['recall_percentage']}% |"
        )
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--rom", type=Path, required=True)
    parser.add_argument("--listing", type=Path, required=True)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = benchmark(args.reference, args.generated, args.rom, args.listing, args.layout, args.output)
    print(json.dumps({
        key: report[key] for key in (
            "reference_instructions", "generated_instructions", "matching_instructions",
            "missed_instructions", "extra_instructions", "instruction_recall_percentage",
            "instruction_precision_percentage", "missed_group_count",
        )
    }, indent=2))


if __name__ == "__main__":
    main()
