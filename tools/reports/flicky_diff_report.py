"""Write machine-readable and concise actionable Flicky source differences."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

from tools.reports.flicky_html_diff import listing_source
from tools.benchmarks.source import listing_instructions


ROM_NAME = "Flicky (UE) [!].bin"
LABEL = re.compile(r"^[A-Za-z_][\w.]*:\s*(.*)$")


def _code(lines: list[str]) -> str:
    result = ""
    for line in lines:
        code = line.split(";", 1)[0].strip()
        label = LABEL.match(code)
        if label:
            code = label.group(1).strip()
        if code:
            result = code
    return result


def _normalized(lines: list[str]) -> tuple[str, ...]:
    return tuple(re.sub(r"\s+", "", line.split(";", 1)[0]).lower()
                 for line in lines)


def write_report(reference: Path, generated: Path, output: Path) -> dict[str, object]:
    rom = (reference / ROM_NAME).read_bytes()
    if rom != (generated / "rebuilt.bin").read_bytes():
        raise ValueError("reference and generated ROMs differ; build and verify first")
    ref_listing = reference / "build" / "main.lst"
    gen_listing = generated / "build" / "retrolarium-main.lst"
    ref_instructions = listing_instructions(ref_listing, rom)
    gen_instructions = listing_instructions(gen_listing, rom)
    ref_source = listing_source(ref_listing)
    gen_source = listing_source(gen_listing)
    fact_path = generated.parent / "analysis" / "m68k" / "instructions.json"
    facts = {
        item["physical_offset"]: item
        for item in json.loads(fact_path.read_text(encoding="utf-8"))["instructions"]
    }

    cases = []
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for address in sorted(ref_instructions):
        original = ref_source.get(address)
        produced = gen_source.get(address)
        ref_lines = original.lines if original else []
        gen_lines = produced.lines if produced else []
        ref_code = _code(ref_lines)
        gen_code = _code(gen_lines)
        ref_op = ref_code.split(None, 1)[0].lower() if ref_code else ""
        gen_op = gen_code.split(None, 1)[0].lower() if gen_code else ""
        fact = facts.get(address)
        if fact is None:
            status = "not_disassembled"
        elif address not in gen_instructions:
            status = "raw_fallback" if gen_op in {"dc.b", "db"} else "not_emitted"
        elif ref_op != gen_op:
            status = ("size_suffix_difference"
                      if ref_op.split(".", 1)[0] == gen_op.split(".", 1)[0]
                      else "mnemonic_difference")
        elif _normalized(ref_lines) != _normalized(gen_lines):
            status = ("label_only_difference"
                      if re.sub(r"\s+", "", ref_code).lower()
                      == re.sub(r"\s+", "", gen_code).lower()
                      else "operand_difference")
        else:
            continue
        mnemonic = fact["mnemonic"] if status == "raw_fallback" else ref_op.upper()
        groups[(status, mnemonic)].append(address)
        cases.append({
            "address": f"{address:06X}",
            "status": status,
            "reference_bytes": ref_instructions[address].hex(" ").upper(),
            "reference_source": ref_code,
            "generated_source": gen_code,
            "reference_operation": ref_op,
            "generated_operation": gen_op,
            "ghidra_mnemonic": fact["mnemonic"] if fact else None,
            "ghidra_operands": fact["operands"] if fact else None,
            "ghidra_bytes": fact["bytes"] if fact else None,
            "html_anchor": f"flicky-source-diff.html#a{address:06X}",
        })

    summary = Counter(case["status"] for case in cases)
    report: dict[str, object] = {
        "schema": "retrolarium.flicky-diff",
        "schema_version": 1,
        "reference_instructions": len(ref_instructions),
        "generated_mnemonic_instructions": len(gen_instructions),
        "summary": dict(sorted(summary.items())),
        "groups": [
            {"status": status, "mnemonic": mnemonic, "count": len(addresses),
             "sample_addresses": [f"{address:06X}" for address in addresses[:8]]}
            for (status, mnemonic), addresses in sorted(
                groups.items(), key=lambda item: (-len(item[1]), item[0])
            )
        ],
        "cases": cases,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "flicky-diff.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n",
    )
    lines = [
        "# Flicky: differences from the reference",
        "",
        f"Reference instructions: {len(ref_instructions)}; "
        f"instructions the kit emitted as mnemonics: {len(gen_instructions)}.",
        "",
        "| Kind | Count |",
        "| --- | ---: |",
    ]
    labels = {
        "not_disassembled": "Not found by the analysis",
        "raw_fallback": "Found, but left as dc.b",
        "not_emitted": "Found, but missing from the listing",
        "mnemonic_difference": "Different mnemonic",
        "size_suffix_difference": "Different size suffix",
        "operand_difference": "Different operands",
        "label_only_difference": "Only the labels differ",
    }
    lines.extend(f"| {labels[key]} | {summary[key]} |" for key in labels)
    lines.extend(("", "## Most often left as dc.b", "",
                  "| Ghidra | Count | Examples |", "| --- | ---: | --- |"))
    raw_groups = [item for item in report["groups"] if item["status"] == "raw_fallback"]
    for item in raw_groups[:30]:
        examples = ", ".join(
            f"[{address}](flicky-source-diff.html#a{address})"
            for address in item["sample_addresses"][:4]
        )
        lines.append(f"| {item['mnemonic']} | {item['count']} | {examples} |")
    lines.extend(("", "## Machine-readable data", "",
                  "`flicky-diff.json` holds every case with its address, bytes, "
                  "the lines of both sources and the Ghidra facts.", ""))
    (output / "flicky-diff.md").write_text(
        "\n".join(lines), encoding="utf-8", newline="\n"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = write_report(args.reference, args.generated, args.output)
    print(json.dumps(report["summary"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
