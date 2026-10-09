"""Explain every reference instruction absent from a byte-exact generated build.

This is an evaluation tool. Its reference-derived addresses must never be fed
back to the blind decoder as entry points.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_kit.facts import load_megadrive_ghidra_facts
from retrolarium_core.megadrive import load_megadrive
from retrolarium_kit.m68k_abstract import discover_packed_orphan_candidates
from megadrive_reference_benchmark import _group_missed, _modules
from source_benchmark import instruction_quality, read_listing, same_instruction


REASONS = {
    "not_decoded": "No instruction in the decoder's output",
    "unrooted_backend_decode": "The decoder found the instruction, but no proven entry reaches it",
    "formatter_fallback": "A proven instruction was emitted as bytes",
    "emission_conflict": "A proven instruction is covered by data or another record",
    "different_encoding": "A different instruction was emitted at the same address",
}


def audit(rom: Path, generated: Path, listing: Path, layout: Path, output: Path) -> dict:
    image = load_megadrive(rom)
    project = generated.parent
    manifest = json.loads((project / "retrolarium-project.json").read_text(encoding="utf-8"))
    if manifest["input"]["sha256"] != image.sha256:
        raise ValueError("generated project belongs to another ROM")
    rebuilt = (generated / "rebuilt.bin").read_bytes()
    if hashlib.sha256(rebuilt).hexdigest() != image.sha256:
        raise ValueError("opcode audit requires a byte-exact assembled project")
    known, known_open = read_listing(listing, image.data)
    emitted, emitted_open = read_listing(generated / "build/retrolarium-main.lst", rebuilt)
    matches = {
        address for address in known.keys() & emitted.keys()
        if same_instruction(known[address], emitted[address],
                            expected_open=address in known_open,
                            actual_open=address in emitted_open)
    }
    analysis = project / "analysis" / "m68k"
    raw_facts = load_megadrive_ghidra_facts(analysis / "instructions.tsv", image)
    records = json.loads((analysis / "instructions.json").read_text(encoding="utf-8"))["instructions"]
    trusted = {item["physical_offset"]: item for item in records}
    trusted_addresses = sorted(trusted)
    orphan_entries = {candidate.address for candidate in discover_packed_orphan_candidates(
        image, {address: raw_facts[address] for address in trusted if address in raw_facts})}
    abstract = json.loads((analysis / "abstract-analysis.json").read_text(encoding="utf-8"))
    seeds = set(abstract["decoder_seed_addresses"])
    incoming = defaultdict(list)
    for fact in raw_facts.values():
        for reference in fact.references:
            incoming[reference.address & 0xFFFFFF].append({
                "source_address": fact.cpu_address,
                "type": reference.reference_type,
                "source_is_trusted": fact.cpu_address in trusted,
            })
    pointers = json.loads((project / "analysis/pointers.json").read_text(encoding="utf-8"))
    pointer_ranges = [item for item in pointers["candidates"] if item["status"] == "accepted"]
    assets = manifest["assets"]["items"]
    missed = known.keys() - matches
    details = []
    for address in sorted(missed):
        fact = raw_facts.get(address)
        if address in emitted:
            reason = "different_encoding"
        elif address in trusted:
            reason = "formatter_fallback"
        elif fact is not None and same_instruction(
                known[address], fact.raw, expected_open=address in known_open):
            reason = "unrooted_backend_decode"
        else:
            reason = "not_decoded"
        covering = [
            {"kind": "pointer", "schema": item["schema_id"],
             "start": item["physical_start"], "end": item["physical_end"]}
            for item in pointer_ranges
            if item["physical_start"] <= address < item["physical_end"]
        ]
        covering.extend(
            {"kind": "asset", "path": item["path"],
             "start": item["rom_file_offset"], "end": item["rom_file_offset"] + item["size"]}
            for item in assets
            if item["rom_file_offset"] <= address < item["rom_file_offset"] + item["size"]
        )
        if reason == "formatter_fallback" and covering:
            reason = "emission_conflict"
        index = bisect_left(trusted_addresses, address)
        previous = trusted[trusted_addresses[index - 1]] if index else None
        following = trusted_addresses[index] if index < len(trusted_addresses) else None
        gap_start = previous["physical_offset"] + previous["length"] if previous else None
        row = {
            "address": address, "address_hex": f"${address:06X}",
            "expected_bytes": known[address].hex(" ").upper(), "reason": reason,
            "backend": ({"mnemonic": fact.mnemonic, "operands": fact.operands,
                         "bytes": fact.raw.hex(" ").upper(), "flow_type": fact.flow_type}
                        if fact is not None else None),
            "is_decoder_seed": address in seeds,
            "incoming_references": incoming[address],
            "covering_data": covering,
            "context": {
                "gap_start": gap_start, "gap_end": following,
                "gap_bytes": following - gap_start if gap_start is not None and following is not None else None,
                "preceding_instruction": previous["physical_offset"] if previous else None,
                "preceding_mnemonic": previous["mnemonic"] if previous else None,
                "preceding_flow_type": previous["flow_type"] if previous else None,
                "gap_first_bytes": image.data[gap_start:gap_start + 12].hex(" ").upper() if gap_start is not None else None,
            },
        }
        details.append(row)
    by_address = {row["address"]: row for row in details}
    groups = _group_missed(missed, known, _modules(layout))
    for group in groups:
        rows = [by_address[a] for a in sorted(by_address) if group["start"] <= a < group["end"]]
        group["reasons"] = dict(Counter(row["reason"] for row in rows))
        group["context"] = rows[0]["context"]
        ctx = group["context"]
        gap_start = ctx["gap_start"]
        barriers = []
        if not any(row["is_decoder_seed"] for row in rows):
            barriers.append("no decoder seed at any missed instruction in this group")
        if gap_start is not None and group["start"] != gap_start:
            barriers.append("group starts inside a mixed gap; code/data boundary is not established")
        if gap_start is not None and any(
                ref["source_is_trusted"] and ref["type"] in {"DATA", "READ"}
                for ref in incoming[gap_start]):
            barriers.append("trusted code references the start of the gap as data")
        if gap_start is not None and gap_start not in orphan_entries:
            barriers.append("gap entry does not satisfy the current packed-orphan recovery rule")
        if ctx["gap_bytes"] is not None and ctx["gap_bytes"] > 128:
            barriers.append("gap exceeds 128 bytes; a return-looking word alone is insufficient evidence")
        group["recovery_barriers"] = barriers
        group["instructions"] = rows
    extra_addresses = emitted.keys() - known.keys()
    extra_groups = _group_missed(extra_addresses, emitted, _modules(layout))
    for group in extra_groups:
        group["instructions"] = [
            {"address": address, "bytes": emitted[address].hex(" ").upper(),
             "backend_mnemonic": raw_facts[address].mnemonic if address in raw_facts else None}
            for address in sorted(extra_addresses) if group["start"] <= address < group["end"]
        ]
    counts = dict(Counter(row["reason"] for row in details))
    report = {
        "schema": "retrolarium.megadrive.opcode-audit", "schema_version": 1,
        "rom_sha256": image.sha256, "reference_instructions": len(known),
        "matching_instructions": len(matches), "missing_instructions": len(missed),
        "extra_instructions": len(extra_addresses), "extra_groups": extra_groups,
        **instruction_quality(len(matches), len(known), len(emitted)),
        "reason_counts": counts, "group_count": len(groups), "groups": groups,
        "return_words_without_known_references": [row["address"] for row in details
                                   if known[row["address"]] == b"\x4e\x75"
                                   and not row["incoming_references"] and not row["is_decoder_seed"]],
        "isolated_return_words_after_return": [row["address"] for row in details
                                   if known[row["address"]] == b"\x4e\x75"
                                   and image.data[row["address"] - 2:row["address"]] == b"\x4e\x75"
                                   and not row["incoming_references"] and not row["is_decoder_seed"]],
        "limitations": [
            "Absence of a proven reference does not prove a function unreachable; unresolved indirect jumps may reach it.",
            "A legal opcode or return-looking word alone does not prove bytes are code. The same bytes can be stored as data.",
            "100 percent recall alone can be obtained by interpreting data as code; precision and exact rebuilding are separate checks.",
            "Reference data directives such as sample descriptors are not instructions and do not enter this denominator.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "opcode-audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# 68000 instruction differences", "",
             f"Matched {len(matches)} / {len(known)} ({report['instruction_recall_percentage']}%). "
             f"Missed {len(missed)}; extra {report['extra_instructions']}. "
             f"Precision: {report['instruction_precision_percentage']}%.", "",
             "Instruction boundaries and bytes are compared in the source as actually assembled. "
             "Label names, data table layout and comments do not count.", "",
             "## Reasons", "", "| Reason | Instructions |", "| --- | ---: |"]
    lines.extend(f"| {REASONS[key]} | {value} |" for key, value in counts.items())
    lines += ["", "## Why 100% cannot be guaranteed without annotations", "",
              "A ROM does not mark code or data. An unreachable routine and an array "
              "holding the same bytes give the same ROM. Ranges without a proven entry "
              "can be handled by a heuristic, but it may decode data as instructions. "
              "Recognising legal instructions alone is not enough.", "",
              "This does not mean the remaining instructions cannot be decoded, "
              "or that the percentage shown is the limit. Unrecognised tables "
              "and entries need new general rules. Matching every choice of the reference's "
              "author cannot be guaranteed from the bytes alone; it needs external entry points "
              "or annotations. Extra instructions are counted separately, so that data "
              "does not raise the recall.", "", "## All groups", ""]
    for group in groups:
        lines += [f"### ${group['start']:06X}–${group['end'] - 1:06X}: {group['instruction_count']} instructions", "",
                  f"Reference: `{group['file']}`. " + "; ".join(f"{REASONS[k]}: {v}" for k, v in group["reasons"].items()), ""]
        ctx = group["context"]
        lines += ["Limits of the current search: " + "; ".join(group["recovery_barriers"]) + ".", ""]
        if ctx["gap_start"] is not None and ctx["gap_end"] is not None:
            lines += [f"Gap in the proven CFG: ${ctx['gap_start']:06X}–${ctx['gap_end']:06X}, "
                      f"{ctx['gap_bytes']} bytes; preceded by {ctx['preceding_mnemonic']} "
                      f"({ctx['preceding_flow_type']}). First bytes: `{ctx['gap_first_bytes']}`.", ""]
        lines += ["| Address | Reference bytes | Decoder | Reason |", "| --- | --- | --- | --- |"]
        for row in group["instructions"]:
            backend = row["backend"]
            decoded = f"{backend['mnemonic']} {backend['operands']}" if backend else "—"
            lines.append(f"| {row['address_hex']} | `{row['expected_bytes']}` | `{decoded.replace('|', ',')}` | {REASONS[row['reason']]} |")
        lines.append("")
    lines += ["## Instructions the reference does not have", "",
              "Every group of extra mnemonics is listed below. They lower the "
              "precision against the reference's chosen layout. An exact ROM "
              "rebuild does not prove them right.", "",
              "| Addresses | Count | Reference module |", "| --- | ---: | --- |"]
    for group in extra_groups:
        lines.append(f"| ${group['start']:06X}–${group['end'] - 1:06X} | {group['instruction_count']} | `{group['file']}` |")
    (output / "opcode-audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("rom", "generated", "listing", "layout", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.rom, args.generated, args.listing, args.layout, args.output)
    print(json.dumps({key: report[key] for key in
                      ("reference_instructions", "matching_instructions", "missing_instructions",
                       "instruction_recall_percentage", "instruction_precision_percentage",
                       "reason_counts", "group_count")}, indent=2))


if __name__ == "__main__":
    main()
