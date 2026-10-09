"""Group actionable Flicky source differences into contiguous ROM regions."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
import re

from tools.reports.flicky_html_diff import (
    DIRECTIVES,
    LABEL,
    ROM_NAME,
    SourceAtAddress,
    _encoded_bytes,
    _operation,
    listing_source,
)
from tools.benchmarks.source import listing_instructions


CATEGORY_LABELS = {
    "false-code": "data decoded as code",
    "false-pointer": "byte data decoded as pointers",
    "long-data": "a 32-bit structure left as raw bytes",
    "missing-include": "the reference binclude is lost",
    "opaque-include": "structured data hidden in a binclude",
    "padding": "ROM padding written differently",
    "text": "text left as numeric bytes",
    "word-data": "a 16-bit structure left as raw bytes",
    "other": "another structural difference",
}

CATEGORY_HINTS = {
    "false-code": "Tighten the reachability check and forbid entries into a proven data table.",
    "false-pointer": "Require proof that code reads the table, not just address-like values.",
    "long-data": "Look for a 4-byte read stride and check whether the values are addresses or records.",
    "missing-include": "Match a large opaque range against resource boundaries.",
    "opaque-include": "Follow the accesses to the range and recover the table element size.",
    "padding": "Normalise equivalent org, FF padding and boundary labels.",
    "text": "Recognise printable runs with a zero terminator.",
    "word-data": "Look for word reads, indexing and a constant 2-byte stride.",
    "other": "Check the accesses to the range and choose a separate data layout.",
}


@dataclass(frozen=True)
class SourceSpan:
    start: int
    end: int
    kind: str
    record: SourceAtAddress


@dataclass(frozen=True)
class DifferenceSegment:
    start: int
    end: int
    category: str
    reference_kind: str
    generated_kind: str


def _statement_for_operation(record: SourceAtAddress, operation: str) -> str:
    result = ""
    for line in record.lines:
        code = line.split(";", 1)[0].strip()
        label = LABEL.match(code)
        if label:
            code = label.group(1).strip()
        if code and code.split(None, 1)[0].lower() == operation:
            result = code
    return result


def semantic_kind(record: SourceAtAddress) -> str | None:
    operation = _operation(record.lines)
    if not operation:
        return None
    if operation.split(".", 1)[0] not in DIRECTIVES:
        return "instruction"
    aliases = {"db": "dc.b", "dw": "dc.w"}
    operation = aliases.get(operation, operation)
    if operation == "dc.b":
        statement = _statement_for_operation(record, _operation(record.lines))
        return "text" if '"' in statement or "'" in statement else "dc.b"
    if operation in {"dc.w", "dc.l"}:
        statement = _statement_for_operation(record, _operation(record.lines))
        operands = statement.split(None, 1)[1] if " " in statement else ""
        without_numbers = re.sub(
            r"\$[0-9A-Fa-f]+|0x[0-9A-Fa-f]+|\b\d+\b", "", operands
        )
        suffix = "symbolic" if re.search(r"[A-Za-z_]", without_numbers) else "numeric"
        return f"{operation}.{suffix}"
    return operation


def source_spans(source: dict[int, SourceAtAddress]) -> tuple[SourceSpan, ...]:
    addresses = sorted(source)
    spans = []
    for index, address in enumerate(addresses):
        record = source[address]
        kind = semantic_kind(record)
        if kind is None:
            continue
        next_address = addresses[index + 1] if index + 1 < len(addresses) else 0x20000
        encoded_size = len(_encoded_bytes(record)) // 2
        if kind == "instruction" and next_address - address > 10:
            end = address + encoded_size
        elif kind in {"org", "equ", "set"}:
            end = address + encoded_size
        else:
            end = next_address
        if end > address:
            spans.append(SourceSpan(address, end, kind, record))
    return tuple(spans)


def _base_kind(kind: str) -> str:
    if kind.startswith("dc.w"):
        return "dc.w"
    if kind.startswith("dc.l"):
        return "dc.l"
    return kind


def _category(reference_kind: str, generated_kind: str) -> str:
    ref = _base_kind(reference_kind)
    gen = _base_kind(generated_kind)
    if gen == "instruction" and ref != "instruction":
        return "false-code"
    if generated_kind.endswith(".symbolic") and reference_kind.endswith(".numeric"):
        return "false-pointer"
    if gen in {"dc.w", "dc.l"} and ref in {"dc.b", "text", "binclude"}:
        return "false-pointer"
    if gen == "binclude" and ref in {"dc.b", "dc.w", "dc.l", "text"}:
        return "opaque-include"
    if ref == "binclude" and gen != "binclude":
        return "missing-include"
    if ref == "text" and gen == "dc.b":
        return "text"
    if ref == "dc.w" and gen == "dc.b":
        return "word-data"
    if ref == "dc.l" and gen == "dc.b":
        return "long-data"
    if ref == "none" or gen in {"org", "none"}:
        return "padding"
    return "other"


def _equivalent(reference_kind: str, generated_kind: str) -> bool:
    if reference_kind == generated_kind:
        return True
    if reference_kind == generated_kind == "instruction":
        return True
    return False


def difference_segments(
    reference: tuple[SourceSpan, ...], generated: tuple[SourceSpan, ...]
) -> tuple[DifferenceSegment, ...]:
    boundaries = sorted(
        {value for span in (*reference, *generated) for value in (span.start, span.end)}
    )
    ref_index = gen_index = 0
    result = []

    def active(
        spans: tuple[SourceSpan, ...], address: int, index: int
    ) -> tuple[SourceSpan | None, int]:
        while index < len(spans) and spans[index].end <= address:
            index += 1
        if index < len(spans) and spans[index].start <= address < spans[index].end:
            return spans[index], index
        return None, index

    for start, end in zip(boundaries, boundaries[1:]):
        ref_span, ref_index = active(reference, start, ref_index)
        gen_span, gen_index = active(generated, start, gen_index)
        ref_kind = ref_span.kind if ref_span else "none"
        gen_kind = gen_span.kind if gen_span else "none"
        if _equivalent(ref_kind, gen_kind):
            continue
        category = _category(ref_kind, gen_kind)
        segment = DifferenceSegment(start, end, category, ref_kind, gen_kind)
        if (
            result
            and result[-1].end == start
            and result[-1].category == category
            and result[-1].reference_kind == ref_kind
            and result[-1].generated_kind == gen_kind
        ):
            previous = result.pop()
            segment = DifferenceSegment(
                previous.start, end, category, ref_kind, gen_kind
            )
        result.append(segment)
    return tuple(result)


def _labels(
    source: dict[int, SourceAtAddress], start: int, end: int
) -> list[str]:
    result = []
    for address in sorted(key for key in source if start <= key < end):
        for line in source[address].lines:
            match = LABEL.match(line.strip())
            if match:
                result.append(line.split(":", 1)[0].strip())
    return result


def group_segments(
    segments: tuple[DifferenceSegment, ...],
    reference: dict[int, SourceAtAddress],
    generated: dict[int, SourceAtAddress],
) -> list[dict[str, object]]:
    grouped: list[list[DifferenceSegment]] = []
    for segment in segments:
        if grouped and grouped[-1][-1].end == segment.start:
            grouped[-1].append(segment)
        else:
            grouped.append([segment])
    result = []
    for index, items in enumerate(grouped, 1):
        start, end = items[0].start, items[-1].end
        category_bytes: Counter[str] = Counter()
        transitions: Counter[str] = Counter()
        for item in items:
            size = item.end - item.start
            category_bytes[item.category] += size
            transitions[f"{item.reference_kind} -> {item.generated_kind}"] += size
        result.append({
            "id": f"M68K-{index:03d}",
            "start": f"{start:06X}",
            "end_exclusive": f"{end:06X}",
            "size": end - start,
            "categories": dict(category_bytes.most_common()),
            "transitions": dict(transitions.most_common()),
            "reference_labels": _labels(reference, start, end),
            "generated_labels": _labels(generated, start, end),
            "html_anchor": f"flicky-source-diff.html#a{start:06X}",
        })
    return result


def instruction_groups(
    addresses: set[int], instructions: dict[int, bytes], prefix: str
) -> list[dict[str, object]]:
    groups = []
    for address in sorted(addresses):
        end = address + len(instructions[address])
        if groups and address <= groups[-1]["_end"]:
            groups[-1]["_end"] = max(groups[-1]["_end"], end)
            groups[-1]["end_exclusive"] = f"{groups[-1]['_end']:04X}"
            groups[-1]["instruction_count"] += 1
            continue
        groups.append({
            "id": f"{prefix}-{len(groups) + 1:03d}",
            "start": f"{address:04X}",
            "end_exclusive": f"{end:04X}",
            "instruction_count": 1,
            "_end": end,
        })
    for group in groups:
        group.pop("_end")
    return groups


def _z80_groups(reference: Path, generated: Path, output: Path) -> dict[str, object]:
    listing = output / "reference" / "z80_driver.lst"
    driver = reference / "data" / "sound" / "data_z80_part1.bin"
    facts = generated.parent / "analysis" / "z80" / "program00" / "instructions.json"
    if not all(path.is_file() for path in (listing, driver, facts)):
        return {"available": False}
    known = listing_instructions(
        listing, driver.read_bytes(), source_column=36, hex_width=2
    )
    analyzed = {
        item["physical_offset"]: bytes.fromhex(item["bytes"])
        for item in json.loads(facts.read_text(encoding="utf-8"))["instructions"]
    }
    missed = set(known) - set(analyzed)
    extra = set(analyzed) - set(known)
    return {
        "available": True,
        "missed_instruction_count": len(missed),
        "extra_instruction_count": len(extra),
        "missed_groups": instruction_groups(missed, known, "Z80-MISSED"),
        "extra_groups": instruction_groups(extra, analyzed, "Z80-EXTRA"),
    }


def write_report(reference: Path, generated: Path, output: Path) -> dict[str, object]:
    reference_rom = (reference / ROM_NAME).read_bytes()
    generated_rom = (generated / "rebuilt.bin").read_bytes()
    if reference_rom != generated_rom:
        raise ValueError("reference and generated ROMs differ; build and verify first")
    ref_source = listing_source(reference / "build" / "main.lst")
    gen_source = listing_source(generated / "build" / "retrolarium-main.lst")
    segments = difference_segments(source_spans(ref_source), source_spans(gen_source))
    groups = group_segments(segments, ref_source, gen_source)
    category_bytes: Counter[str] = Counter()
    category_groups: Counter[str] = Counter()
    for group in groups:
        for category, size in group["categories"].items():
            category_bytes[category] += size
            category_groups[category] += 1
    report: dict[str, object] = {
        "schema": "retrolarium.flicky-discrepancy-groups",
        "schema_version": 1,
        "m68k": {
            "group_count": len(groups),
            "different_bytes": sum(group["size"] for group in groups),
            "category_group_counts": dict(category_groups.most_common()),
            "category_byte_counts": dict(category_bytes.most_common()),
            "groups": groups,
        },
        "z80": _z80_groups(reference, generated, output),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "flicky-discrepancy-groups.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    lines = [
        "# Flicky: groups of remaining differences",
        "",
        "Both ROMs match byte for byte. These are the differences in "
        "source structure, merged into contiguous ROM ranges.",
        "",
        "## M68K summary",
        "",
        f"Groups: **{len(groups)}**, bytes affected: "
        f"**{sum(group['size'] for group in groups)}**.",
        "",
        "| Category | Groups | Bytes | Direction for the heuristic |",
        "| --- | ---: | ---: | --- |",
    ]
    for category, count in category_groups.most_common():
        lines.append(
            f"| {CATEGORY_LABELS[category]} | {count} | "
            f"{category_bytes[category]} | {CATEGORY_HINTS[category]} |"
        )
    lines.extend((
        "",
        "## All M68K groups",
        "",
        "| ID | Range | Bytes | Categories | Reference labels |",
        "| --- | --- | ---: | --- | --- |",
    ))
    for group in groups:
        start = group["start"]
        end = f"{int(group['end_exclusive'], 16) - 1:06X}"
        categories = ", ".join(
            f"{CATEGORY_LABELS[key]} ({value})"
            for key, value in group["categories"].items()
        )
        labels = ", ".join(group["reference_labels"][:8]) or "—"
        if len(group["reference_labels"]) > 8:
            labels += f" … +{len(group['reference_labels']) - 8}"
        lines.append(
            f"| [{group['id']}](flicky-source-diff.html#a{start}) | "
            f"`${start}–{end}` | {group['size']} | {categories} | {labels} |"
        )
    z80 = report["z80"]
    lines.extend(("", "## Z80 groups", ""))
    if not z80["available"]:
        lines.append("There is no Z80 reference listing.")
    else:
        lines.extend((
            f"Missed instructions: **{z80['missed_instruction_count']}** in "
            f"**{len(z80['missed_groups'])}** groups. Extra instructions: "
            f"**{z80['extra_instruction_count']}** in "
            f"**{len(z80['extra_groups'])}** groups.",
            "",
            "| ID | Range | Instructions |",
            "| --- | --- | ---: |",
        ))
        for group in (*z80["missed_groups"], *z80["extra_groups"]):
            end = f"{int(group['end_exclusive'], 16) - 1:04X}"
            lines.append(
                f"| {group['id']} | `${group['start']}–{end}` | "
                f"{group['instruction_count']} |"
            )
    lines.append("")
    (output / "flicky-discrepancy-groups.md").write_text(
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
    print(json.dumps({
        "m68k_groups": report["m68k"]["group_count"],
        "z80_missed_groups": len(report["z80"].get("missed_groups", [])),
        "z80_extra_groups": len(report["z80"].get("extra_groups", [])),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
