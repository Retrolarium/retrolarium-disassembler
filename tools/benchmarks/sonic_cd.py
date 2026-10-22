"""Compare ROM-only M68K analysis of Sonic CD MMD overlays with scddisasm.

Reference listings are used only after Ghidra has analyzed the disc file.
Every candidate reference instruction is checked against the original bytes.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import sys

from tools.benchmarks.sonic_corpus import M68K, compare
from tools.benchmarks.source import instruction_quality


SOURCE_LINE = re.compile(r"^([0-9A-Fa-f]{8}) ((?:[0-9A-Fa-f]{4})(?: [0-9A-Fa-f]{4}){0,7})\s{2,}(.*)$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def overlay_header(data: bytes) -> tuple[int, tuple[int, ...]]:
    if len(data) < 0x102 or data[1] != 0:
        raise ValueError("MMD header is missing or truncated")
    origin = int.from_bytes(data[2:6], "big")
    entry = int.from_bytes(data[8:12], "big")
    base = (origin or entry) - 0x100
    if base < 0:
        raise ValueError("MMD load address is invalid")
    entries = tuple(
        address
        for address in (
            entry,
            int.from_bytes(data[12:16], "big"),
            int.from_bytes(data[16:20], "big"),
        )
        if address and base <= address < base + len(data) and not address & 1
    )
    if not entries:
        raise ValueError("MMD has no file-backed entry point")
    return base, tuple(dict.fromkeys(entries))


def reference_instructions(
    listing: Path, data: bytes, base: int
) -> tuple[dict[int, bytes], dict[int, str], dict[str, int]]:
    """Map an AS first-pass listing onto proven final bytes of one MMD file."""
    found: dict[int, bytes] = {}
    sources: dict[int, str] = {}
    stats = {"candidates": 0, "unmapped": 0, "opcode_conflicts": 0, "length_conflicts": 0}
    for line in listing.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SOURCE_LINE.match(line)
        if not match:
            continue
        source = match[3].strip()
        if source.startswith("M "):
            source = source[2:].strip()
        code = source.split(";", 1)[0].strip()
        code = re.sub(r"^[\w.$]+:\s*", "", code)
        op = code.split(None, 1)[0].lower().lstrip("!") if code else ""
        if op.split(".", 1)[0] not in M68K:
            continue
        stats["candidates"] += 1
        address = int(match[1], 16)
        offset = address - base
        printed = bytes.fromhex(match[2])
        if not 0 <= offset <= len(data) - len(printed):
            stats["unmapped"] += 1
            continue
        actual = data[offset : offset + len(printed)]
        expected_opcode = int.from_bytes(printed[:2], "big")
        actual_opcode = int.from_bytes(actual[:2], "big")
        mask = 0xFF00 if expected_opcode & 0xF000 == 0x6000 or expected_opcode & 0xF100 == 0x7000 else 0xFFFF
        if expected_opcode & mask != actual_opcode & mask:
            stats["opcode_conflicts"] += 1
            continue
        if actual_opcode & 0xF000 == 0x6000:
            length = 4 if actual_opcode & 0xFF == 0 else 2
            if len(printed) != length:
                stats["length_conflicts"] += 1
                continue
        previous = found.get(offset)
        if previous is not None and previous != actual:
            raise ValueError(f"conflicting reference instruction at 0x{offset:X}")
        found[offset] = actual
        sources[offset] = source
    return found, sources, stats


def generated_instructions(tsv: Path, data: bytes, base: int) -> tuple[dict[int, bytes], dict[int, str]]:
    found: dict[int, bytes] = {}
    sources: dict[int, str] = {}
    with tsv.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if row["block"] != "CD_MODULE":
                continue
            offset = int(row["address"], 16) - base
            raw = bytes.fromhex(row["bytes"])
            if not 0 <= offset <= len(data) - len(raw) or data[offset : offset + len(raw)] != raw:
                raise ValueError(f"Ghidra instruction disagrees with disc at 0x{offset:X}")
            found[offset] = raw
            sources[offset] = row["mnemonic"] + " " + row["operands"].replace("|", ",")
    return found, sources


def emit_overlay_project(
    tsv: Path, data: bytes, base: int, root: Path, assembler: Path, p2bin: Path, *, tail_data: bytes = b""
) -> tuple[dict[int, bytes], dict[str, object]]:
    """Emit a standalone ASM module, assemble it, and require exact bytes."""
    from retrolarium_disassembler.facts import InstructionFact, parse_address, parse_references
    from retrolarium_disassembler.megadrive.emit import _asm_instruction

    facts: dict[int, InstructionFact] = {}
    with tsv.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if row["block"] != "CD_MODULE":
                continue
            offset = int(row["address"], 16) - base
            raw = bytes.fromhex(row["bytes"])
            if not 0 <= offset <= len(data) - len(raw) or data[offset : offset + len(raw)] != raw:
                raise ValueError(f"Ghidra instruction disagrees with disc at 0x{offset:X}")
            facts[offset] = InstructionFact(
                physical_offset=offset,
                bank=0,
                cpu_address=base + offset,
                length=len(raw),
                raw=raw,
                mnemonic=row["mnemonic"],
                operands=row["operands"],
                flows=tuple(parse_address(value) for value in row["flows"].split("|") if value),
                flow_type=row["flow_type"],
                backend_space=row["space"],
                backend_block=row["block"],
                backend_symbol=row["symbol"],
                backend_function=row["function"],
                references=parse_references(row["references"]),
            )
    source = root / "src/main.s"
    source.parent.mkdir(parents=True, exist_ok=True)
    (root / "src/data").mkdir(exist_ok=True)
    (root / "src/memory").mkdir(exist_ok=True)
    (root / "src/macros").mkdir(exist_ok=True)
    fact_offsets = sorted(facts)
    banned: set[int] = set()
    rebuilt = root / "rebuilt.bin"
    for _attempt in range(min(len(facts) + 1, 128)):
        lines = ["; Standalone Sega CD M68K overlay, generated from disc bytes.", f"    phase ${base:08X}"]
        line_instruction_offsets: dict[int, int] = {}
        emitted: dict[int, bytes] = {}
        offset = 0
        while offset < len(data):
            fact = facts.get(offset)
            instruction = _asm_instruction(fact) if fact and offset not in banned else None
            if instruction:
                lines.append(f"                {instruction}")
                line_instruction_offsets[len(lines)] = offset
                emitted[offset] = fact.raw
                offset += fact.length
                continue
            next_index = bisect_right(fact_offsets, offset)
            next_fact = fact_offsets[next_index] if next_index < len(fact_offsets) else len(data)
            end = min(offset + 16, next_fact, len(data))
            if fact:
                end = min(end, offset + fact.length)
            if end <= offset:
                raise ValueError(f"cannot advance overlay source at 0x{offset:X}")
            lines.append("                dc.b    " + ", ".join(f"${byte:02X}" for byte in data[offset:end]))
            offset = end
        lines.append("    dephase")
        if tail_data:
            (root / "src/data/remainder.bin").write_bytes(tail_data)
            lines.append('                binclude "src/data/remainder.bin"')
        source.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        source.with_suffix(".p").unlink(missing_ok=True)
        rebuilt.unlink(missing_ok=True)
        assembled = subprocess.run(
            [str(assembler.resolve()), "-q", "-xx", "-n", "-A", "-L", "-U", "-E", "-i", ".", str(source.resolve())],
            cwd=root.resolve(),
            capture_output=True,
            text=True,
        )
        if assembled.returncode:
            log = source.with_suffix(".log")
            diagnostic = log.read_text(errors="replace") if log.exists() else assembled.stderr
            bad_lines = {int(value) for value in re.findall(r"main\.s\((\d+)\):[^\n]*\berror\b", diagnostic, re.I)}
            demote = {line_instruction_offsets[line] for line in bad_lines if line in line_instruction_offsets}
            if not demote - banned:
                raise ValueError("overlay ASM failed to assemble: " + diagnostic[-1000:])
            banned.update(demote)
            continue
        converted = subprocess.run(
            [str(p2bin.resolve()), str(source.with_suffix(".p").resolve()), str(rebuilt.resolve())],
            cwd=root.resolve(),
            capture_output=True,
            text=True,
        )
        if converted.returncode or not rebuilt.is_file():
            raise ValueError("overlay ASM conversion failed: " + converted.stderr[-1000:])
        actual = rebuilt.read_bytes()
        if actual == data + tail_data:
            break
        first = next(
            (i for i, (left, right) in enumerate(zip(data, actual)) if left != right), min(len(data), len(actual))
        )
        earlier = [point for point in emitted if point <= first < point + len(emitted[point])]
        if not earlier:
            raise ValueError(
                f"overlay rebuild differs outside emitted instruction at 0x{first:X} "
                f"({len(actual)} vs {len(data)} bytes)"
            )
        banned.add(earlier[-1])
    else:
        raise ValueError("overlay ASM did not converge to exact bytes")
    project = {
        "schema": "retrolarium.sonic-cd-overlay",
        "schema_version": 1,
        "load_base": base,
        "input_sha256": sha256(data + tail_data),
        "module_sha256": sha256(data),
        "unmapped_tail_size": len(tail_data),
        "source": "src/main.s",
        "rebuilt": "rebuilt.bin",
        "emitted_instructions": len(emitted),
        "analysis_instructions": len(facts),
        "demoted_instructions": sorted(banned),
    }
    (root / "overlay-project.json").write_text(json.dumps(project, indent=2) + "\n", encoding="utf-8")
    return emitted, project


def write_difference_html(
    path: Path,
    known: dict[int, bytes],
    actual: dict[int, bytes],
    reference_text: dict[int, str],
    generated_text: dict[int, str],
    base: int,
    *,
    title: str = "Sonic CD",
) -> None:
    rows = []
    for offset in sorted(known.keys() | actual.keys()):
        if known.get(offset) == actual.get(offset):
            continue
        left = known.get(offset)
        right = actual.get(offset)
        rows.append(
            "<tr><td>${:06X}</td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>".format(
                base + offset,
                left.hex(" ").upper() if left else "—",
                html.escape(reference_text.get(offset, "—")),
                right.hex(" ").upper() if right else "—",
                html.escape(generated_text.get(offset, "—")),
            )
        )
    path.write_text(
        "<!doctype html><meta charset='utf-8'><title>" + html.escape(title) + " opcode differences</title>"
        "<style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}"
        "td,th{border:1px solid #bbb;padding:.3rem;vertical-align:top}code{white-space:nowrap}</style>"
        "<h1>" + html.escape(title) + ": 68000 instruction differences</h1><table>"
        "<tr><th>Address</th><th>Reference</th><th>Reference source</th>"
        "<th>Kit</th><th>Kit disassembly</th></tr>" + "\n".join(rows) + "</table>",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disc-files", type=Path, default=Path("build/sonic-cd/disc-files"))
    parser.add_argument("--corpus", type=Path, default=Path("build/sonic-references"))
    parser.add_argument("--output", type=Path, default=Path("build/sonic-cd/comparison"))
    parser.add_argument("--ghidra-home", type=Path, default=Path(__file__).resolve().parents[2] / ".tools" / "ghidra")
    parser.add_argument("--unit", action="append", help="limit to a reference unit name; repeat as needed")
    parser.add_argument(
        "--report-only", action="store_true", help="rebuild summary from existing per-module comparisons"
    )
    parser.add_argument(
        "--reuse-analysis", action="store_true", help="re-emit and verify projects from saved decoder facts"
    )
    parser.add_argument("--minimum-source-recall", type=float, default=0)
    parser.add_argument("--assembler", type=Path, default=Path("references/scddisasm/bin/asw.exe"))
    parser.add_argument("--p2bin", type=Path, default=Path("references/scddisasm/bin/p2bin.exe"))
    args = parser.parse_args()
    if not 0 <= args.minimum_source_recall <= 100:
        parser.error("minimum source recall must be between 0 and 100")
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from retrolarium_disassembler.m68k.repair.overlay import analyze_overlay
    from retrolarium_disassembler.ghidra import GhidraArtifacts

    manifest = json.loads((args.corpus / "manifest.json").read_text(encoding="utf-8"))
    sources = {sha256(path.read_bytes()): path for path in args.disc_files.rglob("*.MMD")}
    scripts = Path(__file__).resolve().parents[2] / "src/retrolarium_disassembler/ghidra/scripts"
    args.output.mkdir(parents=True, exist_ok=True)
    cases = []
    for unit in manifest["units"]:
        if unit.get("repository") != "scddisasm" or unit.get("cpu") != "m68000" or not unit.get("binary"):
            continue
        if args.unit and unit["name"] not in args.unit:
            continue
        binary = Path(unit["binary"]).read_bytes()
        if (
            not unit.get("matches_upstream")
            or sha256(binary) != unit["binary_sha256"]
            or sha256(Path(unit["source"]).read_bytes()) != unit["source_sha256"]
        ):
            raise ValueError(f"reference build or source changed: {unit['name']}")
        disc = sources.get(sha256(binary))
        if disc is None:
            continue  # A non-MMD unit needs a different address-space model.
        name = unit["name"]
        dest = args.output / name
        dest.mkdir(parents=True, exist_ok=True)
        if args.report_only:
            saved = dest / "comparison.json"
            if not saved.is_file():
                raise ValueError(f"comparison is missing for {name}")
            cases.append(json.loads(saved.read_text(encoding="utf-8")))
            continue
        print(f"Analyzing {name} ({disc.name})...", flush=True)
        try:
            base, entries = overlay_header(binary)
            if args.reuse_analysis:
                artifacts = GhidraArtifacts(
                    dest / "analysis/instructions.tsv", dest / "analysis/program.json", dest / "analysis/headless.log"
                )
            else:
                artifacts = analyze_overlay(
                    disc,
                    dest / "analysis",
                    args.ghidra_home,
                    scripts,
                    base_address=base,
                    entry_addresses=entries,
                )
            known, reference_text, provenance = reference_instructions(
                Path(unit["source"]).parent / "reference.lst", binary, base
            )
            actual, generated_text = generated_instructions(artifacts.facts, binary, base)
            emitted, project = emit_overlay_project(
                artifacts.facts, binary, base, dest / "project", args.assembler, args.p2bin
            )
            result = {
                "name": name,
                "disc_file": disc.name,
                "disc_sha256": sha256(binary),
                "load_base": base,
                "entry_addresses": entries,
                "reference_listing_sha256": sha256((Path(unit["source"]).parent / "reference.lst").read_bytes()),
                "reference_provenance": provenance,
                "comparison": compare(known, frozenset(), actual),
                "source_emission": compare(known, frozenset(), emitted),
                "project": str((dest / "project/overlay-project.json").resolve()),
                "rebuild_status": "exact",
            }
            write_difference_html(
                dest / "opcode-differences.html", known, emitted, reference_text, generated_text, base
            )
        except (ValueError, OSError, RuntimeError) as exc:
            result = {"name": name, "disc_file": disc.name, "error": str(exc)}
        (dest / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        cases.append(result)
    scored = [case["source_emission"] for case in cases if "source_emission" in case]
    reference_count = sum(case["reference_instructions"] for case in scored)
    match_count = sum(case["matching_instructions"] for case in scored)
    generated_count = sum(case["generated_instructions"] for case in scored)
    total = (
        {
            "reference_instructions": reference_count,
            "matching_instructions": match_count,
            "generated_instructions": generated_count,
            **instruction_quality(match_count, reference_count, generated_count),
        }
        if scored
        else None
    )
    summary = {
        "schema": "retrolarium.sonic-cd-overlay-benchmark",
        "cases": cases,
        "total_source_emission": total,
        "scope": "Standalone MMD M68K overlays only; byte/length/address instruction comparison.",
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Sonic CD Japan: MMD instruction comparison",
        "",
        "| Module | Reference instructions | Analysis recall | ASM recall | ASM precision | Rebuild | Differences |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for case in cases:
        if "comparison" in case:
            score = case["comparison"]
            source = case["source_emission"]
            lines.append(
                f"| {case['name']} | {score['reference_instructions']} | "
                f"{score['instruction_recall_percentage']}% | "
                f"{source['instruction_recall_percentage']}% | "
                f"{source['instruction_precision_percentage']}% | exact | "
                f"[HTML]({case['name']}/opcode-differences.html) |"
            )
        else:
            lines.append(f"| {case['name']} | — | — | — | — | failed | {case['error']} |")
    if total is not None:
        lines.append(
            f"| **Total ({len(scored)} MMD)** | **{reference_count}** | — | "
            f"**{total['instruction_recall_percentage']}%** | "
            f"**{total['instruction_precision_percentage']}%** | "
            f"{len(scored)} exact | — |"
        )
    lines += [
        "",
        "The reference listings are used only to compare after the disc's MMDs are analysed.",
        "BIN programs, Z80 and the disc's other files need a separate loading model.",
    ]
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(cases), "errors": sum("error" in case for case in cases)}, indent=2))
    if not scored or len(scored) != len(cases) or 100 * match_count < args.minimum_source_recall * reference_count:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
