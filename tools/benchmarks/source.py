"""Build a comparison-only, flattened Mega Drive source oracle.

The reference tree is read only. Its contents must never be an input to the
ROM-to-source emitter; this tool runs after emission for evaluation.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


INCLUDE = re.compile(r'^\s*include\s+"([^"]+)"', re.IGNORECASE)
LABEL = re.compile(r"^\s*([A-Za-z_.$][\w.$]*)\s*:\s*(.*)$")
MNEMONIC = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:\.[bwlcs]?)?$", re.IGNORECASE)
DIRECTIVES = {
    "binclude",
    "dc",
    "ds",
    "equ",
    "include",
    "org",
    "cpu",
    "page",
    "supmode",
    "padding",
    "end",
    "align",
    "cnop",
    "org0",
    "set",
    "if",
    "else",
    "endif",
    "rept",
    "endr",
    "macro",
    "endm",
    "even",
    "db",
    "dw",
    "dd",
    "defs",
}
LISTING_LINE = re.compile(r"^(?:\(\d+\))?\s*\d+/\s*([0-9A-Fa-f]+)\s+: (.*)$")


def instruction_quality(matches: int, reference_count: int, generated_count: int) -> dict[str, float]:
    recall = 100 * matches / reference_count if reference_count else 100.0
    precision = 100 * matches / generated_count if generated_count else (100.0 if not reference_count else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "instruction_recall_percentage": round(recall, 2),
        "instruction_precision_percentage": round(precision, 2),
        "instruction_f1_percentage": round(f1, 2),
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_z80_reference_listing(reference: Path, output: Path) -> None:
    """Assemble the oracle Z80 source only inside the comparison directory."""
    listing = output / "reference" / "z80_driver.lst"
    source = reference / "src" / "sound" / "z80" / "driver.asm"
    assembler = reference / "bin" / "windows_i386" / "asw.exe"
    if not source.is_file() or not assembler.is_file():
        return
    object_file = listing.with_suffix(".p")
    command = [
        str(assembler),
        "-i",
        str(reference),
        "-L",
        "-olist",
        str(listing),
        "-o",
        str(object_file),
        os.path.relpath(source, assembler.parent),
    ]
    result = subprocess.run(
        command,
        cwd=assembler.parent,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode or not listing.is_file():
        raise ValueError(f"reference Z80 assembler failed: {result.stdout[-1000:]} {result.stderr[-1000:]}")


def flatten(reference: Path) -> tuple[str, list[dict[str, object]]]:
    src = reference / "src"
    entry = src / "main.s"
    if not entry.is_file():
        raise ValueError(f"missing reference entry: {entry}")
    output: list[str] = []
    origins: list[dict[str, object]] = []
    active: set[Path] = set()

    def visit(path: Path) -> None:
        path = path.resolve()
        if not path.is_relative_to(src.resolve()):
            raise ValueError(f"source include escapes src: {path}")
        if path in active:
            raise ValueError(f"recursive source include: {path}")
        active.add(path)
        start = len(output) + 1
        for line in path.read_text(encoding="utf-8").splitlines():
            match = INCLUDE.match(line)
            if match and match.group(1).lower().endswith(".s"):
                child = src / match.group(1)
                if not child.is_file():
                    raise ValueError(f"missing source include: {child}")
                output.append(f"; BEGIN {child.relative_to(src).as_posix()}")
                visit(child)
                output.append(f"; END {child.relative_to(src).as_posix()}")
            else:
                output.append(line)
        origins.append(
            {
                "path": path.relative_to(src).as_posix(),
                "start_line": start,
                "end_line": len(output),
                "sha256": sha256(path),
            }
        )
        active.remove(path)

    visit(entry)
    return "\n".join(output) + "\n", origins


def source_metrics(source: str) -> dict[str, int]:
    metrics = {
        "lines": 0,
        "labels": 0,
        "instruction_lines": 0,
        "raw_byte_directives": 0,
        "binary_includes": 0,
        "source_includes": 0,
    }
    for raw in source.splitlines():
        metrics["lines"] += 1
        code = raw.split(";", 1)[0].strip()
        if not code:
            continue
        label = LABEL.match(code)
        if label:
            metrics["labels"] += 1
            code = label.group(2).strip()
            if not code:
                continue
        words = code.split(None, 1)
        if not words:
            continue
        operation = words[0].lower()
        if operation in {"dc.b", "db"}:
            metrics["raw_byte_directives"] += 1
        elif operation == "binclude":
            metrics["binary_includes"] += 1
        elif operation == "include":
            metrics["source_includes"] += 1
        elif MNEMONIC.fullmatch(operation) and operation.split(".", 1)[0] not in DIRECTIVES:
            metrics["instruction_lines"] += 1
    return metrics


# AS lists at most six leading bytes on a 68000 source line; the longest
# 68000 instruction is ten bytes.
M68K_LISTED_BYTES = 6
M68K_MAXIMUM_INSTRUCTION = 10


def read_listing(
    path: Path,
    rom: bytes | None,
    *,
    source_column: int = 21,
    hex_width: int = 4,
    listed_bytes: int | None = M68K_LISTED_BYTES,
    maximum_length: int = M68K_MAXIMUM_INSTRUCTION,
) -> tuple[dict[int, bytes], frozenset[int]]:
    """Read byte-proven instructions and the addresses whose length is unknown.

    A line showing exactly ``listed_bytes`` may be truncated. Its full length
    is recovered from the next listed byte address when that is close enough
    to belong to the same instruction; the bytes then come from ``rom``.
    Otherwise the address is returned as open-ended and only its prefix is
    known. Without ``rom`` the listing is not verified or extended.
    """
    found: dict[int, bytes] = {}
    boundaries: set[int] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = LISTING_LINE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        encoded = match.group(2)[:source_column]
        source = match.group(2)[source_column:]
        code = source.split(";", 1)[0].strip()
        label = LABEL.match(code)
        if label:
            code = label.group(2).strip()
        operation = code.split(None, 1)[0].lower() if code else ""
        words = encoded.split()
        if operation in {"binclude", "incbin", "binfile"}:
            boundaries.add(address)
        if not words or not all(
            len(word) in {2, 4} and all(char in "0123456789abcdefABCDEF" for char in word) for word in words
        ):
            continue
        boundaries.add(address)
        if not all(len(word) == hex_width for word in words) or not operation:
            continue
        if not MNEMONIC.fullmatch(operation) or operation.split(".", 1)[0] in DIRECTIVES:
            continue
        payload = bytes.fromhex("".join(words))
        if rom is not None and rom[address : address + len(payload)] != payload:
            raise ValueError(f"reference listing disagrees with ROM at {address:#x}")
        previous = found.get(address)
        if previous is not None and previous != payload:
            raise ValueError(f"conflicting reference instructions at {address:#x}")
        found[address] = payload
    if listed_bytes is None:
        return found, frozenset()
    ordered = sorted(boundaries)
    open_ended = set()
    for address, payload in found.items():
        if len(payload) != listed_bytes:
            continue
        # A 68000 JMP/JSR has at most a four-byte effective address. An
        # absolute-long jump already occupies all six displayed bytes; the
        # next data statement may be several bytes away after a ROM gap.
        if listed_bytes == 6 and int.from_bytes(payload[:2], "big") & 0xFFC0 in {0x4E80, 0x4EC0}:
            continue
        index = bisect_right(ordered, address)
        following = ordered[index] if index < len(ordered) else None
        length = None if following is None else following - address
        if length is None or not listed_bytes <= length <= maximum_length or rom is None:
            if length != listed_bytes:
                open_ended.add(address)
            continue
        full = rom[address : address + length]
        if len(full) != length:
            open_ended.add(address)
            continue
        found[address] = full
    return found, frozenset(open_ended)


def listing_instructions(path: Path, rom: bytes, *, source_column: int = 21, hex_width: int = 4) -> dict[int, bytes]:
    """Read byte-proven listed instruction bytes without length recovery."""
    return read_listing(path, rom, source_column=source_column, hex_width=hex_width, listed_bytes=None)[0]


def same_instruction(expected: bytes, actual: bytes, *, expected_open: bool = False, actual_open: bool = False) -> bool:
    """Compare instructions, allowing only an open-ended side to be a prefix.

    A truncated listing prefix never matches an instruction of a different
    length unless the listing itself leaves that length undetermined.
    """
    if expected_open and actual_open:
        return expected.startswith(actual) or actual.startswith(expected)
    if expected_open:
        return actual.startswith(expected)
    if actual_open:
        return expected.startswith(actual)
    return expected == actual


def instruction_comparison(reference: Path, generated: Path) -> dict[str, object] | None:
    listing = reference / "build" / "main.lst"
    rom_path = reference / "Flicky (UE) [!].bin"
    facts_path = generated.parent / "analysis" / "m68k" / "instructions.json"
    if not all(path.is_file() for path in (listing, rom_path, facts_path)):
        return None
    rom = rom_path.read_bytes()
    known, known_open = read_listing(listing, rom)
    facts = json.loads(facts_path.read_text(encoding="utf-8"))["instructions"]
    analyzed = {item["physical_offset"]: bytes.fromhex(item["bytes"]) for item in facts}

    def analyzed_matches(address: int) -> bool:
        return same_instruction(known[address], analyzed[address], expected_open=address in known_open)

    matches = sorted(address for address in known.keys() & analyzed.keys() if analyzed_matches(address))
    disagreements = sorted(address for address in known.keys() & analyzed.keys() if not analyzed_matches(address))
    missed = sorted(known.keys() - analyzed.keys())
    extra = sorted(analyzed.keys() - known.keys())
    quality = instruction_quality(len(matches), len(known), len(analyzed))
    report = {
        "reference_listing_sha256": sha256(listing),
        "reference_rom_sha256": sha256(rom_path),
        "reference_instructions": len(known),
        "generated_instructions": len(analyzed),
        "matching_instruction_starts": len(matches),
        "matching_instruction_percentage": round(100 * len(matches) / len(known), 2),
        **quality,
        "missed_reference_instructions": len(missed),
        "other_generated_instructions": len(extra),
        "different_opcode_prefixes_at_same_address": len(disagreements),
        "first_missed_addresses": [f"{address:06X}" for address in missed[:12]],
        "first_other_addresses": [f"{address:06X}" for address in extra[:12]],
    }
    source_listing = generated / "build" / "retrolarium-main.lst"
    rebuilt = generated / "rebuilt.bin"
    if source_listing.is_file() and rebuilt.is_file():
        emitted, emitted_open = read_listing(source_listing, rebuilt.read_bytes())
        source_matches = sum(
            address in known
            and same_instruction(
                known[address],
                emitted[address],
                expected_open=address in known_open,
                actual_open=address in emitted_open,
            )
            for address in emitted
        )
        report["source_emission"] = {
            "listing_sha256": sha256(source_listing),
            "emitted_mnemonic_instructions": len(emitted),
            "matching_reference_instructions": source_matches,
            "matching_reference_percentage": round(100 * source_matches / len(known), 2),
            **instruction_quality(source_matches, len(known), len(emitted)),
        }
    return report


def z80_source_comparison(reference: Path, generated: Path) -> dict[str, object] | None:
    original_files = sorted((reference / "src" / "sound" / "z80" / "driver").glob("*.asm"))
    generated_files = sorted((generated / "src" / "sound" / "z80").glob("program*.asm"))
    if not original_files and not generated_files:
        return None
    reference_text = "\n".join(path.read_text(encoding="utf-8") for path in original_files)
    generated_text = "\n".join(path.read_text(encoding="utf-8") for path in generated_files)
    report = {
        "reference_files": len(original_files),
        "reference_metrics": source_metrics(reference_text),
        "generated_files": len(generated_files),
        "generated_metrics": source_metrics(generated_text),
    }
    return report


def z80_program_facts(facts_path: Path) -> tuple[int | None, dict[int, bytes]]:
    """Return a Z80 program's load base and instructions keyed by Z80 address."""
    facts = json.loads(facts_path.read_text(encoding="utf-8"))["instructions"]
    bases = {item["logical_address"] - item["physical_offset"] for item in facts}
    if len(bases) > 1:
        raise ValueError(f"Z80 facts use inconsistent load bases: {facts_path}")
    analyzed = {item["logical_address"]: bytes.fromhex(item["bytes"]) for item in facts}
    return (next(iter(bases)) if bases else None), analyzed


def compare_z80_program(
    known: dict[int, bytes],
    base: int,
    payload: bytes,
    analyzed: dict[int, bytes],
    emitted: dict[int, bytes] | None = None,
) -> dict[str, object]:
    """Compare one loaded Z80 program with the reference instructions it contains.

    Reference instructions count only when their listed bytes equal the
    program bytes at the same Z80 address, so overlays loaded at the same
    destination are not credited to each other. ``emitted`` is keyed by
    offset in the program, as the generated source assembles at ``org 0``.
    """
    owned = {
        address: raw
        for address, raw in known.items()
        if base <= address and payload[address - base : address - base + len(raw)] == raw
    }
    matches = {address for address in owned.keys() & analyzed.keys() if analyzed[address] == owned[address]}
    result: dict[str, object] = {
        "base_address": base,
        "size": len(payload),
        "reference_instructions": len(owned),
        "generated_instructions": len(analyzed),
        "matching_instruction_starts": len(matches),
        **instruction_quality(len(matches), len(owned), len(analyzed)),
        "missed_reference_instructions": len(owned.keys() - analyzed.keys()),
        "other_generated_instructions": len(analyzed.keys() - owned.keys()),
        "different_opcode_prefixes_at_same_address": len((owned.keys() & analyzed.keys()) - matches),
        "_matches": matches,
        "_owned": set(owned),
    }
    if emitted is not None:
        source_matches = {base + offset for offset, raw in emitted.items() if owned.get(base + offset) == raw}
        result["source_emission"] = {
            "emitted_mnemonic_instructions": len(emitted),
            "matching_reference_instructions": len(source_matches),
            **instruction_quality(len(source_matches), len(owned), len(emitted)),
        }
        result["_source_matches"] = source_matches
    return result


def z80_instruction_comparison(reference: Path, generated: Path, output: Path) -> dict[str, object] | None:
    listing = output / "reference" / "z80_driver.lst"
    facts_root = generated.parent / "analysis" / "z80"
    fact_paths = sorted(facts_root.glob("program*/instructions.json"))
    if not listing.is_file() or not fact_paths:
        return None
    # Program bytes, not one reference part, verify the listing below.
    known, _ = read_listing(listing, None, source_column=36, hex_width=2, listed_bytes=None)
    programs = []
    analyzed_total = 0
    emitted_total = 0
    has_emission = False
    matched: set[int] = set()
    source_matched: set[int] = set()
    owned: set[int] = set()
    analyzed_addresses: set[int] = set()
    disagreements = 0
    for facts_path in fact_paths:
        name = facts_path.parent.name
        driver = generated / "build" / f"z80-{name}.bin"
        if not driver.is_file():
            raise ValueError(f"generated Z80 program is missing: {driver}")
        payload = driver.read_bytes()
        base, analyzed = z80_program_facts(facts_path)
        if base is None:
            base = 0
        source_listing = generated / "build" / f"z80-{name}.lst"
        emitted = None
        if source_listing.is_file():
            emitted, _ = read_listing(source_listing, payload, source_column=24, hex_width=2, listed_bytes=None)
        result = compare_z80_program(known, base, payload, analyzed, emitted)
        matched |= result.pop("_matches")
        owned |= result.pop("_owned")
        analyzed_addresses |= analyzed.keys()
        analyzed_total += len(analyzed)
        disagreements += result["different_opcode_prefixes_at_same_address"]
        if emitted is not None:
            has_emission = True
            emitted_total += len(emitted)
            source_matched |= result.pop("_source_matches")
            result["source_emission"]["listing_sha256"] = sha256(source_listing)
        programs.append({"program": name, "generated_driver_sha256": sha256(driver), **result})
    missed = sorted(known.keys() - analyzed_addresses)
    extra = sorted(analyzed_addresses - known.keys())
    reference_parts = sorted((reference / "data" / "sound").glob("data_z80_part*.bin"))
    report = {
        "reference_listing_sha256": sha256(listing),
        "reference_driver_sha256": {path.name: sha256(path) for path in reference_parts},
        "programs": programs,
        "reference_instructions": len(known),
        "unattributed_reference_instructions": len(known.keys() - owned),
        "generated_instructions": analyzed_total,
        "matching_instruction_starts": len(matched),
        "matching_instruction_percentage": round(100 * len(matched) / len(known), 2) if known else 100.0,
        **instruction_quality(len(matched), len(known), analyzed_total),
        "missed_reference_instructions": len(missed),
        "other_generated_instructions": len(extra),
        "different_opcode_prefixes_at_same_address": disagreements,
        "first_missed_addresses": [f"{address:04X}" for address in missed[:12]],
        "first_other_addresses": [f"{address:04X}" for address in extra[:12]],
    }
    if has_emission:
        report["source_emission"] = {
            "emitted_mnemonic_instructions": emitted_total,
            "matching_reference_instructions": len(source_matched),
            "matching_reference_percentage": round(100 * len(source_matched) / len(known), 2) if known else 100.0,
            **instruction_quality(len(source_matched), len(known), emitted_total),
        }
    return report


def memory_symbol_comparison(reference: Path, generated: Path) -> dict[str, object] | None:
    result: dict[str, object] = {}
    for name in ("ram.inc", "hardware.inc"):
        left = reference / "src" / "memory" / name
        right = generated / "src" / "memory" / name
        if not left.is_file() or not right.is_file():
            continue
        count = lambda path: sum(
            bool(re.match(r"^\s*[A-Za-z_][\w.]*:?\s+equ\b", line, re.I))
            for line in path.read_text(encoding="utf-8").splitlines()
        )
        result[name] = {"reference_symbols": count(left), "generated_symbols": count(right)}
    return result or None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--minimum-instruction-match", type=float, default=0)
    parser.add_argument("--minimum-instruction-precision", type=float, default=0)
    parser.add_argument("--minimum-instruction-f1", type=float, default=0)
    parser.add_argument("--minimum-source-match", type=float, default=0)
    parser.add_argument("--minimum-m68k-instruction-match", type=float, default=0)
    parser.add_argument("--minimum-m68k-precision", type=float, default=0)
    parser.add_argument("--minimum-m68k-f1", type=float, default=0)
    parser.add_argument("--minimum-m68k-source-match", type=float, default=0)
    parser.add_argument("--minimum-z80-instruction-match", type=float, default=0)
    parser.add_argument("--minimum-z80-precision", type=float, default=0)
    parser.add_argument("--minimum-z80-f1", type=float, default=0)
    parser.add_argument("--minimum-z80-source-match", type=float, default=0)
    args = parser.parse_args()
    for value in (
        args.minimum_instruction_match,
        args.minimum_instruction_precision,
        args.minimum_instruction_f1,
        args.minimum_source_match,
        args.minimum_m68k_instruction_match,
        args.minimum_m68k_precision,
        args.minimum_m68k_f1,
        args.minimum_m68k_source_match,
        args.minimum_z80_instruction_match,
        args.minimum_z80_precision,
        args.minimum_z80_f1,
        args.minimum_z80_source_match,
    ):
        if not 0 <= value <= 100:
            parser.error("match percentages must be between 0 and 100")
    reference = args.reference.resolve()
    generated = args.generated.resolve()
    output = args.output.resolve()
    flattened, origins = flatten(reference)
    generated_source = generated / "src" / "main.s"
    if not generated_source.is_file():
        raise ValueError(f"generated project needs src/main.s: {generated_source}")
    generated_flattened, generated_origins = flatten(generated)
    output.mkdir(parents=True, exist_ok=True)
    (output / "reference").mkdir(exist_ok=True)
    (output / "generated").mkdir(exist_ok=True)
    prepare_z80_reference_listing(reference, output)
    (output / "reference" / "main.s").write_text(flattened, encoding="utf-8", newline="\n")
    (output / "generated" / "main.s").write_text(generated_flattened, encoding="utf-8", newline="\n")
    (output / "reference-source-map.json").write_text(
        json.dumps(origins, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (output / "generated-source-map.json").write_text(
        json.dumps(generated_origins, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    report = {
        "schema": "retrolarium.source-benchmark",
        "schema_version": 1,
        "reference": {
            "entry_sha256": sha256(reference / "src" / "main.s"),
            "modules": len(origins) - 1,
            "metrics": source_metrics(flattened),
        },
        "generated": {
            "entry_sha256": sha256(generated_source),
            "modules": len(generated_origins) - 1,
            "metrics": source_metrics(generated_flattened),
        },
    }
    manifest = generated.parent / "retrolarium-project.json"
    if manifest.is_file():
        project = json.loads(manifest.read_text(encoding="utf-8"))
        if project.get("schema") == "retrolarium.megadrive.disassembly":
            report["generated"]["rom_coverage"] = project["source"]["coverage"]
    instruction_report = instruction_comparison(reference, generated)
    if instruction_report is not None:
        project = json.loads(manifest.read_text(encoding="utf-8"))
        input_sha = project["input"]["sha256"]
        if instruction_report["reference_rom_sha256"] != input_sha:
            raise ValueError("reference and generated projects use different ROMs")
        instruction_report["generated_rom_sha256"] = input_sha
        report["instruction_comparison"] = instruction_report
    z80_report = z80_source_comparison(reference, generated)
    if z80_report is not None:
        report["z80_source_comparison"] = z80_report
    z80_instructions = z80_instruction_comparison(reference, generated, output)
    if z80_instructions is not None:
        report["z80_instruction_comparison"] = z80_instructions
    memory_report = memory_symbol_comparison(reference, generated)
    if memory_report is not None:
        report["memory_symbol_comparison"] = memory_report
    (output / "comparison.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    thresholds = {
        "68000": (
            args.minimum_m68k_instruction_match or args.minimum_instruction_match,
            args.minimum_m68k_source_match or args.minimum_source_match,
            args.minimum_m68k_precision or args.minimum_instruction_precision,
            args.minimum_m68k_f1 or args.minimum_instruction_f1,
        ),
        "Z80": (
            args.minimum_z80_instruction_match or args.minimum_instruction_match,
            args.minimum_z80_source_match or args.minimum_source_match,
            args.minimum_z80_precision or args.minimum_instruction_precision,
            args.minimum_z80_f1 or args.minimum_instruction_f1,
        ),
    }
    for cpu, key in (("68000", "instruction_comparison"), ("Z80", "z80_instruction_comparison")):
        comparison = report.get(key)
        (
            minimum_instruction_match,
            minimum_source_match,
            minimum_precision,
            minimum_f1,
        ) = thresholds[cpu]
        if minimum_instruction_match:
            if not isinstance(comparison, dict):
                raise SystemExit(f"{cpu} reference instruction comparison is missing")
            actual = comparison["matching_instruction_percentage"]
            if actual < minimum_instruction_match:
                raise SystemExit(f"{cpu} instruction match {actual}% is below {minimum_instruction_match}%")
        for label, minimum, field in (
            ("precision", minimum_precision, "instruction_precision_percentage"),
            ("F1", minimum_f1, "instruction_f1_percentage"),
        ):
            if not minimum:
                continue
            if not isinstance(comparison, dict):
                raise SystemExit(f"{cpu} reference instruction comparison is missing")
            actual = comparison[field]
            if actual < minimum:
                raise SystemExit(f"{cpu} instruction {label} {actual}% is below {minimum}%")
        if minimum_source_match:
            emission = comparison.get("source_emission") if isinstance(comparison, dict) else None
            if not isinstance(emission, dict):
                raise SystemExit(f"{cpu} assembled source comparison is missing")
            actual = emission["matching_reference_percentage"]
            if actual < minimum_source_match:
                raise SystemExit(f"{cpu} assembled source match {actual}% is below {minimum_source_match}%")


if __name__ == "__main__":
    main()
