"""Evaluate ROM-only Sonic disassembly against verified assembly references."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

from flicky_html_diff import write_html
from source_benchmark import LISTING_LINE, instruction_quality, read_listing, same_instruction


M68K = set("""abcd add adda addi addq addx and andi asl asr bcc bcs beq bge bgt bhi
ble bls blt bmi bne bpl bra bsr bvc bvs bhs blo bchg bclr bset btst chk clr cmp
cmpa cmpi cmpm dbcc dbcs dbeq dbf dbge dbgt dbhi dble dbls dblt dbmi dbne dbpl
dbra dbt dbvc dbvs divs divu eor eori exg ext illegal jmp jsr lea link lsl lsr
move movea movem movep moveq muls mulu nbcd neg negx nop not or ori pea reset
rol ror roxl roxr rte rtr rts sbcd scc scs seq sf sge sgt shi sle sls slt smi
sne spl st svc svs stop sub suba subi subq subx swap tas trap trapv tst unlk""".split())
SN_LINE = re.compile(r"^([0-9A-Fa-f]{8}) (.{26})(.*)$")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def operation(source: str) -> str:
    code = source.split(";", 1)[0].strip()
    code = re.sub(r"^[\w.$]+:\s*", "", code)
    return code.split(None, 1)[0].lower().lstrip("!") if code else ""


def normalise_reference_listing(
    listing: Path, rom: bytes, output: Path, *, sn: bool = False,
    patched_ranges: tuple[tuple[int, int], ...] = (),
) -> tuple[dict[int, bytes], frozenset[int], dict]:
    """Keep M68K instructions, resolve address phases and verify opcode bytes.

    AS distinguishes M68K words from Z80 byte groups. SN lists unresolved
    forward operands from its first pass; the proven final ROM supplies those
    operands, with opcode shape and instruction length checked below.
    These mappings are evaluation-only and are never passed to the analyzer.
    """
    candidates: dict[int, tuple[bytes, str]] = {}
    labels: dict[int, list[str]] = {}
    phase_labels: list[tuple[dict[int, list[str]], set[int]]] = []
    boundaries: set[int] = set()
    delta = 0
    phases: list[int] = []
    saved: list[tuple[int, str]] = []
    cpu = "68000"
    assembler_patches: dict[int, int] = {}
    previous_physical = 0
    pending_obj: int | None = None
    macro_depth = 0
    stats = Counter()
    unmapped_samples = []

    def project(address: int) -> int:
        if not sn:
            return address + delta
        if 0x880000 <= address < 0x900000:
            return address - 0x880000
        if 0x900000 <= address < 0xA00000:
            return address - 0x900000 + 0x200000
        if phases:
            return address + delta
        return address

    for line in listing.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SN_LINE.match(line) if sn else LISTING_LINE.match(line)
        if match is None:
            continue
        address = int(match[1], 16)
        encoded, source = (match[2], match[3]) if sn else (match[2][:20], match[2][20:])
        code = source.split(";", 1)[0].strip()
        op = operation(source)
        if re.match(r"^\S+\s+macros?\b", code, re.I):
            macro_depth += 1
        if macro_depth:
            if op == "endm":
                macro_depth -= 1
            continue
        if pending_obj is not None:
            delta = pending_obj - address
            pending_obj = None
        if op == "save":
            saved.append((delta, cpu))
        elif op == "restore" and saved:
            delta, cpu = saved.pop()
        elif op == "cpu":
            cpu = code.split(None, 1)[1].strip().upper()
        elif op == "phase":
            phases.append(delta)
            phase_labels.append(({}, set()))
            delta = previous_physical - address
        elif op == "dephase" and phases:
            delta = phases.pop()
            if phase_labels:
                pending_labels, phase_instructions = phase_labels.pop()
                if phase_instructions:
                    labels.update(pending_labels)
        elif op == "obj" and sn:
            pending_obj = project(address)
            phases.append(delta)
            continue
        elif op == "objend" and sn and phases:
            delta = phases.pop()
        physical = project(address)
        previous_physical = physical
        words = encoded.split()
        if words and all(re.fullmatch(r"(?:[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4})", word) for word in words):
            previous_physical = physical + len(bytes.fromhex("".join(words)))
            if not sn and cpu == "68000" and code.startswith("!dc."):
                for index, value in enumerate(bytes.fromhex("".join(words))):
                    assembler_patches[physical + index] = value
        if not sn and cpu != "68000":
            continue
        label = re.match(r"([\w.$]+):", code)
        label_emitter = op.split(".", 1)[0] in M68K | {"dc", "dcb", "binclude", "binfile", "incbin"}
        if label and (not op or label_emitter) and 0 <= physical < len(rom):
            # Phased DS declarations describe RAM, without storing ROM bytes.
            # Publish their labels only when the phase actually contains code.
            target_labels = phase_labels[-1][0] if phase_labels else labels
            target_labels.setdefault(physical, []).append(label[1] + ":")
        # Byte directives also delimit the preceding truncated instruction.
        # Their encoding groups need not have the width of M68K opcodes.
        if words and all(re.fullmatch(r"(?:[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4})", word) for word in words):
            boundary_raw = bytes.fromhex("".join(words))
            if 0 <= physical < len(rom) and rom[physical:physical + len(boundary_raw)] == boundary_raw:
                boundaries.add(physical)
        if not words or not all(re.fullmatch(r"[0-9A-Fa-f]{4}", word) for word in words):
            continue
        raw = bytes.fromhex("".join(words))
        if not 0 <= physical < len(rom) or physical + len(raw) > len(rom):
            if op.split(".", 1)[0] in M68K:
                stats["instructions_outside_rom"] += 1
                if len(unmapped_samples) < 12:
                    unmapped_samples.append({"logical_address": address, "physical_offset": physical,
                                             "source": source.strip()})
            continue
        actual = rom[physical:physical + len(raw)]
        if op.split(".", 1)[0] not in M68K:
            if actual == raw:
                boundaries.add(physical)
            continue
        boundaries.add(physical)
        if sn:
            if len(raw) > 10:
                raise ValueError(f"SN instruction longer than 68000 maximum: {physical:#x}")
            expected_opcode, actual_opcode = int.from_bytes(raw[:2], "big"), int.from_bytes(actual[:2], "big")
            # First-pass short branches and MOVEQ can have unresolved low bytes.
            mask = 0xFF00 if expected_opcode & 0xF000 == 0x6000 or expected_opcode & 0xF100 == 0x7000 else 0xFFFF
            if expected_opcode & mask != actual_opcode & mask:
                raise ValueError(f"SN opcode disagrees with proven final ROM: {physical:#x}")
            if actual_opcode & 0xF000 == 0x6000 and len(raw) != (4 if actual_opcode & 0xFF == 0 else 2):
                raise ValueError(f"SN branch length disagrees with final ROM: {physical:#x}")
            stats["first_pass_operands_resolved"] += actual != raw
            raw = actual
            boundaries.add(physical + len(raw))
        previous = candidates.get(physical)
        if previous and previous[0] != raw:
            raise ValueError(f"conflicting reference instruction at {physical:#x}")
        candidates[physical] = (raw, re.sub(r"(?<!\w)!(?=[A-Za-z])", "", source).rstrip())
        if phase_labels:
            phase_labels[-1][1].add(physical)
    ordered = sorted(boundaries)
    found = {}
    open_ended = set()
    for address, (raw, source) in candidates.items():
        if not sn and raw != rom[address:address + len(raw)]:
            actual = rom[address:address + len(raw)]
            differences = [address + index for index, (left, right) in enumerate(zip(raw, actual)) if left != right]
            if not all(any(start <= point < end for start, end in patched_ranges)
                       or assembler_patches.get(point) == rom[point] for point in differences):
                raise ValueError(f"AS listing disagrees with original ROM: {address:#x}")
            stats["postprocessed_instructions"] += 1
            raw = actual
        if not sn and len(raw) == 6 and int.from_bytes(raw[:2], "big") & 0xFFC0 not in {0x4E80, 0x4EC0}:
            # Macro byte overwrites can create boundaries inside an instruction.
            index = bisect_right(ordered, address + len(raw) - 1)
            following = ordered[index] if index < len(ordered) else None
            length = following - address if following is not None else None
            if length is not None and 6 <= length <= 10:
                raw = rom[address:following]
            elif length != 6:
                open_ended.add(address)
        found[address] = raw
    # A common AS format lets the existing HTML comparison consume SN listings.
    interiors = bytearray(len(rom))
    for address, raw in found.items():
        interiors[address + 1:address + len(raw)] = b"\x01" * (len(raw) - 1)
        boundaries.add(address + len(raw))
    rows = []
    for address in sorted(boundaries | found.keys() | labels.keys()):
        if not 0 <= address < len(rom) - 1:
            continue
        for label in dict.fromkeys(labels.get(address, [])):
            rows.append(f"{len(rows) + 1:8d}/{address:8X} : {'':21}{label}")
        if address not in boundaries and address not in found:
            continue
        if interiors[address] and address not in found:
            continue
        raw, source = (found[address], candidates[address][1]) if address in found else (
            rom[address:address + 2], f" dc.w ${int.from_bytes(rom[address:address + 2], 'big'):04X} ; listing boundary")
        encoded = " ".join(raw[i:i + 2].hex().upper() for i in range(0, min(len(raw), 6), 2))
        rows.append(f"{len(rows) + 1:8d}/{address:8X} : {encoded:<21}{source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    stats.update(reference_instructions=len(found), open_ended_lengths=len(open_ended))
    return found, frozenset(open_ended), {**stats, "unmapped_samples": unmapped_samples}


def group_spans(addresses: set[int], instructions: dict[int, bytes]) -> list[dict]:
    groups = []
    for address in sorted(addresses):
        if groups and address <= groups[-1]["end"] + 12:
            groups[-1]["end"] = address + len(instructions[address])
            groups[-1]["instructions"] += 1
        else:
            groups.append({"start": address, "end": address + len(instructions[address]), "instructions": 1})
    return sorted(groups, key=lambda group: (-group["instructions"], group["start"]))


def compare(known: dict[int, bytes], known_open: frozenset[int], actual: dict[int, bytes]) -> dict:
    matching = {address for address in known.keys() & actual.keys()
                if same_instruction(known[address], actual[address], expected_open=address in known_open)}
    missing = known.keys() - matching
    extra = actual.keys() - known.keys()
    return {"reference_instructions": len(known), "generated_instructions": len(actual),
            "matching_instructions": len(matching), "missing_instructions": len(missing),
            "extra_instructions": len(extra),
            "different_encodings": len(known.keys() & actual.keys() - matching),
            **instruction_quality(len(matching), len(known), len(actual)),
            "missing_groups": group_spans(missing, known),
            "extra_groups": group_spans(extra, actual)}


def annotate_groups(groups: list[dict], listing: Path) -> None:
    labels = {}
    for line in listing.read_text(encoding="utf-8").splitlines():
        match = LISTING_LINE.match(line)
        if match is None:
            continue
        label = re.match(r"\s*([A-Za-z_$][\w.$]*):", match[2][21:])
        if label:
            labels[int(match[1], 16)] = label[1]
    addresses = sorted(labels)
    for group in groups:
        index = bisect_right(addresses, group["start"]) - 1
        if index >= 0:
            base = addresses[index]
            group["reference_context"] = f"{labels[base]}+${group['start'] - base:X}"


def benchmark(corpus: Path, projects: Path, output: Path) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from retrolarium_kit.project import build_project, verify_project
    reports = []
    for unit in manifest["units"]:
        if not unit.get("matching_original_roms"):
            continue
        name = "chaotix" if unit["name"] == "chaotix-main" else unit["name"]
        print(f"Comparing {name}...", flush=True)
        project, dest = projects / name, output / name
        dest.mkdir(parents=True, exist_ok=True)
        result = {"name": name, "rom_sha256": unit["binary_sha256"],
                  "reference_source_sha256": unit["source_sha256"]}
        reports.append(result)
        try:
            if not unit.get("matches_upstream"):
                raise ValueError("reference assembly was not verified against the upstream build")
            if digest(Path(unit["source"])) != unit["source_sha256"]:
                raise ValueError("reference source hash changed")
            rom_path = Path(unit["matching_original_roms"][0])
            if digest(rom_path) != unit["binary_sha256"] or digest(Path(unit["binary"])) != unit["binary_sha256"]:
                raise ValueError("original/reference ROM hash changed")
            project_manifest = project / "retrolarium-project.json"
            if not project_manifest.is_file():
                raise ValueError(f"ROM disassembly did not produce a project: {project}")
            build_project(project_manifest, toolchain_cache=output / "toolchain-cache")
            verification = verify_project(project_manifest)
            result["rebuild_status"] = verification["status"]
            if verification["status"] != "exact":
                raise ValueError("generated project does not reproduce original ROM")
            rom = rom_path.read_bytes()
            reference_dir = Path(unit["source"]).parent
            patches = ()
            if name == "sonic2-rev01":
                header = (reference_dir / "main.h").read_text(encoding="utf-8")
                offset = int(re.search(r"\bmovewZ80CompSize\b[^\r\n]*?(0x[0-9A-Fa-f]+)", header)[1], 16) + 2
                patches = ((offset, offset + 2),)
            listing = reference_dir / ("chaotix.lst" if name == "chaotix" else "reference.lst")
            normalized = dest / "reference-m68k.lst"
            known, known_open, provenance = normalise_reference_listing(listing, rom, normalized,
                                                                        sn=name == "chaotix", patched_ranges=patches)
            if known_open or provenance.get("instructions_outside_rom", 0):
                raise ValueError("reference listing has unresolved lengths or unmapped M68K instructions")
            recovered, recovered_open = read_listing(normalized, rom)
            if recovered != known or recovered_open:
                raise ValueError("normalized reference listing did not preserve complete instruction encodings")
            facts = json.loads((project / "analysis/m68k/instructions.json").read_text(encoding="utf-8"))
            if facts["input_sha256"] != unit["binary_sha256"]:
                raise ValueError("analysis input hash does not match reference")
            actual = {item["physical_offset"]: bytes.fromhex(item["bytes"]) for item in facts["instructions"]}
            result["analysis"] = compare(known, known_open, actual)
            emitted, emitted_open = read_listing(project / "generated/build/retrolarium-main.lst", rom)
            result["source_emission"] = compare(known, known_open, emitted)
            result["emitted_listing_open_ended_lengths"] = len(emitted_open)
            annotate_groups(result["source_emission"]["missing_groups"], normalized)
            annotate_groups(result["source_emission"]["extra_groups"], normalized)
            result["listing_provenance"] = provenance
            result["reference_listing_sha256"] = digest(listing)
            result["normalized_listing_sha256"] = digest(normalized)
            result["analysis_facts_sha256"] = digest(project / "analysis/m68k/instructions.json")
            result["generated_listing_sha256"] = digest(project / "generated/build/retrolarium-main.lst")
            passes = json.loads((project / "analysis/m68k/decoder-passes.json").read_text(encoding="utf-8"))
            result["decoder_passes"] = len(passes["passes"])
            result["decoder_converged"] = passes["converged"]
            z80_facts = [json.loads(path.read_text(encoding="utf-8"))
                         for path in (project / "analysis/z80").glob("*/instructions.json")]
            result["z80_payloads"] = len(z80_facts)
            result["z80_programs"] = sum(bool(program["instructions"]) for program in z80_facts)
            if name == "chaotix":
                result["limitation"] = (
                    "Baseline Mega Drive backend lacks 32X banks and SH-2; this measures partial M68K recovery only. "
                    "The reference includes mars_init.bin without M68K source, so additional instructions can be genuine bootstrap code."
                )
            counts = write_html(reference_dir, project / "generated", dest / "opcode-differences.html",
                                differences_only=True, opcodes_only=True, rom=rom_path,
                                reference_listing=normalized, title=name)
            result["html_status_counts"] = dict(counts)
            for key in ("missing", "extra"):
                lines = ["start\tend_exclusive\tinstructions\treference_context"]
                lines.extend(f"${group['start']:06X}\t${group['end']:06X}\t{group['instructions']}\t{group.get('reference_context', '')}"
                             for group in result["source_emission"][key + "_groups"])
                (dest / (key + "-groups.tsv")).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except (ValueError, RuntimeError, OSError) as error:
            result["error"] = str(error)
        (dest / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    report = {"schema": "retrolarium.sonic-corpus-benchmark", "schema_version": 1,
              "reference_repositories": manifest["repositories"], "cases": reports,
              "scope": "M68K opcodes. Sonic CD has no original disc input; Z80 recall needs separate decompressed-driver oracles."}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rows = ["# Sonic: automatic ROM disassembly", "",
            "A match is a 68000 instruction with the same address, length and bytes.", "",
            "| ROM | Reference | Analysis | ASM | Precision ASM | ROM rebuild | Differences |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- |"]
    for case in reports:
        if "source_emission" in case:
            source, analysis = case["source_emission"], case["analysis"]
            rows.append(f"| {case['name']} | {analysis['reference_instructions']} | "
                        f"{analysis['instruction_recall_percentage']}% | {source['instruction_recall_percentage']}% | "
                        f"{source['instruction_precision_percentage']}% | {case['rebuild_status']} | "
                        f"[HTML]({case['name']}/opcode-differences.html) |")
        else:
            rows.append(f"| {case['name']} | — | — | — | — | {case.get('rebuild_status', '—')} | {case.get('error')} |")
    rows += ["", "Chaotix: the current Mega Drive model does not support 32X banks and the SH-2; the result covers a partial M68K disassembly.",
             "Sonic CD: the original disc is missing, so it was not run. Z80 is not counted in the M68K percentages.", ""]
    (output / "summary.md").write_text("\n".join(rows), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("build/sonic-references"))
    parser.add_argument("--projects", type=Path, default=Path("build/sonic-disassembly"))
    parser.add_argument("--output", type=Path, default=Path("build/sonic-comparison"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = benchmark(args.corpus.resolve(), args.projects.resolve(), args.output.resolve())
    print(json.dumps([{key: value for key, value in case.items() if key in {"name", "error", "rebuild_status"}}
                      for case in report["cases"]], indent=2))
    if any("error" in case for case in report["cases"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
