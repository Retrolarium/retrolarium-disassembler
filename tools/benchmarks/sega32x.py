"""Analyze the fixed 32X M68K ROM window and compare a verified reference.

The reference is opened only after ROM-only analysis and exact assembly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from sonic_cd_benchmark import emit_overlay_project, generated_instructions, write_difference_html
from sonic_corpus_benchmark import normalise_reference_listing, compare


def fixed_window_entries(data: bytes) -> tuple[int, int, tuple[int, ...]]:
    if len(data) < 0x400 or data[0x100:0x108] != b"SEGA 32X":
        raise ValueError("expected SEGA 32X cartridge")
    base, size = 0x880000, min(len(data), 0x80000)
    entries = set()
    for offset in range(4, 0x100, 4):
        address = int.from_bytes(data[offset:offset + 4], "big") & 0xFFFFFF
        if offset == 4 and 0x200 <= address < size:
            address += base
        if base + 0x200 <= address < base + size and not address & 1:
            entries.add(address)
    # The 32X vector stub page begins at $200, before SH-2 metadata.
    # Decode its contiguous JMP/NOP/RTS slots, stopping at any other bytes.
    cursor = 0x200
    while cursor < 0x400 and data[0x200:0x202] == b"\x4e\xf9":
        word = data[cursor:cursor + 2]
        if word in {b"\x4e\xf9", b"\x4e\xf8"}:
            length = 6 if word == b"\x4e\xf9" else 4
            if cursor + length > 0x400:
                break
            target = int.from_bytes(data[cursor + 2:cursor + length], "big",
                                    signed=length == 4) & 0xFFFFFF
            if target & 1:
                break
            entries.add(base + cursor)
            if base + 0x200 <= target < base + size:
                entries.add(target)
            cursor += length
        elif word in {b"\x4e\x71", b"\x4e\x75"}:
            entries.add(base + cursor)
            cursor += 2
        else:
            break
    if not entries:
        raise ValueError("no executable vectors in fixed ROM window")
    return base, size, tuple(sorted(entries))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ghidra-home", type=Path, default=Path("retrolarium-disassembler/.tools/ghidra"))
    parser.add_argument("--reuse-analysis", action="store_true")
    parser.add_argument("--minimum-source-recall", type=float, default=0)
    args = parser.parse_args()
    if not 0 <= args.minimum_source_recall <= 100:
        parser.error("minimum source recall must be between 0 and 100")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from retrolarium_disasm.m68k.repair.overlay import analyze_overlay
    data = args.rom.read_bytes()
    base, size, entries = fixed_window_entries(data)
    args.output.mkdir(parents=True, exist_ok=True)
    payload = args.output / "fixed-window.bin"
    payload.write_bytes(data[:size])
    tsv = args.output / "analysis/instructions.tsv"
    if not args.reuse_analysis:
        analyze_overlay(payload, args.output / "analysis", args.ghidra_home,
                        Path(__file__).resolve().parents[1] / "src/retrolarium_disasm/ghidra/scripts",
                        base_address=base, entry_addresses=tuple(sorted(entries)))
    actual, text = generated_instructions(tsv, data[:size], base)
    emitted, project = emit_overlay_project(
        tsv, data[:size], base, args.output / "project",
        Path("references/scddisasm/bin/asw.exe"), Path("references/scddisasm/bin/p2bin.exe"),
        tail_data=data[size:])
    known, unknown, provenance = normalise_reference_listing(
        args.reference, data, args.output / "reference-m68k.lst", sn=True)
    result = {"name": "32x-fixed-window", "rom_sha256": hashlib.sha256(data).hexdigest(),
              "analysis": compare(known, unknown, actual),
              "source_emission": compare(known, unknown, emitted),
              "rebuild_status": "exact", "project": project,
              "reference_provenance": provenance,
              "scope": "Full reference M68K denominator; fixed-window analysis only. SH-2 excluded."}
    (args.output / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    from source_benchmark import LISTING_LINE
    reference_text = {}
    for line in (args.output / "reference-m68k.lst").read_text(encoding="utf-8").splitlines():
        match = LISTING_LINE.match(line)
        if match:
            reference_text[int(match[1], 16)] = match[2][21:].strip()
    write_difference_html(args.output / "opcode-differences.html", known, emitted, reference_text, text, 0,
                          title="Chaotix / 32X")
    print(json.dumps({k: v for k, v in result["source_emission"].items() if not isinstance(v, list)}, indent=2))
    if 100 * result["source_emission"]["matching_instructions"] < args.minimum_source_recall * len(known):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
