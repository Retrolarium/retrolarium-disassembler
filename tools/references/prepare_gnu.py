"""Normalize a linked GNU assembler reference, for evaluation only.

Requires an original-identical upstream build and a separately linked build
of the flattened source. GNU listing addresses are section-relative; the
linker map supplies physical bases. Relocations come from the proven linked
ROM. Only explicit M68K statements (including expanded macros) are counted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil

from sonic_corpus_benchmark import M68K, digest, operation
from source_benchmark import read_listing


def section_bases(text: str, object_name: str) -> dict[str, int]:
    result = {}
    pattern = re.compile(r"^\s+(\.[\w.]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S+)\s*$", re.I)
    for line in text.splitlines():
        match = pattern.fullmatch(line)
        if match and match[4].replace("\\", "/") == object_name:
            name, address = match[1], int(match[2], 16)
            if name in result and result[name] != address:
                raise ValueError(f"ambiguous linker section: {name}")
            result[name] = address
    if not result:
        raise ValueError("object sections not found in GNU linker map")
    return result


def normalize_listing(text: str, rom: bytes, bases: dict[str, int]) -> tuple[str, dict[int, bytes]]:
    section = ".text"
    records = []
    pending = None
    labels = []

    def finish():
        nonlocal pending
        if pending is not None:
            records.append(pending)
            pending = None

    for line in text.splitlines():
        if "\t" not in line:
            # GNU wraps an instruction's bytes onto rows with the same source
            # line number and no address/source column. Incbin dumps may be
            # truncated; they are boundaries, never counted as instructions.
            words = line.split()
            if pending and words and words[0] == pending["line"]:
                chunks = words[1:]
                if chunks and all(re.fullmatch(r"[0-9a-f]{4}", w, re.I) for w in chunks):
                    pending["raw"] += bytes.fromhex("".join(chunks))
            continue
        finish()
        header, source = line.split("\t", 1)
        source = source.lstrip().lstrip(">").strip()
        # Macro expansion nesting markers precede actual source statements.
        source = re.sub(r"^>+\s*", "", source)
        if source.startswith((".subsection", ".pushsection", ".popsection", ".previous")):
            raise ValueError("unsupported GNU section stack/subsection")
        match = re.match(r"\.section\s+([^\s,]+)", source)
        if match:
            section = match[1].strip('"')
            labels = []
        elif source in {".text", ".data", ".bss"}:
            section = source
            labels = []
        label = re.fullmatch(r"([\w.$]+):", source)
        if label:
            labels.append(source)
        words = header.split()
        if len(words) < 3 or not re.fullmatch(r"[0-9a-f]{4,8}", words[1], re.I):
            continue
        if not all(re.fullmatch(r"[0-9a-f]{4}", w, re.I) for w in words[2:]):
            continue
        if section not in bases:
            raise ValueError(f"unmapped GNU section {section}")
        address = bases[section] + int(words[1], 16)
        pending = {"line": words[0], "address": address, "raw": bytes.fromhex("".join(words[2:])),
                   "source": source, "labels": labels}
        labels = []
    finish()
    instructions = {}
    rows = []
    instruction_ranges = []
    for record in records:
        address, raw, source = record["address"], record["raw"], record["source"]
        is_instruction = operation(source).split(".", 1)[0] in M68K
        if is_instruction:
            if len(raw) not in {2, 4, 6, 8, 10} or address < 0 or address + len(raw) > len(rom):
                raise ValueError(f"invalid complete instruction at {address:#x}")
            actual = rom[address:address + len(raw)]
            opcode = int.from_bytes(raw[:2], "big")
            mask = 0xFF00 if opcode & 0xF000 == 0x6000 else 0xFFFF
            if opcode & mask != int.from_bytes(actual[:2], "big") & mask:
                raise ValueError(f"linked opcode differs from listing at {address:#x}")
            if address in instructions:
                raise ValueError(f"duplicate instruction address {address:#x}")
            instructions[address] = actual
            instruction_ranges.append((address, address + len(raw)))
        if not 0 <= address < len(rom):
            if is_instruction:
                raise ValueError("instruction outside ROM")
            continue
        for label in record["labels"]:
            rows.append((address, label, b""))
        # At most six bytes fit the existing AS listing column. Explicit end
        # boundaries below establish full lengths without decoding assets.
        payload = rom[address:address + min(len(raw), 6)]
        display = source if is_instruction else "dc.b ; GNU data boundary: " + source
        rows.append((address, display, payload))
    preceding_end = 0
    for address, end in sorted(instruction_ranges):
        if address < preceding_end:
            raise ValueError(f"overlapping GNU instructions at {address:#x}")
        preceding_end = end
        if end - address >= 6 and end < len(rom):
            rows.append((end, "; complete GNU instruction boundary", rom[end:end + 2]))
    out = []
    for number, (address, source, raw) in enumerate(sorted(rows, key=lambda r: r[0]), 1):
        if len(raw) % 2:
            encoded = " ".join(f"{v:02X}" for v in raw)
        else:
            encoded = " ".join(raw[i:i+2].hex().upper() for i in range(0, len(raw), 2))
        out.append(f"{number:6d}/{address:08X} : {encoded:<21}{source}")
    return "\n".join(out) + "\n", instructions


def prepare(*, name: str, original: Path, upstream_binary: Path, flattened_binary: Path,
            source: Path, listing: Path, link_map: Path, object_name: str, output: Path) -> dict:
    rom = original.read_bytes()
    if upstream_binary.read_bytes() != rom or flattened_binary.read_bytes() != rom:
        raise ValueError("both upstream and flattened builds must be byte-identical to original")
    bases = section_bases(link_map.read_text(), object_name)
    normalized, expected = normalize_listing(listing.read_text(), rom, bases)
    output.mkdir(parents=True, exist_ok=True)
    target_source, target_listing = output / "main.s", output / "reference-normalized.lst"
    shutil.copyfile(source, target_source)
    target_listing.write_text(normalized, encoding="utf-8", newline="\n")
    found, uncertain = read_listing(target_listing, rom)
    if found != expected or uncertain or not found:
        raise ValueError("normalized GNU listing lost instruction bytes or lengths")
    binary = output / "reference.bin"
    binary.write_bytes(rom)
    result = {"name": name, "status": "verified-original", "matches_upstream": True,
              "matching_original_roms": [str(original.resolve())], "binary": str(binary.resolve()),
              "binary_sha256": digest(binary), "source": str(target_source.resolve()),
              "source_sha256": digest(target_source), "listing": str(target_listing.resolve()),
              "listing_sha256": digest(target_listing), "reference_instructions": len(found),
              "uncertain_instruction_addresses": 0, "listing_provenance": {
                  "assembler": "GNU as (complete continuation bytes), GNU ld section map",
                  "upstream_binary_sha256": digest(upstream_binary),
                  "flattened_binary_sha256": digest(flattened_binary),
                  "gnu_listing_sha256": digest(listing), "linker_map_sha256": digest(link_map),
                  "instructions_outside_rom": 0, "section_bases": bases}}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    for key in ("original", "upstream-binary", "flattened-binary", "source", "listing", "link-map", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--object-name", required=True)
    print(json.dumps(prepare(**vars(parser.parse_args())), indent=2))


if __name__ == "__main__":
    main()
