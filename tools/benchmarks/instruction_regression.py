"""Audit instruction losses between two assembled disassemblies of one ROM.

Inputs are normalized AS listings. The manual listing is used only here for
evaluation; this tool never supplies addresses to the ROM analyzer.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.benchmarks.source import instruction_quality, read_listing


def compare_instruction_sets(reference, before, after):
    """A net increase cannot compensate for a previously matching instruction."""
    old = {address for address, raw in reference.items() if before.get(address) == raw}
    new = {address for address, raw in reference.items() if after.get(address) == raw}

    def describe(address):
        return dict(offset=address, offset_hex=f"{address:06X}",
                    reference=reference[address].hex(" "),
                    before=before.get(address, b"").hex(" "),
                    after=after.get(address, b"").hex(" "))

    def score(actual, matching):
        return dict(matching=len(matching), generated=len(actual),
                    extra=len(actual.keys() - reference.keys()),
                    different_encodings=len(actual.keys() & reference.keys() - matching),
                    **instruction_quality(len(matching), len(reference), len(actual)))

    def fingerprint(matching):
        digest = sha256()
        for address in sorted(matching):
            raw = reference[address]
            digest.update(address.to_bytes(8, "big"))
            digest.update(len(raw).to_bytes(2, "big"))
            digest.update(raw)
        return digest.hexdigest()

    lost, gained = old - new, new - old
    return dict(status="regressed" if lost else "preserved", reference=len(reference),
                before=score(before, old), after=score(after, new),
                net_delta=len(new) - len(old), lost_count=len(lost), gained_count=len(gained),
                lost=[describe(address) for address in sorted(lost)],
                gained=[describe(address) for address in sorted(gained)],
                before_matched_sha256=fingerprint(old), after_matched_sha256=fingerprint(new))


def read_complete_listing(path: Path, rom: bytes, base: int = 0):
    """Normalize logical addresses and reject unknown instruction lengths."""
    class MappedROM:
        def __getitem__(self, key):
            start, stop = key.start - base, key.stop - base
            return rom[start:stop] if 0 <= start <= stop <= len(rom) else b""

    instructions, opened = read_listing(path, MappedROM() if base else rom)
    if opened:
        addresses = ", ".join(f"{address:06X}" for address in sorted(opened)[:8])
        raise ValueError(f"unknown instruction lengths in {path}: {addresses}")
    normalized = {address - base: raw for address, raw in instructions.items()}
    for address, raw in normalized.items():
        if address < 0 or address + len(raw) > len(rom) or rom[address:address + len(raw)] != raw:
            raise ValueError(f"listing instruction does not match ROM at {address:#x}: {path}")
    return normalized


def audit_listings(rom_path: Path, reference_path: Path, before_path: Path, after_path: Path,
                   before_rom: Path, after_rom: Path, *, reference_base=0, generated_base=0):
    rom = rom_path.read_bytes()
    for path in (before_rom, after_rom):
        if path.read_bytes() != rom:
            raise ValueError(f"rebuilt image differs from original ROM: {path}")
    reference = read_complete_listing(reference_path, rom, reference_base)
    if not reference:
        raise ValueError("reference listing has no complete instructions; check its format and address base")
    before = read_complete_listing(before_path, rom, generated_base)
    after = read_complete_listing(after_path, rom, generated_base)
    result = compare_instruction_sets(reference, before, after)
    paths = dict(rom=rom_path, reference=reference_path, before=before_path,
                 after=after_path, before_rom=before_rom, after_rom=after_rom)
    result.update(schema="retrolarium.instruction-regression", schema_version=1,
                  rebuild_status="exact", reference_base=reference_base, generated_base=generated_base,
                  inputs={name: dict(path=str(path.resolve()), sha256=sha256(path.read_bytes()).hexdigest())
                          for name, path in paths.items()})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("rom", "reference", "before", "after", "before-rom", "after-rom", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--reference-base", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--generated-base", type=lambda value: int(value, 0), default=0)
    args = parser.parse_args(argv)
    if min(args.reference_base, args.generated_base) < 0:
        parser.error("listing bases must be nonnegative")
    try:
        result = audit_listings(args.rom, args.reference, args.before, args.after,
                                args.before_rom, args.after_rom,
                                reference_base=args.reference_base, generated_base=args.generated_base)
    except (OSError, ValueError) as error:
        result = dict(schema="retrolarium.instruction-regression", schema_version=1,
                      status="invalid", error=str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("status", "lost_count", "gained_count", "error")
                      if key in result}))
    return {"preserved": 0, "regressed": 1, "invalid": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
