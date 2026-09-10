"""Exact-first ASM68K project emitter for analyzed Mega Drive ROMs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .megadrive_pointers import PointerCandidate
from .megadrive_symbols import TechnicalSymbol
from .megadrive_z80 import CrossCpuCopy


MODULE_SIZE = 0x10000


class MegaDriveEmitError(ValueError):
    """Analysis artifacts cannot be emitted without changing ROM bytes."""


@dataclass(frozen=True)
class EmitResult:
    source_units: tuple[str, ...]
    assets: tuple[dict[str, object], ...]
    instruction_bytes: int
    pointer_bytes: int
    asset_bytes: int
    raw_bytes: int


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hex_bytes(payload: bytes) -> str:
    return ", ".join(f"${value:02X}" for value in payload)


def _symbol_maps(
    symbols: tuple[TechnicalSymbol, ...],
) -> tuple[dict[int, TechnicalSymbol], dict[int, tuple[str, ...]]]:
    primary = {
        symbol.logical_address: symbol
        for symbol in symbols
        if symbol.cpu_id == "m68k"
    }
    aliases = {
        address: tuple(alias for alias in symbol.aliases if alias != symbol.name)
        for address, symbol in primary.items()
    }
    return primary, aliases


def _emit_labels(
    lines: list[str],
    logical_address: int,
    primary: dict[int, TechnicalSymbol],
    aliases: dict[int, tuple[str, ...]],
) -> None:
    symbol = primary.get(logical_address)
    if symbol is None:
        return
    lines.append(f"{symbol.name}:")
    lines.extend(f"{alias}:" for alias in aliases.get(logical_address, ()))


def _target_expression(
    address: int, primary: dict[int, TechnicalSymbol], width: int
) -> str:
    symbol = primary.get(address)
    if symbol is not None:
        return symbol.name
    return f"${address:0{width}X}"


def _pointer_lines(
    candidate: PointerCandidate,
    image: MegaDriveImage,
    primary: dict[int, TechnicalSymbol],
) -> list[str]:
    lines = [f"    ; {candidate.schema_id}"]
    table = _target_expression(candidate.logical_start, primary, 6)
    for entry in candidate.entries:
        target = _target_expression(entry.target, primary, 6)
        if candidate.schema_id == "megadrive.u32be.absolute":
            lines.append(f"    dc.l    {target}")
            encoded = entry.target.to_bytes(4, "big")
        elif candidate.schema_id == "megadrive.u16be.absolute":
            lines.append(f"    dc.w    {target}")
            encoded = entry.target.to_bytes(2, "big")
        elif candidate.schema_id == "megadrive.s16be.target-table_base":
            lines.append(f"    dc.w    {target}-{table}")
            encoded = ((entry.target - candidate.logical_start) & 0xFFFF).to_bytes(
                2, "big"
            )
        elif candidate.schema_id == "megadrive.s16be.target-entry_address":
            lines.append(f"    dc.w    {target}-*")
            encoded = ((entry.target - entry.logical_address) & 0xFFFF).to_bytes(
                2, "big"
            )
        else:
            raise MegaDriveEmitError(
                f"unsupported accepted pointer schema: {candidate.schema_id}"
            )
        original = image.data[
            entry.physical_offset:entry.physical_offset + candidate.entry_size
        ]
        if encoded != original:
            raise MegaDriveEmitError(
                f"pointer expression changes bytes at {entry.physical_offset:#x}"
            )
    return lines


def _selected_tables(
    candidates: tuple[PointerCandidate, ...],
    assets: tuple[tuple[int, int], ...],
) -> dict[int, PointerCandidate]:
    selected: dict[int, PointerCandidate] = {}
    occupied: set[int] = set()
    for candidate in sorted(
        candidates,
        key=lambda item: (-item.score, item.physical_start, -item.entry_size),
    ):
        if candidate.status != "accepted" or candidate.physical_start < 0x200:
            continue
        byte_range = set(range(candidate.physical_start, candidate.physical_end))
        if any(
            candidate.physical_start < end and start < candidate.physical_end
            for start, end in assets
        ):
            continue
        if occupied & byte_range:
            continue
        selected[candidate.physical_start] = candidate
        occupied.update(byte_range)
    return selected


def _emit_payload_module(
    path: Path,
    image: MegaDriveImage,
    start: int,
    limit: int,
    facts: dict[int, InstructionFact],
    tables: dict[int, PointerCandidate],
    asset_ranges: dict[int, tuple[int, str]],
    primary: dict[int, TechnicalSymbol],
    aliases: dict[int, tuple[str, ...]],
) -> tuple[int, int, int, int, int]:
    lines = [f"    ; ROM ${start:06X}..${limit - 1:06X}"]
    instruction_bytes = 0
    pointer_bytes = 0
    asset_bytes = 0
    raw_bytes = 0
    offset = start
    event_offsets = set(facts) | set(tables) | set(asset_ranges) | set(primary)
    while offset < limit:
        logical_address = image.header.rom_start + offset
        _emit_labels(lines, logical_address, primary, aliases)
        asset = asset_ranges.get(offset)
        if asset is not None:
            size, asset_path = asset
            lines.append(f'    binclude "{asset_path}"')
            lines.append("")
            asset_bytes += size
            offset += size
            continue
        table = tables.get(offset)
        if table is not None:
            lines.extend(_pointer_lines(table, image, primary))
            lines.append("")
            size = table.physical_end - table.physical_start
            pointer_bytes += size
            offset += size
            continue
        instruction = facts.get(offset)
        if instruction is not None:
            if image.data[offset:offset + instruction.length] != instruction.raw:
                raise MegaDriveEmitError(
                    f"instruction facts disagree with ROM at {offset:#x}"
                )
            lines.append(
                f"    dc.b    {_hex_bytes(instruction.raw)}"
                f"    ; ${instruction.cpu_address:06X}: "
                f"{instruction.mnemonic} {instruction.operands}".rstrip()
            )
            instruction_bytes += instruction.length
            offset += instruction.length
            continue

        next_events = [event for event in event_offsets if offset < event < limit]
        end = min(offset + 16, limit, min(next_events, default=limit))
        payload = image.data[offset:end]
        lines.append(f"    dc.b    {_hex_bytes(payload)}")
        raw_bytes += len(payload)
        offset = end
    path.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return offset, instruction_bytes, pointer_bytes, asset_bytes, raw_bytes


def emit_project(
    root: Path,
    image: MegaDriveImage,
    m68k_facts: dict[int, InstructionFact],
    pointer_candidates: tuple[PointerCandidate, ...],
    symbols: tuple[TechnicalSymbol, ...],
    z80_copies: tuple[CrossCpuCopy, ...],
) -> EmitResult:
    root.mkdir(parents=True, exist_ok=True)
    source_root = root / "src"
    asset_root = root / "assets"
    source_root.mkdir(exist_ok=True)
    asset_root.mkdir(exist_ok=True)
    primary, aliases = _symbol_maps(symbols)

    vector_lines = ["    ; Mega Drive 68000 vector table"]
    for vector in image.vector_table:
        logical_address = image.header.rom_start + vector.index * 4
        _emit_labels(vector_lines, logical_address, primary, aliases)
        vector_lines.append(
            f"    dc.l    ${vector.raw_value:08X}"
            f"    ; {vector.index}: {vector.name} -> ${vector.address:06X}"
        )
    vectors_path = source_root / "vectors.68k"
    vectors_path.write_text(
        "\n".join(vector_lines) + "\n", encoding="utf-8", newline="\n"
    )

    header_asset = asset_root / "header.bin"
    header_asset.write_bytes(image.header_data)
    header_source = source_root / "header.68k"
    header_source.write_text(
        '    binclude "assets/header.bin"\n', encoding="utf-8", newline="\n"
    )
    assets: list[dict[str, object]] = [
        {
            "id": "megadrive.cartridge.header",
            "kind": "container_header",
            "path": "assets/header.bin",
            "rom_file_offset": 0x100,
            "size": len(image.header_data),
            "sha256": _sha256(image.header_data),
            "emit": "binclude",
        }
    ]

    asset_ranges: dict[int, tuple[int, str]] = {}
    ranges: list[tuple[int, int]] = []
    for index, copy in enumerate(z80_copies):
        offset = copy.source_start - image.header.rom_start
        payload = image.data[offset:offset + copy.size]
        name = f"z80-program{index:02d}.bin"
        path = asset_root / name
        path.write_bytes(payload)
        relative = f"assets/{name}"
        asset_ranges[offset] = (copy.size, relative)
        ranges.append((offset, offset + copy.size))
        assets.append(
            {
                "id": f"megadrive.z80.program{index:02d}",
                "kind": "z80_program",
                "path": relative,
                "rom_file_offset": offset,
                "size": copy.size,
                "sha256": copy.payload_sha256,
                "emit": "binclude",
                "address": {
                    "space": "z80",
                    "start": copy.target_start,
                    "end": copy.target_end,
                },
            }
        )
    tables = _selected_tables(pointer_candidates, tuple(ranges))

    source_units = ["src/vectors.68k", "src/header.68k"]
    counts = [0, 0, 0, 0]
    offset = 0x200
    while offset < len(image.data):
        nominal_limit = min(
            len(image.data), ((offset // MODULE_SIZE) + 1) * MODULE_SIZE
        )
        name = f"rom-{offset:06x}.68k"
        path = source_root / name
        result = _emit_payload_module(
            path,
            image,
            offset,
            nominal_limit,
            m68k_facts,
            tables,
            asset_ranges,
            primary,
            aliases,
        )
        offset = result[0]
        counts = [left + right for left, right in zip(counts, result[1:])]
        source_units.append(f"src/{name}")

    main_lines = ["    org     $000000", ""]
    main_lines.extend(f'    include "{unit}"' for unit in source_units)
    (root / "main.68k").write_text(
        "\n".join(main_lines) + "\n", encoding="utf-8", newline="\n"
    )
    source_units.insert(0, "main.68k")
    covered = 0x100 + len(image.header_data) + sum(counts)
    if covered != len(image.data):
        raise MegaDriveEmitError(
            f"emitter covered {covered} of {len(image.data)} ROM bytes"
        )
    return EmitResult(
        source_units=tuple(source_units),
        assets=tuple(assets),
        instruction_bytes=counts[0],
        pointer_bytes=counts[1],
        asset_bytes=counts[2] + len(image.header_data),
        raw_bytes=counts[3],
    )
