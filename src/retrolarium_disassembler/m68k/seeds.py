"""Conservative Python discovery of Motorola 68000 decoder entry points."""

from __future__ import annotations

from dataclasses import dataclass

from retrolarium_core.megadrive import MegaDriveImage


@dataclass(frozen=True)
class DecoderSeed:
    """An address Ghidra may decode, together with auditable Python evidence."""

    address: int
    kind: str
    confidence: str
    evidence: str
    source_address: int | None = None


@dataclass(frozen=True)
class RamTrampolineTable:
    """A counted ROM address table proven by its RAM JMP-stub builder."""

    table_address: int
    loader_address: int
    targets: tuple[int, ...]


@dataclass(frozen=True)
class RamCopyRegion:
    """A ROM range copied verbatim to 68000 work RAM before execution."""

    source_start: int
    source_end: int
    destination_start: int
    destination_end: int
    loader_address: int


def _word(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def _long(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def _signed_word(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _valid_code_address(data: bytes, address: int) -> bool:
    return 0x200 <= address < len(data) and address & 1 == 0


def discover_vector_seeds(image: MegaDriveImage) -> tuple[DecoderSeed, ...]:
    """Use valid cartridge exception vectors as proven decoder roots."""
    return tuple(
        DecoderSeed(
            address=vector.address,
            kind="vector",
            confidence="proven",
            evidence=f"cartridge vector {vector.index} ({vector.name})",
            source_address=vector.index * 4,
        )
        for vector in image.vector_table[1:]
        if _valid_code_address(image.data, vector.address)
    )


def discover_ram_copy_regions(image: MegaDriveImage, *, scan_start: int = 0x200) -> tuple[RamCopyRegion, ...]:
    """Find ranges proven by a complete MOVE/DBF/JMP ROM-to-RAM idiom."""
    data = image.data
    regions = []
    for offset in range(scan_start, len(data) - 27, 2):
        if (
            _word(data, offset) != 0x41F9
            or _word(data, offset + 6) != 0x43F9
            or _word(data, offset + 12) != 0x303C
            or _word(data, offset + 16) != 0x22D8
            or _word(data, offset + 18) != 0x51C8
            or _word(data, offset + 20) != 0xFFFC
            or _word(data, offset + 22) != 0x4EF9
        ):
            continue
        source = _long(data, offset + 2)
        destination = _long(data, offset + 8)
        jump = _long(data, offset + 24)
        length = (_word(data, offset + 14) + 1) * 4
        if (
            destination != jump
            or not _valid_code_address(data, source)
            or source + length > len(data)
            or destination & 0xFF0000 != 0xFF0000
        ):
            continue
        regions.append(RamCopyRegion(
            source_start=source,
            source_end=source + length,
            destination_start=destination,
            destination_end=destination + length,
            loader_address=offset,
        ))
    return tuple(regions)


def discover_ram_copy_seeds(image: MegaDriveImage) -> tuple[DecoderSeed, ...]:
    """Use each proven ROM-to-RAM copy origin as a decoder root."""
    return tuple(
        DecoderSeed(
            address=region.source_start,
            kind="ram_copy_origin",
            confidence="proven",
            evidence=(
                f"ROM code copied to RAM 0x{region.destination_start:06X} "
                "by MOVE/DBF/JMP loop "
                f"({region.source_end - region.source_start} bytes)"
            ),
            source_address=region.loader_address,
        )
        for region in discover_ram_copy_regions(image)
    )


def _branch_table(
    data: bytes, table: int, *, maximum_size: int | None = None
) -> tuple[tuple[int, int], ...]:
    entries = []
    cursor = table
    while cursor + 4 <= len(data):
        if maximum_size is not None and cursor - table >= maximum_size:
            break
        if _word(data, cursor) != 0x6000:
            break
        target = cursor + 2 + _signed_word(_word(data, cursor + 2))
        if not _valid_code_address(data, target):
            break
        entries.append((cursor, target))
        cursor += 4
    return tuple(entries)


def _short_branch_table(
    data: bytes, table: int, *, maximum_size: int | None = None
) -> tuple[tuple[int, int], ...]:
    entries = []
    cursor = table
    while cursor + 2 <= len(data):
        if maximum_size is not None and cursor - table >= maximum_size:
            break
        opcode = _word(data, cursor)
        displacement = opcode & 0xFF
        if opcode & 0xFF00 != 0x6000 or displacement == 0:
            break
        if displacement & 0x80:
            displacement -= 0x100
        target = cursor + 2 + displacement
        if not _valid_code_address(data, target):
            break
        entries.append((cursor, target))
        cursor += 2
    return tuple(entries)


def _indexed_dispatch_table(
    data: bytes, table: int
) -> tuple[tuple[int, int], ...]:
    """Read the BRA.S or BRA.W run selected by a PC-indexed jump."""
    opcode = _word(data, table)
    if opcode == 0x6000:
        return _branch_table(data, table, maximum_size=0x400)
    if opcode & 0xFF00 == 0x6000:
        return _short_branch_table(data, table, maximum_size=0x400)
    return ()


def _branch_table_seeds(
    table: int,
    entries: tuple[tuple[int, int], ...],
    *,
    kind: str,
    evidence: str,
    source_address: int | None,
) -> tuple[DecoderSeed, ...]:
    seeds = []
    detail = f"{evidence} at 0x{table:06X} ({len(entries)} entries)"
    for entry, target in entries:
        seeds.append(DecoderSeed(
            address=entry,
            kind=f"{kind}_entry",
            confidence="high",
            evidence=detail,
            source_address=source_address,
        ))
        seeds.append(DecoderSeed(
            address=target,
            kind=f"{kind}_target",
            confidence="high",
            evidence=detail,
            source_address=entry,
        ))
    return tuple(seeds)


def discover_indexed_branch_table_seeds(
    image: MegaDriveImage,
    *, scan_start: int = 0x200,
) -> tuple[DecoderSeed, ...]:
    """Find BRA.W tables addressed by JSR/JMP d8(PC,Dn.W)."""
    data = image.data
    seeds = []
    seen_tables: set[int] = set()
    for offset in range(scan_start, len(data) - 3, 2):
        if _word(data, offset) not in {0x4EBB, 0x4EFB}:
            continue
        extension = _word(data, offset + 2)
        # Brief extension, Dn.W index, scale 1: the plain 68000 form.
        if extension & 0x8F00:
            continue
        displacement = extension & 0xFF
        if displacement & 0x80:
            displacement -= 0x100
        table = offset + 2 + displacement
        if (
            table in seen_tables
            or table < 0x200
            or table & 1
            or table + 8 > len(data)
        ):
            continue
        seen_tables.add(table)
        entries = _indexed_dispatch_table(data, table)
        if len(entries) < 2:
            continue
        seeds.extend(_branch_table_seeds(
            table,
            entries,
            kind="indexed_branch_table",
            evidence=(
                f"BRA dispatch selected by PC-indexed "
                f"{'JSR' if _word(data, offset) == 0x4EBB else 'JMP'} "
                f"at 0x{offset:06X}"
            ),
            source_address=offset,
        ))
    return tuple(seeds)


def discover_dense_branch_table_seeds(
    image: MegaDriveImage,
    *, scan_start: int = 0x200,
) -> tuple[DecoderSeed, ...]:
    """Find otherwise unreferenced runs of at least four valid BRA.W stubs."""
    data = image.data
    seeds = []
    offset = scan_start
    while offset + 16 <= len(data):
        entries = _branch_table(data, offset)
        if len(entries) < 4:
            offset += 2
            continue
        seeds.extend(_branch_table_seeds(
            offset,
            entries,
            kind="dense_branch_table",
            evidence="dense run of valid BRA.W dispatch stubs",
            source_address=None,
        ))
        offset += len(entries) * 4
    return tuple(seeds)


def discover_ram_trampoline_tables(
    image: MegaDriveImage,
    *,
    scan_start: int = 0x200,
) -> tuple[RamTrampolineTable, ...]:
    """Find counted ROM tables used to construct JMP abs.l stubs in RAM."""
    data = image.data
    tables = []
    for offset in range(scan_start, len(data) - 23, 2):
        if (
            _word(data, offset) != 0x41FA
            or _word(data, offset + 4) != 0x43F8
            or _word(data, offset + 8) != 0x3018
            or _word(data, offset + 10) != 0x32FC
            or _word(data, offset + 12) != 0x4EF9
            or _word(data, offset + 14) != 0x7200
            or _word(data, offset + 16) != 0x3218
            or _word(data, offset + 18) != 0x22C1
            or _word(data, offset + 20) != 0x51C8
            or _word(data, offset + 22) != 0xFFF4
        ):
            continue
        table = offset + 2 + _signed_word(_word(data, offset + 2))
        if table < 0x200 or table & 1 or table + 4 > len(data):
            continue
        count = _word(data, table) + 1
        if not 4 <= count <= 1024 or table + 2 + count * 2 > len(data):
            continue
        targets = tuple(
            _word(data, table + 2 + index * 2)
            for index in range(count)
        )
        if not all(_valid_code_address(data, target) for target in targets):
            continue
        tables.append(RamTrampolineTable(
            table_address=table,
            loader_address=offset,
            targets=targets,
        ))
    return tuple(tables)


def discover_ram_trampoline_seeds(
    image: MegaDriveImage,
) -> tuple[DecoderSeed, ...]:
    """Find ROM targets used to construct counted JMP abs.l stubs in RAM."""
    seeds = []
    for table in discover_ram_trampoline_tables(image):
        evidence = (
            f"counted ROM table at 0x{table.table_address:06X} builds "
            f"{len(table.targets)} JMP abs.l trampolines in RAM"
        )
        seeds.extend(
            DecoderSeed(
                address=target,
                kind="ram_trampoline_target",
                confidence="proven",
                evidence=evidence,
                source_address=table.loader_address,
            )
            for target in table.targets
        )
    return tuple(seeds)


def discover_initial_decoder_seeds(
    image: MegaDriveImage,
) -> tuple[DecoderSeed, ...]:
    """Build the complete first-pass decoder plan without Ghidra heuristics."""
    return (
        *discover_vector_seeds(image),
        *discover_ram_copy_seeds(image),
        *discover_indexed_branch_table_seeds(image),
        *discover_dense_branch_table_seeds(image),
        *discover_ram_trampoline_seeds(image),
    )
