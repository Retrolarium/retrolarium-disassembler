"""Neutral instruction facts imported from external analysis backends."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable

from retrolarium_core.ines import InesImage, InesError, cpu_to_prg_offset
from retrolarium_core.megadrive import MegaDriveError, MegaDriveImage, m68k_to_rom_offset
from retrolarium_core.snes import SnesError, SnesImage, snes_to_rom_offset


class FactError(ValueError):
    """Instruction facts conflict with the immutable input image."""


@dataclass(frozen=True)
class InstructionReference:
    address: int
    reference_type: str
    operand_index: int


@dataclass(frozen=True)
class InstructionFact:
    physical_offset: int
    bank: int
    cpu_address: int
    length: int
    raw: bytes
    mnemonic: str
    operands: str
    flows: tuple[int, ...]
    flow_type: str
    backend_space: str
    backend_block: str
    backend_symbol: str
    backend_function: str
    references: tuple[InstructionReference, ...]


def parse_address(value: str) -> int:
    match = re.search(r"(?:0x)?([0-9a-f]+)$", value.strip(), re.I)
    if match is None:
        raise FactError(f"invalid Ghidra address: {value}")
    return int(match.group(1), 16)


def parse_references(value: str) -> tuple[InstructionReference, ...]:
    references = []
    for item in value.split("|"):
        if not item:
            continue
        try:
            address, reference_type, operand_index = item.rsplit("~", 2)
        except ValueError as exc:
            raise FactError(f"invalid Ghidra reference: {item}") from exc
        references.append(
            InstructionReference(
                address=parse_address(address),
                reference_type=reference_type,
                operand_index=int(operand_index),
            )
        )
    return tuple(references)


def load_ghidra_facts(
    path: Path, image: InesImage, *, bank: int = 0, allow_empty: bool = False
) -> dict[int, InstructionFact]:
    def project(address: int) -> int:
        try:
            return cpu_to_prg_offset(image, address, bank=bank)
        except InesError as exc:
            raise FactError(str(exc)) from exc

    return _load_ghidra_facts(
        path,
        image.prg,
        project,
        bank=bank,
        address_label="CPU",
        allow_empty=allow_empty,
    )


def load_megadrive_ghidra_facts(
    path: Path, image: MegaDriveImage, *, speculative: bool = False
) -> dict[int, InstructionFact]:
    def project(address: int) -> int:
        try:
            return m68k_to_rom_offset(image, address)
        except MegaDriveError as exc:
            raise FactError(str(exc)) from exc

    return _load_ghidra_facts(
        path,
        image.data,
        project,
        bank=0,
        address_label="M68K",
        expected_block="ROM",
        allow_empty=speculative,
        allow_overlaps=speculative,
    )


def load_z80_ghidra_facts(path: Path, payload: bytes, *, base_address: int = 0) -> dict[int, InstructionFact]:
    def project(address: int) -> int:
        offset = address - base_address
        if not 0 <= offset < len(payload):
            raise FactError(f"Z80 address ${address:04X} is outside the extracted payload")
        return offset

    return _load_ghidra_facts(
        path,
        payload,
        project,
        bank=0,
        address_label="Z80",
        expected_block="Z80_RAM",
        # A copy away from address zero has no implicit reset entry. It can
        # contain only data; keep the verified payload without inventing code.
        allow_empty=base_address != 0,
    )


def load_spc700_ghidra_facts(path: Path, payload: bytes, *, base_address: int = 0) -> dict[int, InstructionFact]:
    def project(address: int) -> int:
        offset = address - base_address
        if not 0 <= offset < len(payload):
            raise FactError(f"SPC700 address ${address:04X} is outside the extracted payload")
        return offset

    return _load_ghidra_facts(
        path,
        payload,
        project,
        bank=0,
        address_label="SPC700",
        expected_block="SPC700_RAM",
    )


def load_snes_ghidra_facts(path: Path, image: SnesImage, *, physical_bank: int) -> dict[int, InstructionFact]:
    bank_size = 0x8000 if image.header.map_mode == "lorom" else 0x10000
    bank_start = physical_bank * bank_size
    bank_end = min(bank_start + bank_size, len(image.data))
    if bank_start >= len(image.data):
        raise FactError(f"SNES physical bank {physical_bank} is outside the ROM")

    def project(address: int) -> int:
        try:
            offset = snes_to_rom_offset(image, address)
        except SnesError as exc:
            raise FactError(str(exc)) from exc
        if not bank_start <= offset < bank_end:
            raise FactError(f"SNES address ${address:06X} projects outside physical bank {physical_bank}")
        return offset

    return _load_ghidra_facts(
        path,
        image.data,
        project,
        bank=physical_bank,
        address_label="SNES",
        expected_block="SNES_ROM",
    )


def _load_ghidra_facts(
    path: Path,
    payload: bytes,
    address_to_offset: Callable[[int], int],
    *,
    bank: int,
    address_label: str,
    expected_block: str | None = None,
    allow_empty: bool = False,
    allow_overlaps: bool = False,
) -> dict[int, InstructionFact]:
    facts: dict[int, InstructionFact] = {}
    occupied: set[int] = set()
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        required = {
            "block",
            "space",
            "address",
            "length",
            "bytes",
            "mnemonic",
            "operands",
            "flows",
            "flow_type",
            "symbol",
            "function",
        }
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise FactError("unsupported Ghidra instruction-fact columns")
        for row in reader:
            if expected_block is not None and row["block"] != expected_block:
                raise FactError(f"unexpected Ghidra block {row['block']!r}; expected {expected_block!r}")
            cpu_address = int(row["address"], 16)
            offset = address_to_offset(cpu_address)
            raw = bytes.fromhex(row["bytes"])
            length = int(row["length"])
            if length <= 0 or len(raw) != length:
                raise FactError(f"instruction {address_label} ${cpu_address:04X} has invalid length")
            if payload[offset : offset + length] != raw:
                raise FactError(f"backend bytes disagree with input at {address_label} ${cpu_address:04X}")
            byte_range = set(range(offset, offset + length))
            # Alternate pseudo decodes may start inside another probe's
            # operands. They remain hypotheses; primary listing facts are
            # always required to be disjoint.
            if not allow_overlaps and occupied & byte_range:
                raise FactError(f"overlapping instruction at {address_label} ${cpu_address:04X}")
            occupied.update(byte_range)
            if offset in facts:
                raise FactError(f"duplicate physical instruction at offset {offset:#x}")
            facts[offset] = InstructionFact(
                physical_offset=offset,
                bank=bank,
                cpu_address=cpu_address,
                length=length,
                raw=raw,
                mnemonic=row["mnemonic"].upper(),
                operands=row["operands"],
                flows=tuple(parse_address(item) for item in row["flows"].split("|") if item),
                flow_type=row["flow_type"],
                backend_space=row["space"],
                backend_block=row["block"],
                backend_symbol=row["symbol"],
                backend_function=row["function"],
                references=parse_references(row.get("references", "") or ""),
            )
    if not facts and not allow_empty:
        raise FactError("backend exported no instructions")
    return facts
