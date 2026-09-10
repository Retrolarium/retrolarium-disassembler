"""Neutral instruction facts imported from external analysis backends."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .ines import InesImage, InesError, cpu_to_prg_offset
from .megadrive import MegaDriveError, MegaDriveImage, m68k_to_rom_offset


class FactError(ValueError):
    """Instruction facts conflict with the immutable input image."""


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


def parse_address(value: str) -> int:
    tail = value.rsplit("::", 1)[-1]
    return int(tail, 16)


def load_ghidra_facts(
    path: Path, image: InesImage, *, bank: int = 0
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
    )


def load_megadrive_ghidra_facts(
    path: Path, image: MegaDriveImage
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
    )


def _load_ghidra_facts(
    path: Path,
    payload: bytes,
    address_to_offset: Callable[[int], int],
    *,
    bank: int,
    address_label: str,
    expected_block: str | None = None,
) -> dict[int, InstructionFact]:
    facts: dict[int, InstructionFact] = {}
    occupied: set[int] = set()
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        required = {
            "block", "space", "address", "length", "bytes", "mnemonic",
            "operands", "flows", "flow_type", "symbol", "function",
        }
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise FactError("unsupported Ghidra instruction-fact columns")
        for row in reader:
            if expected_block is not None and row["block"] != expected_block:
                raise FactError(
                    f"unexpected Ghidra block {row['block']!r}; "
                    f"expected {expected_block!r}"
                )
            cpu_address = int(row["address"], 16)
            offset = address_to_offset(cpu_address)
            raw = bytes.fromhex(row["bytes"])
            length = int(row["length"])
            if len(raw) != length:
                raise FactError(
                    f"instruction {address_label} ${cpu_address:04X} has invalid length"
                )
            if payload[offset:offset + length] != raw:
                raise FactError(
                    f"backend bytes disagree with input at "
                    f"{address_label} ${cpu_address:04X}"
                )
            byte_range = set(range(offset, offset + length))
            if occupied & byte_range:
                raise FactError(
                    f"overlapping instruction at {address_label} ${cpu_address:04X}"
                )
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
            )
    if not facts:
        raise FactError("backend exported no instructions")
    return facts
