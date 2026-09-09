"""Neutral instruction facts imported from external analysis backends."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .ines import InesImage, InesError, cpu_to_prg_offset


class FactError(ValueError):
    """Instruction facts conflict with the immutable input image."""


@dataclass(frozen=True)
class InstructionFact:
    physical_offset: int
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


def load_ghidra_facts(path: Path, image: InesImage) -> dict[int, InstructionFact]:
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
            cpu_address = int(row["address"], 16)
            try:
                offset = cpu_to_prg_offset(image, cpu_address)
            except InesError as exc:
                raise FactError(str(exc)) from exc
            raw = bytes.fromhex(row["bytes"])
            length = int(row["length"])
            if len(raw) != length:
                raise FactError(f"instruction ${cpu_address:04X} has invalid length")
            if image.prg[offset:offset + length] != raw:
                raise FactError(
                    f"backend bytes disagree with PRG at CPU ${cpu_address:04X}"
                )
            byte_range = set(range(offset, offset + length))
            if occupied & byte_range:
                raise FactError(f"overlapping instruction at CPU ${cpu_address:04X}")
            occupied.update(byte_range)
            if offset in facts:
                raise FactError(f"duplicate physical instruction at offset {offset:#x}")
            facts[offset] = InstructionFact(
                physical_offset=offset,
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
