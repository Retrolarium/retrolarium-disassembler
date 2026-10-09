"""Stable evidence-derived technical symbols for SNES programs and tables."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from retrolarium_core.snes import SnesImage, snes_to_rom_offset
from retrolarium_kit.snes_analysis import AnalysisResult
from retrolarium_kit.snes_pointers import PointerCandidate


@dataclass(frozen=True)
class TechnicalSymbol:
    symbol_id: str
    name: str
    kind: str
    cpu_id: str
    address_space: str
    logical_address: int
    physical_offset: int
    aliases: tuple[str, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.symbol_id,
            "name": self.name,
            "kind": self.kind,
            "cpu_id": self.cpu_id,
            "address_space": self.address_space,
            "logical_address": self.logical_address,
            "physical_offset": self.physical_offset,
            "aliases": list(self.aliases),
            "evidence": list(self.evidence),
        }


def _vector_alias(mode: str, name: str, address: int) -> str:
    mode_name = mode.capitalize()
    vector_name = "".join(part.capitalize() for part in name.split("_"))
    return f"Vec_{mode_name}_{vector_name}_{address:06X}"


def generate_symbols(
    image: SnesImage,
    result: AnalysisResult,
    pointer_candidates: tuple[PointerCandidate, ...],
) -> tuple[TechnicalSymbol, ...]:
    claims: dict[int, dict[str, set[str]]] = {}
    aliases: dict[int, set[str]] = {}

    def claim(address: int, kind: str, evidence: str) -> None:
        claims.setdefault(address, {}).setdefault(kind, set()).add(evidence)

    reset = image.reset_vector.cpu_address
    if reset is not None:
        claim(reset, "entry", "emulation_reset_vector")
    for vector in image.vector_table:
        if vector.cpu_address is None or vector.rom_offset is None:
            continue
        alias = _vector_alias(vector.mode, vector.name, vector.cpu_address)
        aliases.setdefault(vector.cpu_address, set()).add(alias)
        claim(
            vector.cpu_address,
            "vector",
            f"{vector.mode}_{vector.name}_vector",
        )
    instruction_addresses = {
        instruction.logical_address for instruction in result.instructions
    }
    for instruction in result.instructions:
        for flow in instruction.flows:
            target = flow.target
            if target is None or target not in instruction_addresses:
                continue
            if flow.kind == "call":
                claim(
                    target,
                    "subroutine",
                    f"call_from_{instruction.logical_address:06X}",
                )
            elif flow.kind in {"branch", "jump"}:
                claim(
                    target,
                    "location",
                    f"{flow.kind}_from_{instruction.logical_address:06X}",
                )
    for candidate in pointer_candidates:
        if candidate.status != "accepted":
            continue
        if candidate.schema_id == "snes.vectors.u16le.bank00":
            continue
        claim(
            candidate.logical_start,
            "table",
            f"accepted_pointer_schema:{candidate.schema_id}",
        )
        for entry in candidate.entries:
            if entry.target in instruction_addresses:
                claim(
                    entry.target,
                    "location",
                    f"pointer_target:{candidate.schema_id}",
                )

    priorities = ("entry", "table", "subroutine", "location", "vector", "offset")
    prefixes = {
        "entry": "Entry",
        "table": "Tbl",
        "subroutine": "Sub",
        "location": "Loc",
        "vector": "Vec",
        "offset": "Off",
    }
    symbols: list[TechnicalSymbol] = []
    for address in sorted(claims):
        kind_claims = claims[address]
        kind = next(item for item in priorities if item in kind_claims)
        physical = snes_to_rom_offset(image, address)
        symbols.append(
            TechnicalSymbol(
                symbol_id=f"snes.w65c816.{kind}.{address:06x}",
                name=f"{prefixes[kind]}_SNES_{address:06X}",
                kind=kind,
                cpu_id="w65c816",
                address_space="cpu",
                logical_address=address,
                physical_offset=physical,
                aliases=tuple(sorted(aliases.get(address, set()))),
                evidence=tuple(
                    sorted(
                        evidence
                        for values in kind_claims.values()
                        for evidence in values
                    )
                ),
            )
        )
    identifiers = [symbol.symbol_id for symbol in symbols]
    names = [symbol.name for symbol in symbols]
    if len(identifiers) != len(set(identifiers)) or len(names) != len(set(names)):
        raise ValueError("generated SNES technical symbols are not unique")
    return tuple(symbols)


def write_symbol_report(
    path: Path,
    image: SnesImage,
    symbols: tuple[TechnicalSymbol, ...],
) -> None:
    document = {
        "schema": "retrolarium.symbols",
        "schema_version": 1,
        "platform": "snes",
        "input_sha256": image.rom_sha256,
        "symbols": [symbol.as_dict() for symbol in symbols],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
