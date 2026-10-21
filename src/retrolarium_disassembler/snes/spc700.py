"""Conservative recovery of statically proven W65C816-to-SPC700 uploads."""

from __future__ import annotations

from retrolarium_disassembler import AnalysisError

from dataclasses import dataclass
import hashlib

from retrolarium_core.snes import SnesError, SnesImage, snes_to_rom_offset
from retrolarium_disassembler.snes.analysis import AnalysisResult, Instruction


APU_IO0 = 0x2140
APU_IO1 = 0x2141
APU_IO2 = 0x2142


@dataclass(frozen=True)
class CrossCpuCopy:
    edge_id: str
    schema_id: str
    source_cpu_id: str
    source_space: str
    source_start: int
    source_end: int
    source_physical_start: int
    source_physical_end: int
    target_cpu_id: str
    target_space: str
    target_start: int
    target_end: int
    size: int
    payload_sha256: str
    evidence_addresses: tuple[int, ...]
    confidence: str


_PATTERN = (
    ("PHK", "imp"),
    ("PLB", "imp"),
    ("REP", "imm8"),
    ("LDA", "immM"),
    ("STA", "abs"),
    ("LDX", "immX"),
    ("SEP", "imm8"),
    ("LDA", "absx"),
    ("STA", "abs"),
    ("TXA", "imp"),
    ("STA", "abs"),
    ("REP", "imm8"),
    ("INX", "imp"),
    ("CPX", "immX"),
    ("BNE", "rel8"),
    ("SEP", "imm8"),
    ("RTS", "imp"),
)


def _u16(instruction: Instruction) -> int:
    return int.from_bytes(instruction.raw[1:], "little")


def _chain(
    instructions: dict[int, Instruction], start: Instruction
) -> tuple[Instruction, ...] | None:
    chain: list[Instruction] = []
    current = start
    for expected in _PATTERN:
        if (current.mnemonic, current.addressing_mode) != expected:
            return None
        chain.append(current)
        next_address = (
            (current.logical_address & 0xFF0000)
            | ((current.logical_address + current.length) & 0xFFFF)
        )
        if len(chain) != len(_PATTERN):
            following = instructions.get(next_address)
            if following is None:
                return None
            current = following
    return tuple(chain)


def _apu_bank(bank: int | None) -> bool:
    return bank is not None and (bank <= 0x3F or 0x80 <= bank <= 0xBF)


def detect_spc700_copies(
    image: SnesImage, analysis: AnalysisResult
) -> tuple[CrossCpuCopy, ...]:
    """Recognize only a fixed-count indexed upload with explicit APU evidence."""
    instructions = {
        instruction.logical_address: instruction
        for instruction in analysis.instructions
    }
    occupied = {
        offset
        for instruction in analysis.instructions
        for offset in range(
            instruction.physical_offset,
            instruction.physical_offset + instruction.length,
        )
    }
    copies: list[CrossCpuCopy] = []
    seen: set[tuple[int, int, int]] = set()
    for instruction in analysis.instructions:
        if instruction.mnemonic != "PHK":
            continue
        chain = _chain(instructions, instruction)
        if chain is None:
            continue
        (
            _phk, plb, wide, destination_load, destination_store,
            index_load, loop_start, source_load, data_store, txa,
            counter_store, accumulator_wide, increment, count_compare,
            branch, accumulator_narrow, _return,
        ) = chain
        if not (
            wide.raw[1] & 0x30 == 0x30
            and destination_load.state_before.m == 0
            and _u16(destination_store) == APU_IO2
            and destination_store.state_before.m == 0
            and index_load.state_before.x == 0
            and _u16(index_load) == 0
            and loop_start.raw[1] & 0x20
            and source_load.state_before.m == 1
            and source_load.state_before.x == 0
            and _u16(data_store) == APU_IO1
            and _u16(counter_store) == APU_IO0
            and accumulator_wide.raw[1] & 0x20
            and count_compare.state_before.x == 0
            and accumulator_narrow.raw[1] & 0x20
            and _apu_bank(source_load.state_before.dbr)
        ):
            continue
        branch_targets = {
            flow.target for flow in branch.flows if flow.kind == "branch"
        }
        if loop_start.logical_address not in branch_targets:
            continue

        target_start = _u16(destination_load)
        size = _u16(count_compare)
        if not 1 <= size <= 0x10000 - target_start:
            continue
        data_bank = source_load.state_before.dbr
        assert data_bank is not None
        source_start = (data_bank << 16) | _u16(source_load)
        physical_offsets: list[int] = []
        try:
            for delta in range(size):
                physical_offsets.append(snes_to_rom_offset(image, source_start + delta))
        except SnesError:
            continue
        source_physical_start = physical_offsets[0]
        if physical_offsets != list(
            range(source_physical_start, source_physical_start + size)
        ):
            continue
        if occupied.intersection(physical_offsets):
            continue
        payload = image.data[source_physical_start:source_physical_start + size]
        if len(payload) != size:
            continue
        key = (source_physical_start, target_start, size)
        if key in seen:
            continue
        seen.add(key)
        copies.append(
            CrossCpuCopy(
                edge_id=(
                    f"snes.cross.w65c816-spc700."
                    f"{source_start:06X}.{target_start:04X}"
                ),
                schema_id="snes.w65c816-spc700.fixed-indexed-apu-upload",
                source_cpu_id="w65c816",
                source_space="snes-rom",
                source_start=source_start,
                source_end=source_start + size - 1,
                source_physical_start=source_physical_start,
                source_physical_end=source_physical_start + size - 1,
                target_cpu_id="spc700",
                target_space="spc700-ram",
                target_start=target_start,
                target_end=target_start + size - 1,
                size=size,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                evidence_addresses=tuple(item.logical_address for item in chain),
                confidence="proven-static-copy",
            )
        )
    return tuple(copies)


def payload_for_copy(image: SnesImage, copy: CrossCpuCopy) -> bytes:
    payload = image.data[
        copy.source_physical_start:copy.source_physical_end + 1
    ]
    if len(payload) != copy.size or hashlib.sha256(payload).hexdigest() != copy.payload_sha256:
        raise AnalysisError("SPC700 copy evidence no longer matches immutable ROM bytes")
    return payload
