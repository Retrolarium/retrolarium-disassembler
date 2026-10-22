"""ROM entry points proven by descriptor loaders copying code to executable RAM."""

from __future__ import annotations

import re

from retrolarium_disassembler.facts import InstructionFact
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disassembler.m68k.instructions import pc_displacement_target


_POST_LOAD = re.compile(r"\((A[0-7])\)\+\|(A[0-7])", re.I)
_POST_WORD = re.compile(r"\((A[0-7])\)\+\|(D[0-7])w", re.I)
_PC_TABLE = re.compile(r"\((0x[0-9a-f]+),PC,(D[0-7])w\*0x1\)\|(A[0-7])", re.I)


def _chain(facts: dict[int, InstructionFact], start: int, count: int) -> list[InstructionFact]:
    result = []
    for _ in range(count):
        fact = facts.get(start)
        if fact is None:
            return []
        result.append(fact)
        start += fact.length
    return result


def _copy_loader_register(facts: dict[int, InstructionFact], start: int) -> str | None:
    """Prove pointer/word descriptor fields and a header-sized longword copy."""
    code = _chain(facts, start, 10)
    if (
        not code
        or [f.mnemonic.upper() for f in code]
        != [
            "MOVEA.L",
            "MOVEQ",
            "MOVE.W",
            "MOVEA.L",
            "MOVE.W",
            "LSR.W",
            "SUBQ.W",
            "MOVE.L",
            "DBF",
            "RTS",
        ]
        or any(f.flow_type.upper() != "FALL_THROUGH" for f in code[:8])
    ):
        return None
    source = _POST_LOAD.fullmatch(code[0].operands)
    destination = _POST_WORD.fullmatch(code[2].operands)
    count = _POST_WORD.fullmatch(code[4].operands)
    address = re.fullmatch(r"(D[0-7])\|(A[0-7])", code[3].operands, re.I)
    if source is None or destination is None or count is None or address is None:
        return None
    record, source_register = (g.upper() for g in source.groups())
    destination_record, temporary = (g.upper() for g in destination.groups())
    count_source, counter = (g.upper() for g in count.groups())
    temporary_source, destination_register = (g.upper() for g in address.groups())
    if (
        record != destination_record
        or temporary != temporary_source
        or count_source != source_register
        or len({record, source_register, destination_register}) != 3
    ):
        return None
    expected = {
        1: rf"-0x1\|{temporary}",
        5: rf"#0x2\|{counter}w",
        6: rf"#?0x1\|{counter}w",
        7: rf"\({source_register}\)\+\|\({destination_register}\)\+",
        8: rf"{counter}w\|0x[0-9a-f]+",
    }
    if any(re.fullmatch(pattern, code[index].operands, re.I) is None for index, pattern in expected.items()):
        return None
    if (
        code[8].flows != (code[7].cpu_address,)
        or code[8].flow_type.upper() != "CONDITIONAL_JUMP"
        or code[9].flow_type.upper() != "TERMINATOR"
    ):
        return None
    return record


def _descriptor_drivers(facts: dict[int, InstructionFact]) -> dict[int, tuple[str, int]]:
    """Prove a signed selector, four-byte handler index and descriptor loop."""
    drivers = {}
    for first in facts.values():
        if first.mnemonic.upper() != "MOVE.W":
            continue
        selector = _POST_WORD.fullmatch(first.operands)
        code = _chain(facts, first.cpu_address, 6)
        if (
            selector is None
            or not code
            or [f.mnemonic.upper().split(".")[0] for f in code]
            != [
                "MOVE",
                "BMI",
                "LSL",
                "MOVEA",
                "JSR",
                "BRA",
            ]
        ):
            continue
        record, index = (g.upper() for g in selector.groups())
        table = _PC_TABLE.fullmatch(code[3].operands)
        if (
            table is None
            or table.group(2).upper() != index
            or code[2].mnemonic.upper() != "LSL.W"
            or code[2].operands.upper() != f"#0X2|{index}W"
            or code[3].mnemonic.upper() != "MOVEA.L"
            or code[4].operands.upper() != f"({table.group(3).upper()})"
            or code[4].flow_type.upper() != "COMPUTED_CALL"
            or code[1].flow_type.upper() != "CONDITIONAL_JUMP"
            or code[5].flows != (first.cpu_address,)
            or len(code[1].flows) != 1
        ):
            continue
        done = facts.get(code[1].flows[0])
        if done is not None and done.mnemonic.upper() == "RTS" and done.flow_type.upper() == "TERMINATOR":
            drivers[first.cpu_address] = (record, int(table.group(1), 0))
    return drivers


def _constant_pointer(fact: InstructionFact, register: str) -> int | None:
    if fact.operands.rsplit("|", 1)[-1].upper() != register:
        return None
    if fact.mnemonic.upper() == "LEA":
        pc = pc_displacement_target(fact)
        if pc is not None:
            return pc
        absolute = re.fullmatch(r"\((0x[0-9a-f]+)\)\.l\|A[0-7]", fact.operands, re.I)
        if absolute:
            return int(absolute.group(1), 0)
    if fact.mnemonic.upper() == "MOVEA.L":
        immediate = re.fullmatch(r"#(0x[0-9a-f]+)\|A[0-7]", fact.operands, re.I)
        if immediate:
            return int(immediate.group(1), 0)
    return None


def discover_descriptor_ram_code_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[DecoderSeed, ...]:
    """Follow proven loader descriptors only when RAM is an execution target.

    Descriptor source points at a byte-count word, followed by the copied code.
    A copy to an ordinary RAM data buffer is never a decoder root.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    drivers = _descriptor_drivers(by_address)
    if not drivers:
        return ()
    executable = {vector.address & 0xFFFFFF for vector in image.vector_table[1:]}
    executable.update(
        target & 0xFFFFFF for fact in facts.values() if fact.mnemonic.upper() in {"JMP", "JSR"} for target in fact.flows
    )
    executable = {address for address in executable if image.header.ram_start <= address <= image.header.ram_end}
    data = image.data
    interiors = {
        address for fact in facts.values() for address in range(fact.cpu_address + 1, fact.cpu_address + fact.length)
    }
    seeds = {}
    for call in facts.values():
        if call.flow_type.upper() not in {"UNCONDITIONAL_CALL", "CALL_TERMINATOR"}:
            continue
        for target in call.flows:
            driver = drivers.get(target)
            if driver is None:
                continue
            record_register, handler_table = driver
            previous = ends.get(call.cpu_address)
            for _ in range(3):
                if previous is None or previous.mnemonic.upper() != "NOP":
                    break
                previous = ends.get(previous.cpu_address)
            if previous is None or previous.flow_type.upper() != "FALL_THROUGH":
                continue
            descriptor = _constant_pointer(previous, record_register)
            if descriptor is None:
                continue
            cursor = descriptor - image.header.rom_start
            for _ in range(64):
                if cursor < 0x200 or cursor + 8 > len(data) or cursor & 1:
                    break
                selector = int.from_bytes(data[cursor : cursor + 2], "big", signed=True)
                table_offset = handler_table - image.header.rom_start + selector * 4
                if selector < 0 or not 0x200 <= table_offset <= len(data) - 4:
                    break
                loader = int.from_bytes(data[table_offset : table_offset + 4], "big")
                if _copy_loader_register(by_address, loader) != record_register:
                    break
                source = int.from_bytes(data[cursor + 2 : cursor + 6], "big")
                destination = 0xFF0000 | int.from_bytes(data[cursor + 6 : cursor + 8], "big")
                source_offset = source - image.header.rom_start
                if source & 1 or not 0x200 <= source_offset <= len(data) - 4:
                    break
                length = int.from_bytes(data[source_offset : source_offset + 2], "big")
                code = source + 2
                if (
                    destination in executable
                    and length >= 4
                    and length % 4 == 0
                    and source_offset + 2 + length <= len(data)
                    and code not in interiors
                ):
                    seeds[code] = DecoderSeed(
                        address=code,
                        kind="descriptor_ram_code_copy",
                        confidence="proven",
                        evidence=(
                            f"descriptor at 0x{image.header.rom_start + cursor:06X}, "
                            f"loader at 0x{loader:06X} copies {length} bytes "
                            f"to executable RAM 0x{destination:06X}"
                        ),
                        source_address=call.cpu_address,
                    )
                cursor += 8
    return tuple(seeds[address] for address in sorted(seeds))
