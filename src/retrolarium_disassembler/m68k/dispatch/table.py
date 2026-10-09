"""LEA-based indexed calls and exception-vector relative-table dispatch."""
from __future__ import annotations

import re

from retrolarium_disasm.facts import InstructionFact
from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disasm.m68k.instructions import absolute_referenced_addresses, instruction_sets
from retrolarium_disasm.m68k.instructions import pc_displacement_target
from retrolarium_disasm.m68k.abstract import _register_list


def _lea_base(fact, register):
    if fact.mnemonic.upper() != "LEA" or fact.operands.rsplit("|", 1)[-1].upper() != register:
        return None
    pc = pc_displacement_target(fact)
    if pc is not None:
        return pc
    absolute = re.fullmatch(r"\((0x[0-9a-f]+)\)\.l\|" + register, fact.operands, re.I)
    return int(absolute[1], 0) if absolute else None


def _targets(image, facts, table, width):
    occupied, interiors, starts = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    origin, data = image.header.rom_start, image.data
    start = table - origin
    limit = min(len(data), start + width * 1024)
    result = []
    slot = start
    while slot + width <= limit:
        if (slot < 0x200 or slot & 1 or any(slot + b in occupied for b in range(width))
                or slot != start and origin + slot in boundaries):
            break
        target = int.from_bytes(data[slot:slot + width], "big", signed=width == 2)
        if width == 2:
            target += table
        physical = target - origin
        if (target & 1 or not 0x200 <= physical <= len(data) - 2
                or physical in interiors or start <= physical < slot + width
                or data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
            break
        result.append(target)
        if physical >= start:
            limit = min(limit, physical)
        slot += width
    return result if len(result) >= 2 and set(result) & starts else []


def discover_lea_indexed_call_seeds(image: MegaDriveImage, facts: dict[int, InstructionFact]):
    by_address = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    result = []
    for load in facts.values():
        match = re.fullmatch(r"\((-?0x[0-9a-f]+),(A[0-6]),D[0-7][wl]?\*0x1\)\|(A[0-6])", load.operands, re.I)
        if load.mnemonic.upper() != "MOVEA.L" or match is None:
            continue
        displacement, base, destination = match.groups()
        base, destination = base.upper(), destination.upper()
        lea = ends.get(load.cpu_address)
        for _ in range(6):
            if lea is None or lea.flow_type.upper() != "FALL_THROUGH":
                lea = None
                break
            if _lea_base(lea, base) is not None:
                break
            operands = lea.operands.upper().split("|")
            destination_operand = operands[-1]
            if (re.fullmatch(base + r"[BWL]?", destination_operand)
                    and not lea.mnemonic.upper().startswith(("CMP", "TST", "BTST"))
                    or lea.mnemonic.upper().startswith("MOVEM") and operands[0] == "(SP)+"
                    and base.lower() in _register_list(destination_operand)):
                lea = None
                break
            lea = ends.get(lea.cpu_address)
        call = by_address.get(load.cpu_address + load.length)
        if (lea is None or call is None or call.mnemonic.upper() not in {"JSR", "JMP"}
                or call.operands.upper() != f"({destination})"):
            continue
        table = _lea_base(lea, base)
        if table is None:
            continue
        table += int(displacement, 0)
        result.extend(DecoderSeed(target, "lea_indexed_call", "high",
                      f"LEA table {table:06X}; indexed MOVEA.L and call at {call.cpu_address:06X}",
                      load.cpu_address) for target in _targets(image, facts, table, 4))
    return tuple(result)


def discover_trap_relative_dispatch_seeds(image: MegaDriveImage, facts: dict[int, InstructionFact]):
    by_address = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    handlers = {}
    for number in range(max(0, min(16, len(image.vector_table) - 32))):
        entry = image.vector_table[32 + number].address
        first = by_address.get(entry)
        if first is None or first.mnemonic.upper() != "ADD.W":
            continue
        index = re.fullmatch(r"(D[0-7])w\|\1w", first.operands, re.I)
        second = by_address.get(entry + first.length)
        if index is None or second is None or second.mnemonic.upper() != "ADDA.W":
            continue
        match = re.fullmatch(r"\(0x0,(A[0-6])," + index[1] + r"w\*0x1\)\|\1", second.operands, re.I)
        third = by_address.get(second.cpu_address + second.length)
        fourth = by_address.get(third.cpu_address + third.length) if third else None
        if (match is None or third is None or third.mnemonic.upper() != "JSR"
                or third.operands.upper() != f"({match[1].upper()})"
                or fourth is None or fourth.raw != b"\x4e\x73"):
            continue
        handlers[number] = (entry, match[1].upper())
    result = []
    for call in facts.values():
        if call.mnemonic.upper() != "TRAP" or len(call.raw) != 2:
            continue
        opcode = int.from_bytes(call.raw, "big")
        if opcode & 0xFFF0 != 0x4E40 or opcode & 15 not in handlers:
            continue
        handler, register = handlers[opcode & 15]
        preceding = ends.get(call.cpu_address)
        for _ in range(6):
            if preceding is None or preceding.flow_type.upper() != "FALL_THROUGH":
                break
            table = _lea_base(preceding, register)
            if table is not None:
                result.extend(DecoderSeed(target, "trap_relative_dispatch", "high",
                    f"TRAP at {call.cpu_address:06X}; vector handler {handler:06X} doubles index "
                    f"and adds signed table word to LEA base {table:06X}", call.cpu_address)
                    for target in _targets(image, facts, table, 2))
                break
            destination = preceding.operands.rsplit("|", 1)[-1].upper()
            if (destination == register or register in preceding.operands.upper()
                    and ("+" in preceding.operands or "-(" in preceding.operands)):
                break
            preceding = ends.get(preceding.cpu_address)
    return tuple(result)
