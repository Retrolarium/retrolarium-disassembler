"""Indexed ROM function tables dispatched by a writable JMP abs.l stub."""
from __future__ import annotations

import re
from dataclasses import dataclass

from retrolarium_kit.facts import InstructionFact
from retrolarium_kit.m68k_seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_kit.megadrive_pointers import _absolute_referenced_addresses, _instruction_sets
from retrolarium_kit.megadrive_symbols import pc_displacement_target


@dataclass(frozen=True)
class InlineTrapCall:
    call_address: int
    data_address: int
    continuation: int
    target: int | None
    handler: int
    data_size: int = 2


def discover_inline_trap_calls(image, facts) -> tuple[InlineTrapCall, ...]:
    """Prove a TRAP ABI consuming a selector word from the exception PC.

    Handler removes the saved SR, loads the PC at SP, reads (PC)+ as a
    word index and saves the advanced PC back at SP, before RAM-JMP dispatch.
    Ordinary TRAPs have no inline-data assumption.
    """
    by_address = {f.cpu_address: f for f in facts.values()}
    stub_sites = {seed.source_address for seed in discover_ram_stub_dispatch_seeds(image, facts)}
    handlers = {}
    for number in range(max(0, min(16, len(image.vector_table) - 32))):
        vector = image.vector_table[32 + number].address
        code = []
        cursor = vector
        for _ in range(16):
            item = by_address.get(cursor)
            if item is None or item.flow_type.upper() != "FALL_THROUGH":
                break
            code.append(item)
            cursor += item.length
        for index in range(len(code) - 5):
            adjust, pc, selector, save, lea, load = code[index:index + 6]
            register = re.fullmatch(r"\(SP\)\|(A[0-6])", pc.operands, re.I)
            if (adjust.mnemonic.upper() != "ADDA.L" or adjust.operands.upper() != "#0X2|SP"
                    or pc.mnemonic.upper() != "MOVEA.L" or register is None):
                continue
            ar = register[1].upper()
            word = re.fullmatch(r"\(" + ar + r"\)\+\|(D[0-7])w", selector.operands, re.I)
            if (selector.mnemonic.upper() != "MOVE.W" or word is None
                    or save.mnemonic.upper() != "MOVE.L" or save.operands.upper() != f"{ar}|(SP)"
                    or lea.mnemonic.upper() != "LEA" or load.cpu_address not in stub_sites
                    or load.operands.upper() != f"(0X0,{ar},{word[1].upper()}W*0X1)|{ar}"):
                continue
            table = pc_displacement_target(lea)
            if table is not None:
                handlers[number] = (vector, table)
    result = []
    for call in facts.values():
        if call.mnemonic.upper() != "TRAP" or len(call.raw) != 2:
            continue
        opcode = int.from_bytes(call.raw, "big")
        if opcode & 0xFFF0 != 0x4E40 or opcode & 15 not in handlers:
            continue
        handler, table = handlers[opcode & 15]
        argument = call.physical_offset + 2
        if argument + 2 > len(image.data):
            continue
        index = int.from_bytes(image.data[argument:argument + 2], "big")
        slot = table - image.header.rom_start + index
        if index % 4 or not 0x200 <= slot <= len(image.data) - 4:
            continue
        target = int.from_bytes(image.data[slot:slot + 4], "big")
        physical = target - image.header.rom_start
        if target & 1 or not 0x200 <= physical <= len(image.data) - 2:
            continue
        result.append(InlineTrapCall(call.cpu_address, call.cpu_address + 2,
                                     call.cpu_address + 4, target, handler))
    from retrolarium_kit.m68k_trap_frame import discover_frame_inline_trap_calls
    result.extend(discover_frame_inline_trap_calls(image, facts))
    from retrolarium_kit.m68k_variable_traps import discover_variable_inline_trap_calls
    result.extend(discover_variable_inline_trap_calls(image, facts))
    return tuple({call.call_address: call for call in result}.values())


def discover_ram_stub_dispatch_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
) -> tuple[DecoderSeed, ...]:
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    occupied, interiors, starts = _instruction_sets(facts)
    boundaries = _absolute_referenced_addresses(facts)
    result = {}
    for load in facts.values():
        match = re.fullmatch(r"\(0x0,(A[0-6]),D[0-7]w\*0x1\)\|(A[0-6])", load.operands, re.I)
        if load.mnemonic.upper() != "MOVEA.L" or match is None:
            continue
        base, register = (g.upper() for g in match.groups())
        lea = ends.get(load.cpu_address)
        if lea is None or lea.mnemonic.upper() != "LEA" or lea.operands.rsplit("|", 1)[-1].upper() != base:
            continue
        table = pc_displacement_target(lea)
        absolute = re.fullmatch(r"\((0x[0-9a-f]+)\)\.l\|" + base, lea.operands, re.I)
        if table is None and absolute:
            table = int(absolute[1], 0)
        if table is None:
            continue
        word_at = pointer_at = None
        cursor = load.cpu_address + load.length
        jump = None
        for _ in range(8):
            item = by_address.get(cursor)
            if item is None:
                break
            if item.mnemonic.upper() == "JMP":
                if len(item.flows) == 1:
                    jump = item
                break
            if item.flow_type.upper() != "FALL_THROUGH":
                break
            word = re.fullmatch(r"#0x4ef9\|\((0x[0-9a-f]+)\)\.[wl]", item.operands, re.I)
            pointer = re.fullmatch(register + r"\|\((0x[0-9a-f]+)\)\.[wl]", item.operands, re.I)
            if item.mnemonic.upper() == "MOVE.W" and word:
                word_at = int(word[1], 0) & 0xFFFFFF
            elif item.mnemonic.upper() == "MOVE.L" and pointer:
                pointer_at = int(pointer[1], 0) & 0xFFFFFF
            elif pointer_at is None and item.operands.rsplit("|", 1)[-1].upper() == register:
                break  # Original loaded value was clobbered before storage.
            cursor += item.length
        if (jump is None or word_at is None or pointer_at != word_at + 2
                or jump.flows[0] & 0xFFFFFF != word_at
                or not image.header.ram_start <= word_at <= image.header.ram_end - 5):
            continue
        start = table - image.header.rom_start
        targets = []
        for index in range(1024):
            slot = start + index * 4
            if (slot < 0x200 or slot & 1 or slot + 4 > len(image.data)
                    or any(slot + b in occupied for b in range(4))
                    or index and image.header.rom_start + slot in boundaries):
                break
            target = int.from_bytes(image.data[slot:slot + 4], "big")
            physical = target - image.header.rom_start
            if (target & 1 or not 0x200 <= physical <= len(image.data) - 2
                    or physical in interiors or start <= physical < slot + 4
                    or image.data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                break
            targets.append(target)
        if len(set(targets)) < 3 or not (set(targets) & starts):
            continue
        evidence = (f"indexed longword table {table:06X}; loaded pointer written to "
                    f"RAM JMP abs.l operand {pointer_at:06X}; stub invoked at {jump.cpu_address:06X}")
        for target in targets:
            result[target] = DecoderSeed(target, "ram_stub_dispatch", "high", evidence, load.cpu_address)
    return tuple(result[address] for address in sorted(result))
