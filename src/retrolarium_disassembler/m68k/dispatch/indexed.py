"""Recover pointer tables addressed by a proven byte index and LEA base."""
import re

from retrolarium_disassembler.facts import InstructionFact
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_disassembler.m68k.instructions import absolute_referenced_addresses, instruction_sets


_LOAD = re.compile(r"\((-?0x[0-9a-f]+),(A[0-6]),(D[0-7])w\*0x1\)\|(A[0-6])", re.I)
_LEA = re.compile(r"\((0x[0-9a-f]+)\)\.l\|(A[0-6])", re.I)
_PC_POINTER = re.compile(r"\((0x[0-9a-f]+),PC,D[0-7]w\*0x1\)\|(A[0-6])", re.I)


def discover_dense_absolute_jump_seeds(image: MegaDriveImage, *, scan_start: int = 0x200) -> tuple[DecoderSeed, ...]:
    """Find at least four consecutive JMP abs.l slots with optional NOP padding."""
    data, origin = image.data, image.header.rom_start
    seeds = []
    start = scan_start
    while start + 24 <= len(data):
        cursor = start
        entries = []
        padding = []
        while cursor + 6 <= len(data) and data[cursor:cursor + 2] == b"\x4e\xf9":
            target = int.from_bytes(data[cursor + 2:cursor + 6], "big") & 0xFFFFFF
            physical = target - origin
            if target & 1 or physical < 0x200 or physical + 2 > len(data) or data[physical:physical + 2] in {b"\xff\xff", b"\x00\x00"}:
                break
            entries.append((origin + cursor, target))
            cursor += 6
            if data[cursor:cursor + 2] == b"\x4e\x71":
                padding.append(origin + cursor)
                cursor += 2
        if len(entries) < 4:
            start += 2
            continue
        evidence = f"{len(entries)} consecutive absolute JMP slots with mapped targets at {origin + start:06X}"
        for address in {a for pair in entries for a in pair} | set(padding):
            seeds.append(DecoderSeed(address, "dense_absolute_jump_table", "high", evidence, origin + start))
        start = cursor
    return tuple(seeds)


def discover_register_indexed_dispatch_seeds(image: MegaDriveImage, facts: dict[int, InstructionFact]) -> tuple[DecoderSeed, ...]:
    by_address = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    occupied, interiors, _ = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    seeds = []
    for load in facts.values():
        match = _LOAD.fullmatch(load.operands)
        if load.mnemonic.upper() != "MOVEA.L" or match is None:
            continue
        displacement, base_reg, index_reg, destination = match.groups()
        base_reg, index_reg, destination = base_reg.upper(), index_reg.upper(), destination.upper()
        call = by_address.get(load.cpu_address + load.length)
        if call is None or call.mnemonic.upper() not in {"JSR", "JMP"} or call.operands.upper() != f"({destination})":
            continue
        lea = ends.get(load.cpu_address)
        base = _LEA.fullmatch(lea.operands) if lea and lea.mnemonic.upper() == "LEA" else None
        if base is None or base.group(2).upper() != base_reg:
            continue
        # Prove unsigned byte -> nonzero guard -> multiply by four, without
        # intervening writes or inferred runtime values.
        previous = ends.get(lea.cpu_address)
        scaled = True
        for _ in range(2):
            if previous is None or previous.mnemonic.upper() != "ADD.W" or previous.operands.upper() != f"{index_reg}W|{index_reg}W":
                scaled = False
                break
            previous = ends.get(previous.cpu_address)
        if not scaled or previous is None or previous.mnemonic.upper().split('.')[0] != "BEQ" or not previous.flows or min(previous.flows) <= call.cpu_address:
            continue
        read = ends.get(previous.cpu_address)
        zero = ends.get(read.cpu_address) if read else None
        if (read is None or read.mnemonic.upper() != "MOVE.B" or not read.operands.upper().endswith(f"|{index_reg}B")
                or zero is None or zero.mnemonic.upper() != "MOVEQ" or zero.operands.upper() != f"0X0|{index_reg}"):
            continue
        table = int(base.group(1), 0) + int(displacement, 0) + 4
        start = table - image.header.rom_start
        entries = []
        for index in range(255):
            slot = start + 4 * index
            if slot < 0x200 or slot + 4 > len(image.data) or slot & 1:
                break
            if index and image.header.rom_start + slot in boundaries:
                break
            if any(slot + b in occupied for b in range(4)):
                break
            target = int.from_bytes(image.data[slot:slot + 4], "big")
            physical = target - image.header.rom_start
            if (target & 1 or physical < 0x200 or physical + 2 > len(image.data)
                    or physical in interiors or start <= physical < slot + 4
                    or image.data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                break
            entries.append(target)
        if len(entries) >= 2:
            seeds.extend(DecoderSeed(target, "register_indexed_dispatch", "proven",
                                     f"zero-extended nonzero byte times four; LEA table {table:06X}; call {call.cpu_address:06X}",
                                     load.cpu_address) for target in entries)
    return tuple(seeds)


def discover_nested_word_dispatch_seeds(image: MegaDriveImage, facts: dict[int, InstructionFact]) -> tuple[DecoderSeed, ...]:
    """Resolve pointer-table -> byte-indexed entry-relative word -> JMP.

    Each load and arithmetic step is present in decoded code. The second
    table stops at its first forward handler, code, or an explicit data base.
    """
    by_address = {f.cpu_address: f for f in facts.values()}
    occupied, interiors, _ = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    data = image.data
    origin = image.header.rom_start
    result = []
    for load in facts.values():
        match = _PC_POINTER.fullmatch(load.operands)
        if load.mnemonic.upper() != "MOVEA.L" or match is None:
            continue
        table, register = int(match[1], 0), match[2].upper()
        sequence = []
        address = load.cpu_address + load.length
        for _ in range(5):
            item = by_address.get(address)
            if item is None:
                break
            sequence.append(item)
            address += item.length
        if len(sequence) != 5:
            continue
        zero, read, index, add, call = sequence
        zero_match = re.fullmatch(r"0x0\|(D[0-7])", zero.operands, re.I)
        if zero.mnemonic.upper() != "MOVEQ" or zero_match is None:
            continue
        dr = zero_match[1].upper()
        if (read.mnemonic.upper() != "MOVE.B" or not read.operands.upper().endswith(f"|{dr}B")
                or index.mnemonic.upper() != "ADDA.W" or index.operands.upper() != f"{dr}W|{register}"
                or add.mnemonic.upper() != "ADDA.W" or add.operands.upper() != f"({register})|{register}"
                or call.mnemonic.upper() not in {"JMP", "JSR"} or call.operands.upper() != f"({register})"):
            continue
        tables = []
        for i in range(256):
            slot = table - origin + 4 * i
            if slot < 0x200 or slot + 4 > len(data) or any(slot + b in occupied for b in range(4)):
                break
            if i and origin + slot in boundaries:
                break
            secondary = int.from_bytes(data[slot:slot + 4], "big")
            physical = secondary - origin
            if physical < 0x200 or physical + 2 > len(data) or physical & 1 or physical in occupied or table <= secondary < table + 4 * (i + 1):
                break
            tables.append(secondary)
        if len(tables) < 2:
            continue
        for secondary in set(tables):
            start = secondary - origin
            limit = min(len(data), start + 256)
            targets = []
            for slot in range(start, limit, 2):
                if slot + 2 > limit or slot in occupied or slot + 1 in occupied:
                    break
                if slot != start and origin + slot in boundaries:
                    break
                word = int.from_bytes(data[slot:slot + 2], "big", signed=True)
                target = origin + slot + word
                physical = target - origin
                if (target & 1 or physical < 0x200 or physical + 2 > len(data)
                        or physical in interiors or start <= physical < slot + 2
                        or data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                    break
                targets.append(target)
                if physical >= start:
                    limit = min(limit, physical)
            if len(targets) >= 2:
                result.extend(DecoderSeed(t, "nested_word_dispatch", "proven",
                    f"pointer table {table:06X} -> entry-relative table {secondary:06X}; call {call.cpu_address:06X}",
                    load.cpu_address) for t in targets)
    return tuple(result)


def discover_added_index_dispatch_seeds(image: MegaDriveImage, facts: dict[int, InstructionFact]) -> tuple[DecoderSeed, ...]:
    """LEA / ADDA.W index / pointer load or entry-relative ADDA.W / JMP."""
    by_address = {f.cpu_address: f for f in facts.values()}
    occupied, interiors, _ = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    result = []
    for lea in facts.values():
        if lea.mnemonic.upper() != "LEA" or len(lea.raw) < 4:
            continue
        register = lea.operands.rsplit("|", 1)[-1].upper()
        if not re.fullmatch(r"A[0-6]", register):
            continue
        mode = int.from_bytes(lea.raw[:2], "big") & 0x3F
        if mode == 0x3A:
            table = lea.cpu_address + 2 + int.from_bytes(lea.raw[2:4], "big", signed=True)
        elif mode == 0x39 and len(lea.raw) == 6:
            table = int.from_bytes(lea.raw[2:6], "big")
        else:
            continue
        add = by_address.get(lea.cpu_address + lea.length)
        # Index preparation may follow LEA. Permit only scalar register work
        # with fall-through: the table base must survive every intervening step.
        for _ in range(8):
            if add is None or add.mnemonic.upper() == "ADDA.W":
                break
            operation = add.mnemonic.upper().split(".", 1)[0]
            destination = add.operands.rsplit("|", 1)[-1].upper()
            if (add.flow_type.upper() != "FALL_THROUGH"
                    or operation not in {"MOVE", "MOVEQ", "AND", "ANDI", "ASL", "ASR", "LSL", "LSR", "ADD", "ADDI", "SUB", "SUBI", "EXT", "SWAP", "CLR"}
                    or re.fullmatch(r"D[0-7][BWL]?", destination) is None):
                add = None
                break
            add = by_address.get(add.cpu_address + add.length)
        if add is None or add.mnemonic.upper() != "ADDA.W" or not add.operands.upper().endswith(f"|{register}"):
            continue
        load = by_address.get(add.cpu_address + add.length)
        if load is None or load.mnemonic.upper() not in {"MOVEA.L", "ADDA.W"} or load.operands.upper() != f"({register})|{register}":
            continue
        word_relative = load.mnemonic.upper() == "ADDA.W"
        if not word_relative and not re.fullmatch(rf"D[0-7]W\|{register}", add.operands.upper()):
            continue
        call = by_address.get(load.cpu_address + load.length)
        if call is None or call.mnemonic.upper() not in {"JMP", "JSR"} or call.operands.upper() != f"({register})":
            continue
        start = table - image.header.rom_start
        width = 2 if word_relative else 4
        limit = min(len(image.data), start + width * 256)
        targets = []
        for slot in range(start, limit, width):
            if slot < 0x200 or slot + width > limit or slot & 1 or any(slot + b in occupied for b in range(width)):
                break
            if slot != start and image.header.rom_start + slot in boundaries:
                break
            target = int.from_bytes(image.data[slot:slot + width], "big", signed=word_relative)
            if word_relative:
                target += image.header.rom_start + slot
            physical = target - image.header.rom_start
            if (target & 1 or physical < 0x200 or physical + 2 > len(image.data)
                    or start <= physical < slot + width
                    or image.data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                break
            # A conflicting backend decode invalidates this handler candidate,
            # not the proven pointer reader or later slots in its table.
            if physical not in interiors:
                targets.append(target)
            if physical >= start:
                limit = min(limit, physical)
        if len(targets) >= 2:
            operation = "entry-relative ADDA.W" if word_relative else "MOVEA.L pointer"
            result.extend(DecoderSeed(t, "added_index_dispatch", "proven",
                f"LEA table {table:06X}; ADDA.W index; {operation}; call {call.cpu_address:06X}",
                lea.cpu_address) for t in targets)
    return tuple(result)
