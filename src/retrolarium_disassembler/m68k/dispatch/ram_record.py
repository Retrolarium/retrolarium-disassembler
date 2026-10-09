"""ROM record callbacks selected through a returned base stored in RAM."""
from collections import deque
import re

from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_disasm.m68k.frames.call_frame import _STACK
from retrolarium_disasm.m68k.instructions import pc_displacement_target
from retrolarium_disasm.m68k.instructions import instruction_sets, absolute_referenced_addresses


def _rom_lea(fact, register):
    if fact.mnemonic.upper() != "LEA" or fact.operands.rsplit("|", 1)[-1].upper() != register:
        return None
    pc = pc_displacement_target(fact)
    if pc is not None:
        return pc
    match = re.fullmatch(r"\((0x[0-9a-f]+)\)\.l\|" + register, fact.operands, re.I)
    return int(match[1], 0) if match else None


def _relative_bases(image, table, occupied):
    start = table - image.header.rom_start
    limit = min(len(image.data), start + 2048)
    values = []
    for at in range(start, limit, 2):
        if at < 0x200 or at + 2 > limit or at in occupied or at + 1 in occupied:
            break
        target = table + int.from_bytes(image.data[at:at + 2], "big")
        physical = target - image.header.rom_start
        if target & 1 or not start < physical < len(image.data) - 3:
            break
        values.append(target)
        limit = min(limit, physical)
    return tuple(values) if len(set(values)) >= 2 else ()


def _returned_bases(image, facts, entry, register, occupied):
    # Prove every decoded return path leaves this register holding a ROM base.
    pending = deque([(entry, (), frozenset(), None)])
    visited, returned = set(), set()
    while pending and len(visited) < 128:
        node = pending.popleft()
        if node in visited:
            continue
        visited.add(node)
        address, bases, zeros, offsets = node
        fact = facts.get(address)
        if fact is None:
            return ()
        if fact.raw == b"\x4e\x75":
            if not bases:
                return ()
            returned.update(bases)
            continue
        operands = fact.operands.upper().split("|")
        mnemonic = fact.mnemonic.upper()
        if any(operand in {f"({register})+", f"-({register})"} for operand in operands):
            return ()
        value = _rom_lea(fact, register)
        if value is not None:
            if not 0x200 <= value - image.header.rom_start < len(image.data) - 3:
                return ()
            bases, offsets = (value,), None
        elif mnemonic == "MOVEQ" and operands[0] == "0X0":
            zeros = zeros | {operands[-1]}
        elif mnemonic == "MOVE.W" and operands[-1][:2] in zeros:
            match = re.fullmatch(r"\(0X0," + register + r",(D[0-7])W\*0X1\)", operands[0])
            if match:
                if len(bases) != 1:
                    return ()
                targets = _relative_bases(image, bases[0], occupied)
                if not targets:
                    return ()
                offsets = (operands[-1][:2], bases[0], targets)
            elif offsets and operands[-1][:2] == offsets[0]:
                offsets = None
        elif mnemonic == "ADDA.L" and operands[-1] == register:
            if not offsets or operands[0] != offsets[0] or bases != (offsets[1],):
                return ()
            bases, offsets = offsets[2], None
        elif (_STACK.search(fact.operands)
              or mnemonic in {"EXG", "SWAP", "MOVEM.L", "MOVEM.W"}
              or any(re.search(r"(?<![A-Z0-9])" + register + r"(?![A-Z0-9])", operand)
                     for operand in operands) and not mnemonic.startswith(("CMP", "TST", "BTST"))):
            return ()
        elif (re.fullmatch(r"D[0-7]W", operands[-1]) and mnemonic.endswith(".W")
              and mnemonic.split(".")[0] in {"LSR", "LSL", "ANDI", "ADDI", "SUBI", "ADDQ", "SUBQ"}):
            if offsets and operands[-1][:2] == offsets[0]:
                offsets = None
        elif re.fullmatch(r"D[0-7][BWL]?", operands[-1]) and not mnemonic.startswith(("CMP", "TST", "BTST")):
            zeros = zeros - {operands[-1][:2]}
            if offsets and operands[-1][:2] == offsets[0]:
                offsets = None
        flow = fact.flow_type.upper()
        following = address + fact.length
        targets = tuple(a & 0xFFFFFF for a in fact.flows)
        if flow == "FALL_THROUGH":
            successors = (following,)
        elif flow == "CONDITIONAL_JUMP" and targets:
            successors = (*targets, following)
        elif flow == "UNCONDITIONAL_JUMP" and targets:
            successors = targets
        else:
            return ()
        pending.extend((a, bases, zeros, offsets) for a in successors)
    return tuple(sorted(returned)) if not pending else ()


def discover_ram_record_dispatch_seeds(image, facts):
    facts = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    occupied, interiors, starts = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    origins = {}
    # The constructor saves the requested register immediately after a direct
    # machine call whose complete return paths establish the ROM bases.
    for store in facts.values():
        match = re.fullmatch(r"(A[0-6])\|\((-?0x[0-9a-f]+)\)\.[wl]", store.operands, re.I)
        call = ends.get(store.cpu_address)
        if store.mnemonic.upper() != "MOVE.L" or not match or not call or len(call.flows) != 1:
            continue
        opcode = int.from_bytes(call.raw[:2], "big")
        if not (opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100):
            continue
        slot = int(match[2], 0) & 0xFFFFFF
        if image.header.ram_start <= slot <= image.header.ram_end - 3:
            bases = _returned_bases(image, facts, call.flows[0] & 0xFFFFFF, match[1].upper(), occupied)
            if bases:
                origins.setdefault(slot, set()).update(bases)
    result = {}
    for read in facts.values():
        match = re.fullmatch(r"\((-?0x[0-9a-f]+)\)\.[wl]\|(A[0-6])", read.operands, re.I)
        if read.mnemonic.upper() != "MOVEA.L" or not match:
            continue
        slot, ar = int(match[1], 0) & 0xFFFFFF, match[2].upper()
        bases = origins.get(slot)
        if not bases:
            continue
        code, cursor = [], read.cpu_address + read.length
        for _ in range(5):
            fact = facts.get(cursor)
            if not fact:
                break
            code.append(fact); cursor += fact.length
        if len(code) != 5:
            continue
        index, scale, add, load, jump = code
        dr = index.operands.rsplit("|", 1)[-1].upper()
        shift = re.fullmatch(r"#0X([1-4])\|" + dr, scale.operands.upper())
        field = re.fullmatch(r"\((0X[0-9A-F]+)," + ar + r"\)\|(A[0-6])", load.operands.upper())
        if (index.mnemonic.upper() != "MOVE.W" or not re.fullmatch(r"D[0-7]W", dr)
                or index.operands.upper().split("|")[0] in {f"({ar})+", f"-({ar})"}
                or any(f.flow_type.upper() != "FALL_THROUGH" for f in code[:4])
                or scale.mnemonic.upper() != "LSL.W" or not shift
                or add.mnemonic.upper() != "LEA" or add.operands.upper() != f"(0X0,{ar},{dr}*0X1)|{ar}"
                or load.mnemonic.upper() != "MOVEA.L" or not field
                or jump.mnemonic.upper() not in {"JMP", "JSR"} or jump.operands.upper() != f"({field[2]})"):
            continue
        stride, displacement = 1 << int(shift[1], 16), int(field[1], 0)
        if displacement > stride - 4:
            continue
        for base in sorted(bases):
            start = base - image.header.rom_start
            following = min((b-image.header.rom_start for b in bases if b > base), default=len(image.data))
            targets = []
            for at in range(start, min(following, start + 256*stride), stride):
                if (at < 0x200 or at + stride > len(image.data) or any(at+b in occupied for b in range(stride))
                        or at != start and image.header.rom_start + at in boundaries):
                    break
                pointer = int.from_bytes(image.data[at+displacement:at+displacement+4], "big")
                physical = pointer-image.header.rom_start
                if (pointer & 1 or not 0x200 <= physical <= len(image.data)-2 or physical in interiors
                        or start <= physical < at+stride or image.data[physical:physical+2] in {b"\x00\x00", b"\xff\xff"}):
                    break
                targets.append(pointer)
            if len(set(targets)) < 3 or not set(targets) & starts:
                continue
            for target in targets:
                result[target] = DecoderSeed(target, "ram_record_dispatch", "high",
                    f"returned ROM group base stored in RAM {slot:06X}; stride {stride}, "
                    f"field +{displacement} called at {jump.cpu_address:06X}; group {base:06X}", read.cpu_address)
    return tuple(result[a] for a in sorted(result))
