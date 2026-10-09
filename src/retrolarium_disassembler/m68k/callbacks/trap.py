"""Corroborate inline TRAP pointers with a bounded RAM callback array ABI."""
import re

from retrolarium_kit.m68k_abstract import _register_list


def _sequence(facts, start, count):
    result = []
    for _ in range(count):
        fact = facts.get(start)
        if fact is None:
            return []
        result.append(fact)
        start += fact.length
    return result


def _lea_ram(image, fact):
    if fact.mnemonic.upper() != "LEA":
        return None
    match = re.fullmatch(r"\((-?0x[0-9a-f]+)\)\.[wl]\|(A[0-6])", fact.operands, re.I)
    if not match:
        return None
    base = int(match[1], 0) & 0xFFFFFF
    return (base, match[2].upper()) if image.header.ram_start <= base <= image.header.ram_end else None


def _count(fact):
    if fact.mnemonic.upper() != "MOVEQ":
        return None
    match = re.fullmatch(r"(0x[0-9a-f]+)\|(D[0-7])", fact.operands, re.I)
    if not match or not 0 <= int(match[1], 0) <= 127:
        return None
    return int(match[1], 0) + 1, match[2].upper()


def _is(fact, mnemonic, operands):
    return fact.mnemonic.upper() == mnemonic and fact.operands.upper() == operands


def _branch_to(fact, address):
    return tuple(a & 0xFFFFFF for a in fact.flows) == (address,)


def _bitfield(image, fact, index):
    match = re.fullmatch(index + r"\|\((-?0x[0-9a-f]+)\)\.[wl]", fact.operands, re.I)
    if not match:
        return None
    address = int(match[1], 0) & 0xFFFFFF
    return address if image.header.ram_start <= address <= image.header.ram_end else None


def executed_arrays(image, facts):
    """A counted postincrement reader calls each enabled slot, preserving state."""
    result = set()
    for lea in facts.values():
        base = _lea_ram(image, lea)
        if base is None:
            continue
        code = _sequence(facts, lea.cpu_address, 12)
        if not code:
            continue
        _, count, clear, read, test, branch, save, load, call, restore, step, loop = code
        count = _count(count)
        clear_match = re.fullmatch(r"D[0-7]W", clear.operands.upper())
        read_match = re.fullmatch(r"\(" + base[1] + r"\)\+\|(D[0-7])", read.operands.upper())
        if not count or clear.mnemonic.upper() != "CLR.W" or not clear_match or not read_match:
            continue
        index, value = clear.operands.upper()[:2], read_match[1]
        flag = _bitfield(image, test, index)
        if (read.mnemonic.upper() != "MOVE.L" or len({index, value, count[1]}) != 3
                or test.mnemonic.upper() != "BTST.B" or flag is None
                or branch.mnemonic.upper() not in {"BEQ.B", "BEQ.W"} or not _branch_to(branch, step.cpu_address)
                or not _is(load, "MOVEA.L", value + "|" + base[1])
                or not _is(call, "JSR", "(" + base[1] + ")")
                or save.mnemonic.upper() != "MOVEM.L" or not save.operands.upper().endswith("|-(SP)")
                or restore.mnemonic.upper() != "MOVEM.L" or not restore.operands.upper().startswith("(SP)+|")
                or not _is(step, "ADDQ.W", "0X1|" + index + "W")
                or loop.mnemonic.upper() != "DBF" or not loop.operands.upper().startswith(count[1] + "W|")
                or not _branch_to(loop, read.cpu_address)):
            continue
        saved = set(_register_list(save.operands.split("|")[0]))
        if (saved != set(_register_list(restore.operands.split("|")[-1]))
                or not {base[1].lower(), count[1].lower(), index.lower()} <= saved
                or base[0] + 4 * count[0] - 1 > image.header.ram_end):
            continue
        result.add((base[0], count[0], flag))
    return result


def setter_array(image, facts, start, slot, pc_register):
    """Find an empty slot in a bounded array and store the inline longword."""
    code = _sequence(facts, start, 13)
    if not code:
        return None
    read, advance, count, lea, clear, test, branch, step, loop, skip, store, enable, end = code
    value_match = re.fullmatch(r"\(" + pc_register + r"\)\+\|(D[0-7])", read.operands.upper())
    base, count = _lea_ram(image, lea), _count(count)
    if not value_match or read.mnemonic.upper() != "MOVE.L" or not base or not count:
        return None
    value, index = value_match[1], clear.operands.upper()[:2]
    flag = _bitfield(image, enable, index)
    if (base[1] == pc_register or len({value, index, count[1]}) != 3
            or not re.fullmatch(r"D[0-7]W", clear.operands.upper())
            or clear.mnemonic.upper() != "CLR.W" or not _is(advance, "ADDQ.L", "0X4|" + slot)
            or not _is(test, "TST.L", "(" + base[1] + ")+")
            or branch.mnemonic.upper() not in {"BEQ.B", "BEQ.W"} or not _branch_to(branch, store.cpu_address)
            or not _is(step, "ADDQ.W", "0X1|" + index + "W")
            or loop.mnemonic.upper() != "DBF" or not loop.operands.upper().startswith(count[1] + "W|")
            or not _branch_to(loop, test.cpu_address)
            or skip.mnemonic.upper() not in {"BRA.B", "BRA.W"}
            or end.mnemonic.upper() not in {"BRA.B", "BRA.W"} or len(skip.flows) != 1 or skip.flows != end.flows
            or not _is(store, "MOVE.L", value + "|-(" + base[1] + ")")
            or enable.mnemonic.upper() != "BSET.B" or flag is None
            or base[0] + 4 * count[0] - 1 > image.header.ram_end):
        return None
    return base[0], count[0], flag
