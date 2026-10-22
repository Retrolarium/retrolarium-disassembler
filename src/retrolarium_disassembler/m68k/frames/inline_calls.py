"""Prove an ordinary subroutine ABI that consumes an inline word."""

import re

from retrolarium_disassembler.m68k.abstract import _register_list
from retrolarium_disassembler.m68k.frames.call_frame import _STACK
from retrolarium_disassembler.m68k.dispatch.ram import InlineTrapCall


def _consumes_word(facts, start):
    first = facts.get(start)
    if first is None or first.raw[:2] != b"\x48\xe7" or len(first.raw) != 4:
        return False
    saved = set(_register_list(first.operands.split("|", 1)[0]))
    if not saved or "a7" in saved or len(saved) != int.from_bytes(first.raw[2:], "big").bit_count():
        return False
    slot = f"(0X{4 * len(saved):X},SP)"
    cursor = start + first.length
    prefix = []
    for _ in range(3):
        fact = facts.get(cursor)
        if fact is None or fact.flow_type.upper() != "FALL_THROUGH":
            return False
        prefix.append(fact)
        cursor += fact.length
    pc, read, write = prefix
    match = re.fullmatch(re.escape(slot) + r"\|(A[0-6])", pc.operands.upper())
    if pc.mnemonic.upper() != "MOVEA.L" or match is None:
        return False
    register = match[1]
    value = re.fullmatch(r"\(" + register + r"\)\+\|(D[0-7])W", read.operands.upper())
    if (
        read.mnemonic.upper() != "MOVE.W"
        or value is None
        or register.lower() not in saved
        or value[1].lower() not in saved
        or write.mnemonic.upper() != "MOVE.L"
        or write.operands.upper() != register + "|" + slot
    ):
        return False
    # The saved PC has advanced exactly two bytes. Only straight-line work
    # with no further stack access is accepted before its balanced restore.
    for _ in range(16):
        fact = facts.get(cursor)
        if fact is None:
            return False
        operands = fact.operands.upper().split("|")
        if fact.raw[:2] == b"\x4c\xdf" and len(fact.raw) == 4:
            restored = set(_register_list(operands[-1]))
            if (
                operands[0] != "(SP)+"
                or restored != saved
                or len(restored) != int.from_bytes(fact.raw[2:], "big").bit_count()
            ):
                return False
            following = facts.get(cursor + fact.length)
            return following is not None and following.raw == b"\x4e\x75"
        if _STACK.search(fact.operands):
            return False
        opcode = int.from_bytes(fact.raw[:2], "big")
        call = opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100
        if fact.flow_type.upper() != "FALL_THROUGH" and not (
            call and fact.flow_type.upper() == "UNCONDITIONAL_CALL" and len(fact.flows) == 1
        ):
            return False
        cursor += fact.length
    return False


def discover_inline_subroutine_calls(image, facts):
    """Only rooted calls and completely decoded fixed argument consumers."""
    facts = {fact.cpu_address: fact for fact in facts.values()}
    handlers = {}
    calls = []
    for fact in facts.values():
        opcode = int.from_bytes(fact.raw[:2], "big")
        if not (opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100):
            continue
        if len(fact.flows) != 1:
            continue
        target = fact.flows[0] & 0xFFFFFF
        if target not in handlers:
            handlers[target] = _consumes_word(facts, target)
        argument = fact.physical_offset + fact.length
        if not handlers[target] or argument + 2 >= len(image.data):
            continue
        following = fact.cpu_address + fact.length
        calls.append(InlineTrapCall(fact.cpu_address, following, following + 2, None, target))
    return tuple(calls)
