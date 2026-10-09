"""Prove selector-dependent inline TRAP lengths from saved exception-PC reads."""
from collections import deque
import re

from retrolarium_disasm.m68k.abstract import _register_list
from retrolarium_disasm.m68k.frames.call_frame import _STACK
from retrolarium_disasm.m68k.dispatch.table import _targets
from retrolarium_disasm.megadrive.symbols import pc_indexed_target


def _dispatch(image, facts, handler):
    first = facts.get(handler)
    if not first or first.raw[:2] not in {b"\x48\xe7", b"\x48\xa7"} or len(first.raw) != 4:
        return None
    saved = set(_register_list(first.operands.split("|", 1)[0]))
    if not saved or len(saved) != int.from_bytes(first.raw[2:], "big").bit_count():
        return None
    width = 4 if first.raw[:2] == b"\x48\xe7" else 2
    slot = f"(0X{2 + len(saved) * width:X},SP)"
    cursor = handler + first.length
    pc_register = index_register = None
    advanced = False
    for _ in range(12):
        fact = facts.get(cursor)
        if not fact or fact.flow_type.upper() != "FALL_THROUGH":
            return None
        operands = fact.operands.upper()
        mnemonic = fact.mnemonic.upper()
        if mnemonic == "MOVEA.L" and operands.startswith(slot + "|"):
            if pc_register: return None
            pc_register = operands.split("|", 1)[1]
            if not re.fullmatch(r"A[0-6]", pc_register): return None
        elif mnemonic == "MOVE.W" and pc_register and re.fullmatch(
                r"\(" + pc_register + r"\)\+\|D[0-7]W", operands):
            if index_register: return None
            index_register = operands.split("|", 1)[1]
        elif mnemonic == "ADDQ.L" and operands.lstrip("#") == "0X2|" + slot:
            if advanced: return None
            advanced = True
        elif _STACK.search(operands) or pc_register and operands.split("|")[-1] == pc_register:
            return None
        cursor += fact.length
        if advanced and index_register: break
    double = facts.get(cursor)
    if not double or double.mnemonic.upper() != "ADD.W" or double.operands.upper() != f"{index_register}|{index_register}":
        return None
    load = facts.get(cursor + double.length)
    jump = facts.get(load.cpu_address + load.length) if load else None
    table = pc_indexed_target(load) if load else None
    if (not table or not jump or load.mnemonic.upper() != "MOVE.W"
            or load.operands.rsplit("|", 1)[-1].upper() != index_register
            or jump.mnemonic.upper() != "JMP" or pc_indexed_target(jump) != table
            or table[1:] != (int(index_register[1]), "d", "w")):
        return None
    targets = _targets(image, facts, table[0], 2)
    if not targets: return None
    return targets, slot, pc_register, saved, width


def _consumption(facts, start, slot, pc_register, saved, width):
    # Cursor and saved PC must agree at every restored RTE path. A parameter
    # read inside a loop or incompatible branch lengths therefore fails.
    pending = deque([(start, 2, 2, False)])
    visited, returns, edges = set(), set(), {}
    lengths = set()
    while pending and len(visited) < 512:
        node = pending.popleft()
        address, consumed, advanced, restored = node
        if node in visited: continue
        visited.add(node)
        fact = facts.get(address)
        if not fact or not 2 <= consumed <= 32 or not 2 <= advanced <= 32:
            return None
        if fact.raw == b"\x4e\x73":
            if not restored or consumed != advanced: return None
            lengths.add(consumed)
            returns.add(node)
            edges[node] = set()
            continue
        operands = fact.operands.upper().split("|")
        mnemonic = fact.mnemonic.upper()
        restore = "MOVEM.L" if width == 4 else "MOVEM.W"
        if mnemonic == restore and operands[0] == "(SP)+":
            if restored or set(_register_list(operands[-1])) != saved: return None
            restored = True
        elif mnemonic == "ADDQ.L" and operands[-1] == slot:
            try: advanced += int(operands[0].lstrip("#"), 0)
            except ValueError: return None
        elif mnemonic in {"MOVE.W", "MOVE.L"} and operands[0] == f"({pc_register})+":
            if restored: return None
            consumed += 4 if mnemonic.endswith(".L") else 2
        elif (any(_STACK.search(operand) for operand in operands)
              or any(pc_register in operand for operand in operands)):
            return None
        flow = fact.flow_type.upper()
        following = address + fact.length
        targets = {target & 0xFFFFFF for target in fact.flows}
        # An unsummarised callee can change the cursor or saved exception PC.
        if flow == "FALL_THROUGH":
            successors = {following}
        elif flow == "CONDITIONAL_JUMP":
            successors = targets | {following}
        elif flow == "UNCONDITIONAL_JUMP" and targets:
            successors = targets
        else: return None
        edges[node] = {(target, consumed, advanced, restored) for target in successors}
        pending.extend(edges[node] - visited)
    if pending or not returns or len(lengths) != 1: return None
    reverse = {node: set() for node in visited}
    for node, successors in edges.items():
        for successor in successors: reverse[successor].add(node)
    can_return = set(returns)
    pending.extend(returns)
    while pending:
        for node in reverse[pending.popleft()] - can_return:
            can_return.add(node)
            pending.append(node)
    return next(iter(lengths)) if can_return == visited else None


def discover_variable_inline_trap_calls(image, facts):
    from retrolarium_disasm.m68k.dispatch.ram import InlineTrapCall
    from retrolarium_disasm.m68k.callbacks.trap import executed_arrays, setter_array
    from retrolarium_disasm.megadrive.pointers import _instruction_sets
    facts = {fact.cpu_address: fact for fact in facts.values()}
    arrays = executed_arrays(image, facts)
    _, interiors, _ = _instruction_sets(facts)
    handlers = {}
    for number in range(max(0, min(16, len(image.vector_table) - 32))):
        handler = image.vector_table[32 + number].address
        dispatch = _dispatch(image, facts, handler)
        if dispatch: handlers[number] = (handler, dispatch)
    calls, summaries, setters = [], {}, {}
    for fact in facts.values():
        if fact.mnemonic.upper() != "TRAP" or len(fact.raw) != 2: continue
        opcode = int.from_bytes(fact.raw, "big")
        if opcode & 0xFFF0 != 0x4E40 or opcode & 15 not in handlers: continue
        handler, (targets, slot, pc_register, saved, width) = handlers[opcode & 15]
        offset = fact.physical_offset + 2
        if offset + 2 > len(image.data): continue
        selector = int.from_bytes(image.data[offset:offset + 2], "big")
        if selector >= len(targets): continue
        key = handler, selector
        if key not in summaries:
            summaries[key] = _consumption(facts, targets[selector], slot, pc_register, saved, width)
            setters[key] = setter_array(image, facts, targets[selector], slot, pc_register)
        length = summaries[key]
        if length and offset + length <= len(image.data):
            target = None
            if length == 6 and setters[key] in arrays:
                pointer = int.from_bytes(image.data[offset + 2:offset + 6], "big") & 0xFFFFFF
                physical = pointer - image.header.rom_start
                if (not pointer & 1 and 0x200 <= physical <= len(image.data) - 2
                        and physical not in interiors
                        and image.data[physical:physical + 2] not in {b"\x00\x00", b"\xff\xff"}):
                    target = pointer
            calls.append(InlineTrapCall(fact.cpu_address, fact.cpu_address + 2,
                         fact.cpu_address + 2 + length, target, handler, length))
    return tuple(calls)
