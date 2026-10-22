"""Prove fixed inline-word TRAP ABIs with a saved MOVEM exception frame."""

from collections import deque
import re

from retrolarium_disassembler.m68k.abstract import _register_list
from retrolarium_disassembler.m68k.frames.call_frame import _STACK


def _handler_consumes_word(facts, handler):
    first = facts.get(handler)
    if first is None or first.raw[:2] not in {b"\x48\xe7", b"\x48\xa7"} or len(first.raw) != 4:
        return False
    saved = set(_register_list(first.operands.split("|", 1)[0]))
    if not saved or len(saved) != int.from_bytes(first.raw[2:], "big").bit_count():
        return False
    saved_size = 4 if first.raw[:2] == b"\x48\xe7" else 2
    restore_mnemonic = "MOVEM.L" if saved_size == 4 else "MOVEM.W"
    slot = f"(0X{2 + saved_size * len(saved):X},SP)"  # saved SR precedes the exception PC
    cursor = handler + first.length
    pc_register = None
    consumed = advanced = False
    prefix = set()
    for _ in range(8):
        fact = facts.get(cursor)
        if fact is None or fact.flow_type.upper() != "FALL_THROUGH":
            break
        operands = fact.operands.upper()
        mnemonic = fact.mnemonic.upper()
        if mnemonic == "MOVEA.L" and operands.startswith(slot + "|"):
            pc_register = operands.split("|", 1)[1]
            if not re.fullmatch(r"A[0-6]", pc_register):
                return False
        elif mnemonic == "ADDQ.L" and operands.lstrip("#") == "0X2|" + slot:
            if advanced:
                return False
            advanced = True
        elif mnemonic == "MOVE.W" and pc_register and re.fullmatch(r"\(" + pc_register + r"\)\+?\|D[0-7]W", operands):
            consumed = True
        elif _STACK.search(operands) or pc_register and operands.split("|")[-1] == pc_register:
            return False
        prefix.add(cursor)
        cursor += fact.length
        if consumed and advanced:
            break
    if not consumed or not advanced:
        return False
    pending = deque([(cursor, False, False)])
    visited = set()
    returns = set()
    edges = {}
    while pending and len(visited) < 512:
        node = pending.popleft()
        address, restored, discarded_sr = node
        if node in visited:
            continue
        visited.add(node)
        fact = facts.get(address)
        if fact is None or address in prefix or slot in fact.operands.upper():
            return False  # Further PC edits would make the argument length variable.
        if fact.raw in {b"\x4e\x73", b"\x4e\x75"}:
            # Some flag-query TRAPs intentionally preserve their result CCR:
            # restore registers, discard only the saved SR word, then RTS.
            if not restored or (fact.raw == b"\x4e\x75") != discarded_sr:
                return False
            returns.add(node)
            edges[node] = set()
            continue
        operands = fact.operands.upper().split("|")
        if discarded_sr:
            return False  # The adjusted exception frame must return immediately.
        if restored and fact.mnemonic.upper() == "ADDQ.L" and operands == ["0X2", "SP"]:
            discarded_sr = True
        elif fact.mnemonic.upper() == restore_mnemonic and operands[0] == "(SP)+":
            if restored or set(_register_list(operands[-1])) != saved:
                return False
            restored = True
        elif any(_STACK.search(operand) for operand in operands):
            return False
        following = address + fact.length
        flow = fact.flow_type.upper()
        targets = {target & 0xFFFFFF for target in fact.flows}
        if flow in {"FALL_THROUGH", "UNCONDITIONAL_CALL", "CONDITIONAL_CALL"}:
            successors = {(following, restored, discarded_sr)}
        elif flow == "CONDITIONAL_JUMP":
            successors = {(target, restored, discarded_sr) for target in targets} | {
                (following, restored, discarded_sr)
            }
        elif flow == "UNCONDITIONAL_JUMP" and targets:
            successors = {(target, restored, discarded_sr) for target in targets}
        else:
            return False
        edges[node] = successors
        pending.extend(successors - visited)
    if pending or not returns:
        return False
    # A closed loop cannot masquerade as a returning handler.
    reverse = {node: set() for node in visited}
    for node, successors in edges.items():
        for successor in successors:
            reverse[successor].add(node)
    can_return = set(returns)
    pending.extend(returns)
    while pending:
        for node in reverse[pending.popleft()] - can_return:
            can_return.add(node)
            pending.append(node)
    return can_return == visited


def discover_frame_inline_trap_calls(image, facts):
    from retrolarium_disassembler.m68k.dispatch.ram import InlineTrapCall

    facts = {fact.cpu_address: fact for fact in facts.values()}
    handlers = {
        number: image.vector_table[32 + number].address
        for number in range(max(0, min(16, len(image.vector_table) - 32)))
        if _handler_consumes_word(facts, image.vector_table[32 + number].address)
    }
    calls = []
    for fact in facts.values():
        if fact.mnemonic.upper() != "TRAP" or len(fact.raw) != 2:
            continue
        opcode = int.from_bytes(fact.raw, "big")
        number = opcode & 15
        if opcode & 0xFFF0 != 0x4E40 or number not in handlers:
            continue
        if fact.physical_offset + 4 > len(image.data):
            continue
        calls.append(
            InlineTrapCall(fact.cpu_address, fact.cpu_address + 2, fact.cpu_address + 4, None, handlers[number])
        )
    return tuple(calls)
