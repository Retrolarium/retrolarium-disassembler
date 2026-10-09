"""Bounded proof that direct helper calls cannot modify their caller's frame."""
from collections import deque
import re

from retrolarium_disasm.m68k.abstract import _register_list


_STACK = re.compile(r"(?<![A-Z0-9])(?:SP|A7|USP)[BWL]?(?![A-Z0-9])", re.I)
_READ_ONLY = {"CMP", "CMPA", "CMPI", "CMPM", "TST", "BTST"}
_EXCEPTIONAL = {"TRAP", "TRAPV", "STOP", "RESET", "ILLEGAL", "LINK", "UNLK", "PEA",
                "DIVU", "DIVS", "CHK", "CHK2"}


def make_trap_call_frame_validator(facts):
    """Check a rooted trap's callees without assuming an unknown call returns.

    Callees may read memory and change registers. Stack access is limited to
    matched MOVEM or single address-register saves/restores; other memory
    stores cannot be ruled out as aliases of the caller's exception frame.
    Computed transfers and recursive calls are deliberately unsupported.
    The inline-argument recognizer checks the trap's overall ABI; this guard
    additionally limits its stores to those specific exception-frame edits.
    """
    facts = {f.cpu_address: f for f in facts.values()}
    cache = {}
    active = set()

    def prove(entry, *, trap=False, depth=0):
        key = entry, trap
        if key in cache:
            return cache[key]
        if key in active or depth > 8:
            return False
        active.add(key)
        result = walk(entry, trap, depth)
        active.remove(key)
        cache[key] = result
        return result

    def walk(entry, trap, depth):
        first = facts.get(entry)
        frame_save = None
        if trap and first and first.raw[:2] in {b'\x48\xe7', b'\x48\xa7'}:
            registers = tuple(sorted(_register_list(first.operands.split('|')[0])))
            width = 4 if first.raw[:2] == b'\x48\xe7' else 2
            if registers and 'a7' not in registers:
                frame_save = (width, registers)
        pc_slot = (f'(0X{2 + frame_save[0] * len(frame_save[1]):X},SP)'
                   if frame_save else None)
        pending = deque([(entry, ())])
        seen, exits, edges = set(), set(), {}
        while pending and len(seen) < 256:
            node = pending.popleft()
            if node in seen:
                continue
            seen.add(node)
            address, stack = node
            fact = facts.get(address)
            if fact is None:
                return False
            op = fact.mnemonic.upper().split('.', 1)[0]
            operands = fact.operands.upper().split('|')
            flow = fact.flow_type.upper()
            following = address + fact.length
            targets = tuple(target & 0xFFFFFF for target in fact.flows)
            if fact.raw == b'\x4e\x75' or trap and fact.raw in {b'\x4e\x73', b'\x4e\x77'}:
                if stack:
                    return False
                exits.add(node)
                edges[node] = set()
                continue
            if (op in _EXCEPTIONAL or op in {'RTE', 'RTR'} and not trap
                    or operands[-1] == 'SR'):
                return False
            if fact.mnemonic.upper() in {'MOVEM.L', 'MOVEM.W'}:
                width = 4 if fact.mnemonic.upper() == 'MOVEM.L' else 2
                if len(operands) != 2:
                    return False
                if operands[-1] == '-(SP)':
                    registers = tuple(sorted(_register_list(operands[0])))
                    if not registers or 'a7' in registers:
                        return False
                    stack += ((width, registers),)
                elif operands[0] == '(SP)+':
                    registers = tuple(sorted(_register_list(operands[-1])))
                    if not stack or stack[-1] != (width, registers):
                        return False
                    stack = stack[:-1]
                else:
                    return False
            elif (fact.mnemonic.upper() == 'MOVE.L' and len(operands) == 2
                  and operands[-1] == '-(SP)' and re.fullmatch(r'A[0-6]', operands[0])):
                stack += ((4, (operands[0].lower(),)),)
            elif (fact.mnemonic.upper() == 'MOVEA.L' and len(operands) == 2
                  and operands[0] == '(SP)+' and re.fullmatch(r'A[0-6]', operands[-1])):
                saved = (4, (operands[-1].lower(),))
                if not stack or stack[-1] != saved:
                    return False
                stack = stack[:-1]
            elif (trap and frame_save and stack == (frame_save,)
                  and fact.mnemonic.upper() == 'MOVEA.L' and operands[0] == pc_slot
                  and re.fullmatch(r'A[0-6]', operands[-1])):
                pass  # Read the exception PC after the recognized initial save.
            elif (trap and frame_save and stack == (frame_save,)
                  and fact.mnemonic.upper() == 'ADDQ.L'
                  and operands == ['0X2', pc_slot]):
                pass  # The ABI recognizer separately checks this single advance.
            elif (trap and not stack and fact.mnemonic.upper() == 'ADDQ.L'
                  and operands == ['0X2', 'SP']):
                pass  # Recognized flag-query ABI discards SR immediately before RTS.
            elif _STACK.search(fact.operands):
                return False
            elif '(' in operands[-1] and op not in _READ_ONLY | {'LEA', 'JMP', 'JSR'}:
                return False
            if op in {'JSR', 'BSR'}:
                if (flow in {'COMPUTED_CALL', 'COMPUTED_JUMP'} or len(targets) != 1
                        or not prove(targets[0], depth=depth + 1)):
                    return False
                next_addresses = (following,)
            elif flow == 'FALL_THROUGH':
                next_addresses = (following,)
            elif flow == 'CONDITIONAL_JUMP' and targets:
                next_addresses = (*targets, following)
            elif op in {'JMP', 'BRA'} and flow not in {'COMPUTED_JUMP', 'COMPUTED_CALL'} and len(targets) == 1:
                next_addresses = targets
            else:
                return False
            edges[node] = {(target, stack) for target in next_addresses}
            pending.extend(edges[node] - seen)
        if pending or not exits:
            return False
        reverse = {node: set() for node in seen}
        for node, successors in edges.items():
            for successor in successors:
                reverse[successor].add(node)
        can_return = set(exits)
        pending.extend(exits)
        while pending:
            for predecessor in reverse[pending.popleft()] - can_return:
                can_return.add(predecessor)
                pending.append(predecessor)
        return can_return == seen

    return lambda handler: prove(handler, trap=True)
