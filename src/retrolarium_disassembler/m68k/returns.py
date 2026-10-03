"""Repair suppressed call continuations using a normal-return CFG witness.

Busy waits depend on DMA/interrupt writes outside the local function. Backend
constant-memory/no-return inference can therefore suppress real returns. A
balanced path to RTS proves a possible normal return, without interpreting
volatile RAM as a constant or overriding truly nonreturning routines.
"""
from collections import deque

from .m68k_abstract import _register_list, AbstractState, TruthValue, transfer_instruction, _branch_outcome
from .m68k_seeds import DecoderSeed
from .m68k_call_frame import _STACK


def discover_returning_call_seeds(image, facts, call_sites=None, *, planned_roots=frozenset()):
    facts = {fact.cpu_address: fact for fact in facts.values()}
    call_sites = dict(facts if call_sites is None else call_sites)
    # An already validated root can be erased by backend no-return inference.
    # Its immediate caller may then be unrooted too. Repair only a caller
    # whose architectural continuation is already an independently planned
    # root; no unrooted call is allowed to invent a new entrypoint.
    call_sites.update((address, fact) for address, fact in facts.items()
                      if fact.cpu_address + fact.length in planned_roots)
    returning = set()

    def may_return(start, recursion=()):
        if start in returning:
            return True
        if start in recursion or len(recursion) >= 5:
            return False
        pending = deque([(start, 0, AbstractState.initial())])
        visited = set()
        while pending and len(visited) < 512:
            address, stack, state = pending.popleft()
            if (address, stack, state) in visited or not 0 <= stack <= 2048:
                continue
            visited.add((address, stack, state))
            fact = facts.get(address)
            if fact is None:
                continue
            if fact.raw == b"\x4e\x75":
                if stack == 0:
                    returning.add(start)
                    return True
                continue
            operands = fact.operands.upper().split("|")
            mnemonic = fact.mnemonic.upper()
            if any(_STACK.search(operand) for operand in operands):
                # Saved registers are supported; reading/modifying the return
                # PC, taking the stack address, LINK/UNLK, and unknown stack
                # arithmetic do not establish this normal-return witness.
                if mnemonic in {"MOVEM.L", "MOVEM.W"} and len(operands) == 2:
                    size = 4 if mnemonic.endswith(".L") else 2
                    if (operands[1] == "-(SP)" and "a7" in _register_list(operands[0])
                            or operands[0] == "(SP)+" and "a7" in _register_list(operands[1])):
                        continue
                    if operands[1] == "-(SP)":
                        stack += size * len(_register_list(operands[0]))
                    elif operands[0] == "(SP)+":
                        stack -= size * len(_register_list(operands[1]))
                    else:
                        continue
                elif mnemonic in {"MOVE.L", "MOVE.W", "MOVE.B", "MOVE", "MOVEA.L", "MOVEA.W"} and len(operands) == 2:
                    size = 4 if mnemonic.endswith(".L") else 2
                    if operands[1] == "-(SP)" and not _STACK.search(operands[0]):
                        stack += size
                    elif operands[0] == "(SP)+" and not _STACK.search(operands[1]):
                        stack -= size
                    else:
                        continue
                else:
                    continue
                if stack < 0:
                    continue  # Popped the return PC: coroutine/nonlocal ABI.
            opcode = int.from_bytes(fact.raw[:2], "big")
            targets = tuple(target & 0xFFFFFF for target in fact.flows)
            following = address + fact.length
            outgoing = transfer_instruction(fact, state)
            if opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100:
                if targets and any(may_return(target, (*recursion, start)) for target in targets):
                    pending.append((following, stack, AbstractState.initial()))
                continue
            flow = fact.flow_type.upper()
            decision = _branch_outcome(fact, outgoing) if flow == "CONDITIONAL_JUMP" else TruthValue.UNKNOWN
            # A backend can mark an ordinary tail BRA as CALL_TERMINATOR
            # after inferring that its destination does not return. The
            # architectural instruction still jumps without pushing a PC.
            tail_branch = opcode & 0xFF00 == 0x6000
            if flow in {"UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP"} or opcode & 0xFFC0 == 0x4EC0 or tail_branch:
                if decision != TruthValue.FALSE:
                    pending.extend((target, stack, outgoing) for target in targets)
            if flow in {"FALL_THROUGH", "CONDITIONAL_JUMP"} and decision != TruthValue.TRUE:
                pending.append((following, stack, outgoing))
        return False

    seeds = {}
    for fact in call_sites.values():
        if fact.flow_type.upper() != "CALL_TERMINATOR":
            continue
        opcode = int.from_bytes(fact.raw[:2], "big")
        if not (opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100):
            continue
        continuation = fact.cpu_address + fact.length
        if not 0x200 <= continuation - image.header.rom_start < len(image.data):
            continue
        witnesses = [target & 0xFFFFFF for target in fact.flows if may_return(target & 0xFFFFFF)]
        if witnesses:
            seeds[continuation] = DecoderSeed(continuation, "normal_return_continuation", "proven",
                "balanced path to RTS from callee " + ",".join(f"{target:06X}" for target in witnesses)
                + "; backend suppressed architectural call fall-through", fact.cpu_address)
    return tuple(seeds[address] for address in sorted(seeds))
