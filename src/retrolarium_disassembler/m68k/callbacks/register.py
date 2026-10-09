"""Prove a constant callback parameter used by a direct helper."""
from __future__ import annotations

import re

from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_disasm.megadrive.pointers import _instruction_sets
from retrolarium_disasm.megadrive.symbols import pc_displacement_target
from retrolarium_disasm.m68k.abstract import _register_list


def _direct(fact):
    op = fact.mnemonic.upper().split('.', 1)[0]
    return (fact.flows[0] & 0xFFFFFF if op in {'BRA', 'BSR', 'JMP', 'JSR'}
            and len(fact.flows) == 1
            and fact.flow_type.upper() not in {'COMPUTED_CALL', 'COMPUTED_JUMP'} else None)


def _executor(facts, start, register):
    """A bounded straight path with no use or modification of the parameter."""
    visited = set()
    for _ in range(16):
        fact = facts.get(start)
        if fact is None or start in visited:
            return None
        visited.add(start)
        op = fact.mnemonic.upper().split('.', 1)[0]
        if (op in {'JSR', 'JMP'} and fact.operands.upper() == f'({register})'
                and fact.flow_type.upper() in {'COMPUTED_CALL', 'COMPUTED_JUMP'}):
            return fact.cpu_address
        # This conservative restriction catches EXG, MOVEM restores and
        # predecrement/postincrement operands as well as ordinary writes.
        if re.search(r'(?<![A-Z0-9])' + register + r'[BWL]?(?![A-Z0-9])', fact.operands.upper()):
            return None
        operands = fact.operands.upper().split('|')
        if op == 'MOVEM' and len(operands) == 2 and register.lower() in _register_list(operands[-1]):
            return None
        if op in {'BRA', 'JMP'}:
            start = _direct(fact)
            if start is None:
                return None
        elif fact.flow_type.upper() == 'FALL_THROUGH' and op not in {'RESET', 'TRAP', 'STOP', 'ILLEGAL'}:
            start = fact.cpu_address + fact.length
        else:
            return None  # Unknown call, conditional branch or exit.
    return None


def discover_register_callback_seeds(image, facts, *, execution_facts=None):
    """Rooted LEA / direct helper transfer / unchanged An / JSR or JMP (An).

    Backend function labels and unrooted writers are insufficient. The
    callback is proven by operand semantics before helper states are merged.
    """
    execution = facts if execution_facts is None else execution_facts
    rooted = {f.cpu_address: f for f in execution.values()}
    _, interiors, _ = _instruction_sets(facts)
    reads = {r.address & 0xFFFFFF for f in execution.values()
             if f.mnemonic.upper() != 'LEA' for r in f.references
             if r.reference_type.upper() == 'READ'
             or r.reference_type.upper() == 'DATA' and not f.operands.startswith('#')}
    result, helpers = {}, {}
    for lea in execution.values():
        if lea.mnemonic.upper() != 'LEA' or lea.flow_type.upper() != 'FALL_THROUGH':
            continue
        register = lea.operands.rsplit('|', 1)[-1].upper()
        if not re.fullmatch(r'A[0-6]', register):
            continue
        target = pc_displacement_target(lea)
        if target is None:
            match = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]\|' + register, lea.operands, re.I)
            if match:
                target = int(match[1], 0) & 0xFFFFFF
        if target is None:
            continue
        physical = target - image.header.rom_start
        if (target & 1 or target in reads or physical in interiors
                or not 0x200 <= physical <= len(image.data) - 2
                or image.data[physical:physical + 2] in {b'\0\0', b'\xff\xff'}):
            continue
        transfer = rooted.get(lea.cpu_address + lea.length)
        helper = _direct(transfer) if transfer else None
        if helper is None or helper not in rooted:
            continue
        key = helper, register
        if key not in helpers:
            helpers[key] = _executor(rooted, helper, register)
        call = helpers[key]
        if call is not None:
            result[target] = DecoderSeed(target, 'register_callback_parameter', 'proven',
                f'rooted LEA at {lea.cpu_address:06X}; direct helper {helper:06X} '
                f'preserves {register} until indirect execution at {call:06X}', lea.cpu_address)
    return tuple(result[t] for t in sorted(result))
