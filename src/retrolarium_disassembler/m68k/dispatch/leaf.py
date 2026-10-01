"""Prove shared word-table dispatchers called with a LEA table argument."""
from __future__ import annotations

import re
from typing import Callable

from .facts import InstructionFact
from .m68k_seeds import DecoderSeed
from .megadrive import MegaDriveImage
from .megadrive_pointers import _absolute_referenced_addresses, _instruction_sets
from .megadrive_symbols import pc_displacement_target


def _direct(fact):
    """One direct call/jump; no conditional flow or computed backend guesses."""
    op = fact.mnemonic.upper().split('.', 1)[0]
    return (fact.flows[0] if len(fact.flows) == 1
            and op in {'JMP', 'JSR', 'BRA', 'BSR'}
            and fact.flow_type.upper() not in {'COMPUTED_JUMP', 'COMPUTED_CALL'} else None)


def _body(by_address, address):
    # A single JMP/BRA thunk is common, but do not follow arbitrary code.
    first = by_address.get(address)
    target = _direct(first) if first else None
    if target is not None and first.mnemonic.upper().split('.', 1)[0] in {'JMP', 'BRA'}:
        address = target
    result = []
    for _ in range(6):
        item = by_address.get(address)
        if item is None:
            return []
        result.append(item)
        if item.mnemonic.upper() == 'JMP' and item.flow_type.upper() == 'COMPUTED_JUMP':
            return result
        if item.flow_type.upper() != 'FALL_THROUGH':
            return []
        address += item.length
    return []


def _schema(body):
    """Exact leaf semantics: object word index * 2, then signed or absolute word."""
    absolute = len(body) == 6
    if len(body) not in {4, 6}:
        return None
    index = 1 if absolute else 0
    read = body[index]
    match = re.fullmatch(r'\((-?0x[0-9a-f]+),(A[0-6])\)\|(D[0-7])w', read.operands, re.I)
    if read.mnemonic.upper() != 'MOVE.W' or match is None:
        return None
    dr = match[3].upper()
    if absolute and (body[0].mnemonic.upper() != 'MOVEQ'
                     or body[0].operands.upper() not in {f'0X0|{dr}', f'#0X0|{dr}'}):
        return None
    add = body[index + 1]
    load = body[index + 2]
    if add.mnemonic.upper() != 'ADD.W' or add.operands.upper() != f'{dr}W|{dr}W':
        return None
    pointer = re.fullmatch(r'\(0x0,(A[0-6]),' + dr + r'w\*0x1\)\|(A[0-6]|' + dr + r'w)', load.operands, re.I)
    if pointer is None:
        return None
    ar = pointer[1].upper()
    # The table argument must survive the index read and multiplication.
    if absolute:
        convert = body[4]
        if (load.mnemonic.upper() != 'MOVE.W' or pointer[2].upper() != dr + 'W'
                or convert.mnemonic.upper() != 'MOVEA.L'
                or convert.operands.upper() != f'{dr}|{ar}'):
            return None
    elif load.mnemonic.upper() != 'ADDA.W' or pointer[2].upper() != ar:
        return None
    if body[-1].operands.upper() != f'({ar})':
        return None
    return ar, absolute


def discover_leaf_word_dispatch_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
    *, handler_validator: Callable[[int], bool] | None = None,
) -> tuple[DecoderSeed, ...]:
    """LEA / direct transfer to a proven shared table dispatcher.

    The executed leaf proves slots are data, even if the backend decoded them.
    Targets cannot overlap instructions. Arrays stop at explicit data references
    or the first forward handler. An array ending exactly at its first handler
    is bounded by that handler; other layouts need an existing code witness.
    """
    by_address = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    origin, data = image.header.rom_start, image.data
    metadata = None
    schemas = {}
    result = {}
    for lea in facts.values():
        if lea.mnemonic.upper() != 'LEA' or lea.flow_type.upper() != 'FALL_THROUGH':
            continue
        caller = by_address.get(lea.cpu_address + lea.length)
        address = _direct(caller) if caller else None
        inline = False
        if address is not None:
            if address not in schemas:
                body = _body(by_address, address)
                schemas[address] = (_schema(body), body)
            schema, body = schemas[address]
            if schema is None:
                continue
            ar, absolute = schema
        else:
            # Inline variant: index was doubled immediately before LEA,
            # then ADDA.W (base,index),base / JMP or JSR (base).
            pointer = re.fullmatch(r'\(0x0,(A[0-6]),(D[0-7])w\*0x1\)\|\1',
                                   caller.operands, re.I) if caller else None
            previous = ends.get(lea.cpu_address)
            call = by_address.get(caller.cpu_address + caller.length) if caller else None
            if (pointer is None or caller.mnemonic.upper() != 'ADDA.W'
                    or caller.flow_type.upper() != 'FALL_THROUGH'
                    or previous is None or previous.mnemonic.upper() != 'ADD.W'
                    or previous.flow_type.upper() != 'FALL_THROUGH'
                    or previous.operands.upper() != f'{pointer[2].upper()}W|{pointer[2].upper()}W'
                    or call is None or call.mnemonic.upper() not in {'JMP','JSR'}
                    or call.operands.upper() != f'({pointer[1].upper()})'
                    or call.flow_type.upper() not in {'COMPUTED_JUMP','COMPUTED_CALL'}):
                continue
            ar, absolute, inline = pointer[1].upper(), False, True
        if lea.operands.rsplit('|', 1)[-1].upper() != ar:
            continue
        table = pc_displacement_target(lea)
        match = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]', lea.operands.split('|')[0], re.I)
        if table is None and match:
            table = int(match[1], 0) & 0xFFFFFF
        if table is None:
            continue
        if metadata is None:
            _, interiors, starts = _instruction_sets(facts)
            metadata = interiors, starts, _absolute_referenced_addresses(facts)
        interiors, starts, boundaries = metadata
        start, at = table - origin, table - origin
        limit = min(len(data), start + 512)
        targets, slots = [], 0
        while 0x200 <= at and at + 2 <= limit and not at & 1:
            if slots and origin + at in boundaries:
                break
            value = int.from_bytes(data[at:at + 2], 'big', signed=not absolute)
            target = value if absolute else table + value
            physical = target - origin
            if (target & 1 or not 0x200 <= physical <= len(data) - 2
                    or start <= physical < at + 2
                    or data[physical:physical + 2] in {b'\0\0', b'\xff\xff'}):
                break
            if physical not in interiors:
                targets.append(target)
            slots += 1
            if physical > at:
                limit = min(limit, physical)
            at += 2
        bounded_by_handler = at == limit and origin + limit in targets
        witness = None
        if slots >= 2 and not (bounded_by_handler or set(targets) & starts) and handler_validator:
            witness = next((target for target in targets if handler_validator(target)), None)
        if slots < 2 or not (bounded_by_handler or set(targets) & starts or witness is not None):
            continue
        for target in targets:
            evidence = (f'LEA table {table:06X}; word index doubled at {previous.cpu_address:06X}; '
                        f'ADDA.W indexed table word to {ar} and call {call.cpu_address:06X}' if inline else
                        f'LEA table {table:06X}; transfer {caller.cpu_address:06X} to leaf '
                        f'{body[0].cpu_address:06X} doubles object word index and jumps via '
                        f'{"zero-extended absolute" if absolute else "signed table-relative"} word in {ar}')
            if witness is not None:
                evidence += f'; handler {witness:06X} has a complete bounded CFG connected to rooted code'
            result[target] = DecoderSeed(target, 'inline_word_dispatch' if inline else 'leaf_word_dispatch',
                                        'proven', evidence, lea.cpu_address)
    return tuple(result[key] for key in sorted(result))
