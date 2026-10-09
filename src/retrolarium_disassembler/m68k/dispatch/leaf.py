"""Prove shared word-table dispatchers called with a LEA table argument."""
from __future__ import annotations

import re
from typing import Callable

from retrolarium_kit.facts import InstructionFact
from retrolarium_kit.m68k_seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_kit.megadrive_pointers import _absolute_referenced_addresses, _instruction_sets
from retrolarium_kit.megadrive_symbols import pc_displacement_target


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
    """Prove the word's extension and its addition to the unchanged table base."""
    zeroed = len(body) == 6
    if len(body) not in {3, 4, 6}:
        return None
    index = 1 if zeroed else 0
    if len(body) == 3:
        # A second entry point may receive the index directly from the caller.
        match = re.fullmatch(r'(D[0-7])w\|\1w', body[0].operands, re.I)
        if match is None:
            return None
        dr = match[1].upper()
    else:
        read = body[index]
        match = re.fullmatch(r'\((-?0x[0-9a-f]+),(A[0-6])\)\|(D[0-7])w', read.operands, re.I)
        if read.mnemonic.upper() != 'MOVE.W' or match is None:
            return None
        dr = match[3].upper()
        index += 1
    if zeroed and (body[0].mnemonic.upper() != 'MOVEQ'
                     or body[0].operands.upper() not in {f'0X0|{dr}', f'#0X0|{dr}'}):
        return None
    add = body[index]
    load = body[index + 1]
    if add.mnemonic.upper() != 'ADD.W' or add.operands.upper() != f'{dr}W|{dr}W':
        return None
    pointer = re.fullmatch(r'\(0x0,(A[0-6]),' + dr + r'w\*0x1\)\|(A[0-6]|' + dr + r'w)', load.operands, re.I)
    if pointer is None:
        return None
    ar = pointer[1].upper()
    # The table argument must survive the index read and multiplication.
    mode = 'signed table-relative'
    if zeroed:
        convert = body[4]
        if (load.mnemonic.upper() != 'MOVE.W' or pointer[2].upper() != dr + 'W'
                or convert.mnemonic.upper() not in {'MOVEA.L', 'ADDA.L'}
                or convert.operands.upper() != f'{dr}|{ar}'):
            return None
        # MOVE.W preserves Dn's high half. MOVEQ #0 above is required before
        # interpreting ADDA.L as addition of an unsigned table-relative word.
        mode = ('zero-extended absolute' if convert.mnemonic.upper() == 'MOVEA.L'
                else 'zero-extended table-relative')
        jump_operand = f'({ar})'
    elif load.mnemonic.upper() == 'ADDA.W' and pointer[2].upper() == ar:
        jump_operand = f'({ar})'
    elif load.mnemonic.upper() == 'MOVE.W' and pointer[2].upper() == dr + 'W':
        # The .W index in the effective address is sign-extended by the CPU;
        # the remaining high half of Dn cannot affect this jump.
        jump_operand = f'(0X0,{ar},{dr}W*0X1)'
    else:
        return None
    if body[-1].operands.upper() != jump_operand:
        return None
    return ar, mode


def _inline_body(by_address, ends, lea):
    """Collect an adjacent scale / word reader / computed transfer only."""
    following = by_address.get(lea.cpu_address + lea.length)
    if following is None:
        return []
    if following.mnemonic.upper() == 'ADD.W':
        scale = following
        load = by_address.get(scale.cpu_address + scale.length)
    elif following.mnemonic.upper() == 'ADDA.W':
        # Existing spelling puts ADD.W before LEA, which preserves Dn.
        scale, load = ends.get(lea.cpu_address), following
    else:
        return []
    call = by_address.get(load.cpu_address + load.length) if load else None
    if (scale is None or load is None or call is None
            or any(f.flow_type.upper() != 'FALL_THROUGH' for f in (scale, load))
            or call.mnemonic.upper() not in {'JMP', 'JSR'}
            or call.flow_type.upper() not in {'COMPUTED_JUMP', 'COMPUTED_CALL'}):
        return []
    return [scale, load, call]


def discover_leaf_word_dispatch_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
    *, handler_validator: Callable[[int], bool] | None = None, entrypoints=(),
) -> tuple[DecoderSeed, ...]:
    """LEA / direct transfer to a proven shared table dispatcher.

    The executed leaf proves slots are data, even if the backend decoded them.
    Targets cannot overlap instructions. Arrays stop at explicit data references
    or the first forward handler. Those bounds only constrain the scan: adjacent
    data can still look like offsets, so every unknown target needs its own CFG
    witness rather than inheriting validity from one decoded neighbour.
    """
    by_address = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    origin, data = image.header.rom_start, image.data
    metadata = None
    masks_before = None
    validated = {}
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
            ar, mode = schema
        else:
            body = _inline_body(by_address, ends, lea)
            schema = _schema(body)
            if schema is None:
                continue
            ar, mode = schema
            inline = True
        if lea.operands.rsplit('|', 1)[-1].upper() != ar:
            continue
        table = pc_displacement_target(lea)
        match = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]', lea.operands.split('|')[0], re.I)
        if table is None and match:
            table = int(match[1], 0) & 0xFFFFFF
        if table is None:
            continue
        masks = None
        if len(body) == 3:
            if masks_before is None:
                from retrolarium_kit.m68k_reaching_dispatch import make_word_index_mask_reader
                masks_before = make_word_index_mask_reader(facts, entrypoints=(
                    *entrypoints, *(vector.address for vector in image.vector_table[1:])))
            register = body[0].operands.split('|')[0][:-1].lower()
            # This leaf entry consumes the caller's index directly. For a
            # shared dispatcher inspect its caller, not every unrelated caller
            # of that same leaf. Longer schemas replace Dn with a memory read.
            masks = masks_before(body[0].cpu_address if inline else caller.cpu_address, register)
        if metadata is None:
            _, interiors, starts = _instruction_sets(facts)
            metadata = interiors, starts, _absolute_referenced_addresses(facts)
        interiors, starts, boundaries = metadata
        start, at = table - origin, table - origin
        limit = min(len(data), start + 512)
        if masks:
            limit = min(limit, start + 2 * (max(masks) + 1))
        targets, slots = [], 0
        while 0x200 <= at and at + 2 <= limit and not at & 1:
            if (slots and origin + at in boundaries) or origin + at + 1 in boundaries:
                break
            index = (at - start) // 2
            if masks and not any(index & ~mask == 0 for mask in masks):
                at += 2
                continue
            value = int.from_bytes(data[at:at + 2], 'big', signed=mode == 'signed table-relative')
            target = value if mode == 'zero-extended absolute' else table + value
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
        if slots < 2:
            continue
        for target in targets:
            if target not in starts:
                if target not in validated:
                    validated[target] = bool(handler_validator and handler_validator(target))
                if not validated[target]:
                    continue
            evidence = (f'LEA table {table:06X}; word index doubled at {body[0].cpu_address:06X}; '
                        f'{body[1].mnemonic} indexed table word and {mode} '
                        f'{body[-1].mnemonic} at {body[-1].cpu_address:06X}' if inline else
                        f'LEA table {table:06X}; transfer {caller.cpu_address:06X} to leaf '
                        f'{body[0].cpu_address:06X} doubles word index and jumps via '
                        f'{mode} word in {ar}')
            if target not in starts:
                evidence += f'; handler {target:06X} has a complete bounded CFG witness'
            if masks:
                evidence += f'; word index restricted by incoming ANDI.W masks {sorted(masks)}'
            result[target] = DecoderSeed(target, 'inline_word_dispatch' if inline else 'leaf_word_dispatch',
                                        'proven', evidence, lea.cpu_address)
    return tuple(result[key] for key in sorted(result))
