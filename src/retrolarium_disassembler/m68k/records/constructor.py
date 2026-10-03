"""Recover bounded ROM records passed to a fixed-pool callback constructor.

The record count and stride come from rooted machine instructions. A stored
callback and its executor must independently address the same counted RAM
pool and field. Only complete, balanced callee summaries may preserve the
ROM cursor and loop counter through constructor calls. No reference data,
game identifiers or known table addresses participate in discovery.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import re

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .m68k_seeds import DecoderSeed
from .m68k_abstract import _register_name, _register_list
from .m68k_callback_abi import _executed_fields
from .megadrive_pointers import _absolute_referenced_addresses, _instruction_sets
from .megadrive_symbols import pc_displacement_target


def _unsupported_frame_or_exception(fact):
    """Reject unsummarized exceptions and changes to the active stack bank.

    Immediate logical operations that affect only the five CCR flags leave
    supervisor, trace and interrupt-mask bits untouched. Some allocators use
    these to return carry without moving the stack or taking an exception.
    """
    base = fact.mnemonic.upper().split('.')[0]
    operands = fact.operands.upper().split('|')
    if base in {'PEA', 'LINK', 'UNLK', 'TRAP', 'TRAPV', 'STOP', 'RESET',
                'ILLEGAL', 'RTE', 'RTR', 'DIVU', 'DIVS', 'CHK', 'CHK2'}:
        return True
    if any(re.search(r'(?<![A-Z0-9])USP(?![A-Z0-9])', operand) for operand in operands):
        return True
    if operands[-1] != 'SR':
        return False
    immediate = re.fullmatch(r'#?(-?0X[0-9A-F]+)', operands[0])
    if len(operands) != 2 or immediate is None:
        return True
    mask = int(immediate[1], 0) & 0xffff
    return not (base in {'ORI', 'EORI'} and mask & 0xffe0 == 0
                or base == 'ANDI' and mask & 0xffe0 == 0xffe0)


def _writes(fact):
    operands = fact.operands.upper().split('|')
    base = fact.mnemonic.upper().split('.')[0]
    changed = set()
    for operand in operands:
        for item in re.findall(r'\((A[0-7]|SP)\)\+|-\((A[0-7]|SP)\)', operand):
            changed.add(_register_name(item[0] or item[1]))
    if base.startswith('DB') or base in {'LINK', 'UNLK'}:
        changed.add(_register_name(operands[0]))
    elif base == 'EXG':
        changed.update(_register_name(operand) for operand in operands)
    elif base == 'MOVEM' and operands[0].startswith('('):
        changed.update(_register_list(operands[-1]))
    elif base not in {'CMP', 'CMPA', 'CMPI', 'CMPM', 'TST', 'BTST'}:
        changed.add(_register_name(operands[-1]))
    return changed - {None}


def _successors(fact):
    base = fact.mnemonic.upper().split('.')[0]
    flow = fact.flow_type.upper()
    if flow == 'FALL_THROUGH':
        return (fact.cpu_address + fact.length,)
    if flow == 'CONDITIONAL_JUMP' and fact.flows:
        return (*fact.flows, fact.cpu_address + fact.length)
    if base in {'BRA', 'JMP'} and len(fact.flows) == 1 and flow != 'COMPUTED_JUMP':
        return fact.flows
    return ()


def _preserved_registers(facts, start, registers, *, cache=None, active=()):
    """All bounded, decoded RTS paths must leave a balanced stack.

    The returned set contains the argument registers left unchanged on every
    return. Nested direct callees may clobber them while a caller MOVEM save
    retains their original values; unknown calls and return-PC tricks reject.
    This uses the normal ABI assumption that a pre-existing address-register
    alias does not overwrite the caller's stack save area. Taking a new SP
    alias, arbitrary SP accesses and implicit stack frames are rejected.
    """
    registers = frozenset(registers)
    cache = {} if cache is None else cache
    key = start, registers
    if key in cache:
        return cache[key]
    if start in active or len(active) >= 4:
        return None
    pending = deque([(start, registers, ())])
    visited, returns = set(), []
    while pending and len(visited) < 512:
        address, original, stack = pending.popleft()
        state = address, original, stack
        if state in visited:
            continue
        visited.add(state)
        fact = facts.get(address)
        if fact is None:
            return None
        mnemonic = fact.mnemonic.upper()
        base = mnemonic.split('.')[0]
        operands = fact.operands.upper().split('|')
        if fact.raw == b'\x4e\x75':
            if stack:
                return None
            returns.append(original)
            continue
        if _unsupported_frame_or_exception(fact):
            return None
        if mnemonic == 'MOVEM.L' and operands[-1] == '-(SP)':
            saved = frozenset(_register_list(operands[0]))
            if 'a7' in saved or not saved:
                return None
            stack += ((saved, original & saved),)
        elif mnemonic == 'MOVEM.L' and operands[0] == '(SP)+':
            restored = frozenset(_register_list(operands[-1]))
            if not stack or stack[-1][0] != restored:
                return None
            original = (original - restored) | stack[-1][1]
            stack = stack[:-1]
        elif any(re.search(r'(?<![A-Z0-9])(?:SP|A7)[BWL]?(?![A-Z0-9])', o) for o in operands):
            return None
        else:
            original -= _writes(fact)
        if base in {'BSR', 'JSR'}:
            if fact.flow_type.upper() == 'COMPUTED_CALL' or len(fact.flows) != 1:
                return None
            child = _preserved_registers(facts, fact.flows[0], registers,
                        cache=cache, active=(*active, start))
            if child is None:
                return None
            original &= child
            successors = (address + fact.length,)
        else:
            successors = _successors(fact)
        if not successors:
            return None
        pending.extend((target, original, stack) for target in successors)
    if pending or not returns:
        return None
    result = frozenset.intersection(*returns)
    cache[key] = result
    return result


def _callback_parameter_stores(facts, start, register, fields):
    """Follow a callback parameter only until its first modification.

    Direct callees receive the parameter. A return from a callee is not
    assumed to retain it: only a store reached inside that callee witnesses
    consumption. All operand writes, including implicit register updates,
    use the same invalidation rules as register-preservation summaries.
    """
    pending = deque([(start, 0)])
    visited, stores = set(), set()
    while pending and len(visited) < 256:
        address, depth = pending.popleft()
        if (address, depth) in visited:
            continue
        visited.add((address, depth))
        fact = facts.get(address)
        if fact is None:
            continue
        if _unsupported_frame_or_exception(fact):
            continue
        match = re.fullmatch(register + r'\|\((?:(-?0x[0-9a-f]+),)?A[0-6]\)',fact.operands,re.I)
        if fact.mnemonic.upper() == 'MOVE.L' and match and int(match[1] or '0',0) in fields:
            stores.add(address)
        if register.lower() in _writes(fact):
            continue
        base = fact.mnemonic.upper().split('.')[0]
        if base in {'JSR','BSR'}:
            if depth < 3 and fact.flow_type.upper() != 'COMPUTED_CALL' and len(fact.flows) == 1:
                pending.append((fact.flows[0],depth+1))
            continue
        if base in {'PEA','LINK','UNLK','TRAP','TRAPV','RESET','STOP','ILLEGAL','RTE','RTR'}:
            continue
        pending.extend((successor,depth) for successor in _successors(fact))
    return stores


def _fixed_pool_at(image, facts, point, base):
    """Prove a field access ranges over a counted RAM pool.

    Follow both tests but decrement DBF concretely. Stop at the access, so an
    executor's unknown indirect call is never assumed to preserve its base.
    Later slots are witnessed through the loop's skip-empty-slot path.
    """
    results = set()
    for lea in facts.values():
        if not 0 <= point - lea.cpu_address <= 512 or lea.mnemonic.upper() != 'LEA':
            continue
        address = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]\|' + base, lea.operands, re.I)
        count_fact = facts.get(lea.cpu_address + lea.length)
        if address is None or count_fact is None:
            continue
        root = int(address[1], 0) & 0xffffff
        number = re.fullmatch(r'#?(0x[0-9a-f]+)\|D[0-7]w?', count_fact.operands, re.I)
        if (not image.header.ram_start <= root <= image.header.ram_end - 3
                or count_fact.mnemonic.upper() not in {'MOVE.W', 'MOVEQ'} or number is None):
            continue
        count = int(number[1], 0) + 1
        if not 2 <= count <= 256 or count_fact.mnemonic.upper() == 'MOVEQ' and count > 128:
            continue
        counter = _register_name(count_fact.operands.split('|')[-1])
        start = count_fact.cpu_address + count_fact.length
        pending = deque([(start, 0, count - 1)])
        visited, offsets, increments = set(), set(), set()
        while pending and len(visited) < 4096:
            state = pending.popleft()
            if state in visited:
                continue
            visited.add(state)
            current_address, offset, remaining = state
            if current_address == point:
                offsets.add(offset)
                continue
            current = facts.get(current_address)
            if current is None or not 0 <= offset <= 0x10000:
                continue
            if _unsupported_frame_or_exception(current):
                continue
            operation = current.mnemonic.upper()
            if operation in {'RTS', 'JSR', 'BSR.B', 'BSR.W', 'PEA', 'LINK', 'UNLK'}:
                continue
            if operation in {'DBF', 'DBRA'}:
                if (_register_name(current.operands.split('|')[0]) != counter
                        or current.flows != (start,) or remaining is None):
                    continue
                remaining = (remaining - 1) & 0xffff
                successors = current.flows if remaining != 0xffff else (current.cpu_address + current.length,)
            else:
                if counter in _writes(current):
                    remaining = None  # A successful allocation may reuse flags Dn.
                step = re.fullmatch(r'#(0x[0-9a-f]+)\|' + base, current.operands, re.I)
                if operation == 'ADDA.L' and step:
                    amount = int(step[1], 0)
                    if not 4 <= amount <= 0x400 or amount & 1:
                        continue
                    offset += amount
                    increments.add(amount)
                elif base in _writes(current):
                    continue
                successors = _successors(current)
            pending.extend((successor, offset, remaining) for successor in successors)
        if pending or len(increments) != 1:
            continue
        stride = next(iter(increments))
        if (offsets == set(range(0, count * stride, stride))
                and root + count * stride - 1 <= image.header.ram_end):
            results.add((root, count, stride))
    return results


def _callback_pools(image, facts):
    """Field width and physical slot identity supplement the callback ABI."""
    result = {}
    for load in facts.values():
        match = re.fullmatch(r'\((?:(-?0x[0-9a-f]+),)?(A[0-6])\)\|(A[0-6])',load.operands,re.I)
        call = facts.get(load.cpu_address + load.length)
        if (load.mnemonic.upper() != 'MOVEA.L' or match is None or call is None
                or call.mnemonic.upper() not in {'JSR', 'JMP'}
                or call.operands.upper() != '(' + match[3].upper() + ')'):
            continue
        field = int(match[1] or '0',0)
        for pool in _fixed_pool_at(image,facts,load.cpu_address,match[2].lower()):
            if 0 <= field <= pool[2]-4:
                result[(pool,field)] = call.cpu_address
    return result


@dataclass(frozen=True)
class ConstructorRecords:
    loop: int
    read: int
    allocator: int
    table: int
    count: int
    stride: int
    field: int
    callback_register: str
    base_register: str
    counter_register: str
    callback_stores: tuple[int, ...]
    pool: tuple[int, int, int]
    pool_field: int
    executor: int
    targets: tuple[int, ...]


def discover_constructor_record_tables(
    image: MegaDriveImage, facts: dict[int, InstructionFact], *, execution_facts=None,
) -> tuple[ConstructorRecords, ...]:
    """Return ROM table proofs, using only explicitly supplied rooted facts."""
    if execution_facts is None:
        return ()
    rooted = {f.cpu_address: f for f in execution_facts.values()}
    fields = _executed_fields(rooted)
    pools = _callback_pools(image, rooted)
    if not fields or not pools:
        return ()
    ends = {f.cpu_address + f.length: f for f in rooted.values()}
    occupied, interiors, _ = _instruction_sets(facts)
    data_addresses = _absolute_referenced_addresses(rooted)
    cache, results = {}, []
    for read in rooted.values():
        load = re.fullmatch(r'\((A[0-6])\)\+\|(A[0-6])', read.operands, re.I)
        if read.mnemonic.upper() != 'MOVEA.L' or not load or load[1].upper() == load[2].upper():
            continue
        base, callback = load[1].lower(), load[2].lower()
        count_fact = ends.get(read.cpu_address)
        lea = ends.get(count_fact.cpu_address) if count_fact else None
        if count_fact is None or lea is None or lea.mnemonic.upper() != 'LEA':
            continue
        counter = _register_name(count_fact.operands.split('|')[-1])
        number = re.fullmatch(r'#?(0x[0-9a-f]+)\|D[0-7][w]?', count_fact.operands, re.I)
        if (count_fact.mnemonic.upper() not in {'MOVE.W', 'MOVEQ'} or not number
                or not counter or not 0 <= int(number[1], 0) <= (127 if count_fact.mnemonic.upper() == 'MOVEQ' else 255)
                or lea.operands.split('|')[-1].lower() != base):
            continue
        table = pc_displacement_target(lea)
        absolute = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]\|' + base, lea.operands, re.I)
        if table is None and absolute:
            table = int(absolute[1], 0) & 0xffffff
        if table is None:
            continue
        count = int(number[1], 0) + 1
        call = rooted.get(read.cpu_address + read.length)
        if (call is None or call.mnemonic.upper().split('.')[0] not in {'JSR', 'BSR'}
                or call.flow_type.upper() == 'COMPUTED_CALL' or len(call.flows) != 1):
            continue
        stores = _callback_parameter_stores(rooted, call.flows[0], callback.upper(), fields)
        if not stores:
            continue
        identities = {}
        for store_address in stores:
            store = rooted[store_address]
            stored = re.fullmatch(r'A[0-6]\|\((?:(-?0x[0-9a-f]+),)?(A[0-6])\)',store.operands,re.I)
            if stored is None:
                continue
            field = int(stored[1] or '0',0)
            for pool in _fixed_pool_at(image,rooted,store_address,stored[2].lower()):
                if (pool,field) in pools:
                    identity = pool, field, pools[pool, field]
                    identities.setdefault(identity, set()).add(store_address)
        if len(identities) != 1:
            continue
        identity = next(iter(identities))
        stores = identities[identity]
        preserve = _preserved_registers(rooted, call.flows[0], {base, counter}, cache=cache)
        if preserve != {base, counter}:
            continue
        # Establish the finite loop boundary from its architectural DBF.
        body, cursor, last = {}, read.cpu_address, None
        for _ in range(64):
            current = rooted.get(cursor)
            if current is None:
                break
            body[cursor] = current
            if (current.mnemonic.upper() in {'DBF', 'DBRA'}
                    and _register_name(current.operands.split('|')[0]) == counter
                    and current.flows == (read.cpu_address,)):
                last = current
                break
            cursor += current.length
        if last is None:
            continue
        pending = deque([(read.cpu_address, 0)])
        visited, strides, invalid = set(), set(), False
        while pending and not invalid:
            address, offset = pending.popleft()
            if (address, offset) in visited:
                continue
            visited.add((address, offset))
            current = body.get(address)
            if current is None or len(visited) > 256:
                invalid = True
                break
            if _unsupported_frame_or_exception(current):
                invalid = True
                break
            if current is last:
                strides.add(offset)
                continue
            operands = current.operands.upper().split('|')
            base_op = current.mnemonic.upper().split('.')[0]
            if base_op in {'JSR', 'BSR'}:
                # The constructor is the only call and the callback pointer
                # is consumed before its register becomes the object result.
                if current is not call:
                    invalid = True
                    break
                successors = (address + current.length,)
            else:
                if counter in _writes(current):
                    invalid = True
                    break
                mentions = [o for o in operands if re.search(r'(?<![A-Z0-9])' + base.upper() + r'[BWL]?(?![A-Z0-9])', o)]
                if mentions:
                    width = {'MOVE.B': 1, 'MOVE.W': 2, 'MOVE.L': 4, 'MOVEA.L': 4}.get(current.mnemonic.upper())
                    # Only typed read-only postincrements of the ROM cursor;
                    # aliases, writes through it and arithmetic need a wider proof.
                    if (width is None or operands[0] != f'({base.upper()})+'
                            or len(mentions) != 1 or base in {_register_name(operands[-1])}):
                        invalid = True
                        break
                    offset += width
                elif base in _writes(current):
                    invalid = True
                    break
                successors = _successors(current)
                if not successors:
                    invalid = True
                    break
            for target in successors:
                if target in body:
                    if target <= address:  # No other loop within one record.
                        invalid = True
                        break
                    pending.append((target, offset))
                elif not (current.flow_type.upper() == 'CONDITIONAL_JUMP'
                          and (target < read.cpu_address or target > last.cpu_address)):
                    invalid = True
                    break
        if invalid or len(strides) != 1:
            continue
        stride = strides.pop()
        if not 4 <= stride <= 256 or stride & 1:
            continue
        physical = table - image.header.rom_start
        limit = physical + stride * count
        if not 0x200 <= physical < limit <= len(image.data) or any(a in occupied for a in range(physical, limit)):
            continue
        targets = tuple(int.from_bytes(image.data[a:a+4], 'big') for a in range(physical, limit, stride))
        if any(target & 1 or not 0x200 <= target - image.header.rom_start <= len(image.data)-2
               or target - image.header.rom_start in interiors or target in data_addresses
               or physical <= target - image.header.rom_start < limit
               or image.data[target-image.header.rom_start:target-image.header.rom_start+2] in {b'\x00\x00', b'\xff\xff'}
               for target in targets):
            continue
        results.append(ConstructorRecords(read.cpu_address, read.cpu_address, call.flows[0], table,
                        count, stride, 0, callback, base, counter, tuple(sorted(stores)), *identity, targets))
    return tuple(results)


def discover_constructor_record_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact], *, execution_facts=None,
) -> tuple[DecoderSeed, ...]:
    """Expose each constructor record's callback as an auditable decoder root."""
    seeds = {}
    for table in discover_constructor_record_tables(image, facts, execution_facts=execution_facts):
        pool_start, pool_count, pool_stride = table.pool
        stores = ','.join(f'{address:06X}' for address in table.callback_stores)
        evidence = (
            f'rooted constructor record loop {table.loop:06X}; ROM table {table.table:06X}, '
            f'{table.count} records, stride {table.stride}, longword field +{table.field}; '
            f'callee {table.allocator:06X} preserves {table.base_register.upper()} and '
            f'{table.counter_register.upper()} on every balanced return; '
            f'unchanged callback parameter {table.callback_register.upper()} stored at {stores}; '
            f'bounded store/executor paths share RAM pool {pool_start:06X}, '
            f'{pool_count} slots, stride {pool_stride}, callback field +{table.pool_field}; '
            f'indirect executor {table.executor:06X}'
        )
        for target in table.targets:
            seeds.setdefault(target, DecoderSeed(target, 'constructor_record_callback',
                                                'proven', evidence, table.read))
    return tuple(seeds[address] for address in sorted(seeds))
