"""High-confidence state-zero entries from a scoped cleared-record lifecycle.

Only a matching allocator, counted executor, type callback table, clearing ABI
and producer may qualify a state slot. This is a lifecycle heuristic over the
supplied rooted code, not a proof of whole-game reachability. It never grows a
table past its positively identified slot or uses a reference disassembly.
"""
from collections import defaultdict, deque
from dataclasses import dataclass
import re

from retrolarium_disasm.m68k.abstract import OrphanCandidate, _register_list
from retrolarium_disasm.m68k.records.constructor import _writes, _unsupported_frame_or_exception
from retrolarium_disasm.m68k.frames.call_frame import _STACK
from retrolarium_disasm.m68k.dispatch.closure import logical_image, make_dispatch_closure_validator, _balanced_body
from retrolarium_disasm.m68k.dispatch.leaf import _body, _schema
from retrolarium_disasm.m68k.records.packed import _complete_cfg
from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_disasm.megadrive.pointers import _absolute_referenced_addresses
from retrolarium_disasm.megadrive.symbols import pc_displacement_target, pc_indexed_target


def _field(text):
    match = re.fullmatch(r'\((?:(-?0x[0-9a-f]+),)?(A[0-6])\)', text, re.I)
    return (int(match[1] or '0', 0), match[2].upper()) if match else None


def _constant(fact):
    if fact is None or fact.mnemonic.upper() not in {'MOVEQ', 'MOVE.W', 'MOVE.L'}:
        return None
    match = re.fullmatch(r'#?(-?0x[0-9a-f]+)\|(D[0-7])[wl]?', fact.operands, re.I)
    return (int(match[1], 0), match[2].upper()) if match else None


def _long_zero(fact, register):
    return (fact.mnemonic.upper() in {'MOVEQ', 'MOVE.L'}
            and _constant(fact) == (0, register))


def _lea(fact):
    if fact is None or fact.mnemonic.upper() != 'LEA':
        return None
    register = fact.operands.split('|')[-1].upper()
    target = pc_displacement_target(fact)
    if target is not None:
        return target, register
    match = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]\|(A[0-6])', fact.operands, re.I)
    return (int(match[1], 0) & 0xffffff, match[2].upper()) if match else None


def _direct(fact):
    if fact is None or len(fact.flows) != 1 or fact.flow_type.upper().startswith('COMPUTED'):
        return None
    if fact.mnemonic.upper().split('.')[0] not in {'JSR', 'BSR', 'JMP', 'BRA'}:
        return None
    return fact.flows[0] & 0xffffff


def _call(fact):
    return fact.mnemonic.upper().split('.')[0] in {'JSR', 'BSR'}


def _step(fact, register):
    match = re.fullmatch(r'\((0x[0-9a-f]+),' + register + r'\)\|' + register,
                        fact.operands, re.I)
    return int(match[1], 0) if fact.mnemonic.upper() == 'LEA' and match else None


def _straight(*facts):
    return all(f.flow_type.upper() == 'FALL_THROUGH' and not f.flows for f in facts)


def _successors(fact):
    op, following = fact.mnemonic.upper().split('.')[0], fact.cpu_address + fact.length
    if op == 'RTS':
        return ()
    if op in {'JMP', 'BRA'}:
        target = _direct(fact)
        return (target,) if target is not None else None
    if fact.flow_type.upper() == 'CONDITIONAL_JUMP' and fact.flows:
        return (*[a & 0xffffff for a in fact.flows], following)
    if fact.flow_type.upper() == 'FALL_THROUGH' or _call(fact):
        return (following,)
    return None


def _escapes_pointer(fact, register):
    fields = fact.operands.upper().split('|')
    if len(fields) != 2:
        return False
    # A copied pointer, including a truncated copy, can later alias the pool.
    if re.fullmatch(register + r'[BWL]?', fields[0]):
        return True
    return (fact.mnemonic.upper() == 'LEA'
            and re.search(r'(?<![A-Z0-9])' + register + r'(?![A-Z0-9])', fields[0]) is not None)


@dataclass(frozen=True)
class _Pool:
    allocator: int
    base: int
    count: int
    stride: int
    register: str
    type_offset: int


@dataclass(frozen=True)
class _Executor:
    entry: int
    selector: int
    register: str
    table: int
    flag_offset: int
    flag_bit: int
    clear: int


class _Model:
    def __init__(self, image, facts, render):
        self.image, self.render = image, render
        self.facts = {f.cpu_address: f for f in facts.values()}
        self.checked = {}

    def fact(self, address):
        if address not in self.checked:
            fact = self.facts.get(address)
            offset = address - self.image.header.rom_start
            valid = (fact is not None and offset >= 0 and address % 2 == 0
                     and fact.physical_offset == offset and 2 <= fact.length <= 10
                     and fact.length % 2 == 0 and len(fact.raw) == fact.length
                     and self.image.data[offset:offset + fact.length] == fact.raw
                     and self.render(fact) is not None)
            self.checked[address] = fact if valid else None
        return self.checked[address]

    def take(self, address, count):
        result = []
        for _ in range(count):
            fact = self.fact(address)
            if fact is None:
                return []
            result.append(fact)
            address += fact.length
        return result

    def pools(self):
        for first in self.facts.values():
            base = _lea(first)
            if base is None:
                continue
            code = self.take(first.cpu_address, 7)
            if not code:
                continue
            lea, count, test, branch, step, loop, end = code
            number = _constant(count)
            field = _field(test.operands)
            stride = _step(step, base[1])
            if (not _straight(lea, count, test, step)
                    or number is None or not 1 <= number[0] < 256 or field is None
                    or field[1] != base[1] or test.mnemonic.upper() != 'TST.W'
                    or branch.mnemonic.upper() not in {'BEQ.B', 'BEQ.W'}
                    or branch.flows != (end.cpu_address,) or stride is None
                    or not 4 <= stride <= 256 or not 0 <= field[0] <= stride - 2
                    or loop.mnemonic.upper() not in {'DBF', 'DBRA'}
                    or loop.operands.split('|')[0].upper() != number[1] + 'W'
                    or loop.flows != (test.cpu_address,) or end.raw != b'\x4e\x75'
                    or not self.image.header.ram_start <= base[0]
                    or base[0] + (number[0] + 1) * stride - 1 > self.image.header.ram_end):
                continue
            yield _Pool(lea.cpu_address, base[0], number[0] + 1, stride, base[1], field[0])

    def clearing_helpers(self, pool):
        helpers = {}
        for first in self.facts.values():
            match = re.fullmatch(r'(D[0-7])\|\((' + pool.register + r')\)\+', first.operands, re.I)
            if first.mnemonic.upper() != 'MOVE.L' or match is None or pool.stride % 4:
                continue
            code = self.take(first.cpu_address, pool.stride // 4 + 1)
            if (code and code[-1].raw == b'\x4e\x75'
                    and all(_straight(f) and f.mnemonic.upper() == 'MOVE.L' and f.operands.upper() == first.operands.upper()
                            for f in code[:-1])):
                helpers[first.cpu_address] = match[1].upper()
        return helpers

    def pool_clear(self, pool, helpers):
        for first in self.facts.values():
            if _lea(first) != (pool.base, pool.register):
                continue
            code = self.take(first.cpu_address, 6)
            if not code:
                continue
            _, zero, count, call, loop, end = code
            helper, number = _direct(call), _constant(count)
            if (_straight(code[0], zero, count) and helper in helpers
                    and _call(call) and _long_zero(zero, helpers[helper])
                    and number and number[0] + 1 == pool.count and number[1] != helpers[helper]
                    and loop.mnemonic.upper() in {'DBF', 'DBRA'}
                    and loop.operands.split('|')[0].upper() == number[1] + 'W'
                    and loop.flows == (call.cpu_address,) and end.raw == b'\x4e\x75'):
                return first.cpu_address
        return None

    def executor(self, pool, helpers):
        for first in self.facts.values():
            base = _lea(first)
            if base is None or base[0] != pool.base:
                continue
            call = self.fact(first.cpu_address + first.length)
            target = _direct(call)
            if call is None or not _call(call) or target is None:
                continue
            code = self.take(target, 9)
            if not code:
                continue
            count, read, branch, save, select, restore, step, loop, end = code
            number = _constant(count)
            fields = read.operands.split('|')
            register = base[1]
            if (not _straight(first, count, read, save, restore, step)
                    or number is None or number[0] + 1 != pool.count or len(fields) != 2
                    or read.mnemonic.upper() != 'MOVE.W'
                    or _field(fields[0]) != (pool.type_offset, register)
                    or not re.fullmatch(r'D[0-7]w', fields[1], re.I) or fields[1].upper() == number[1] + 'W'
                    or branch.mnemonic.upper() not in {'BEQ.B', 'BEQ.W'}
                    or branch.flows != (step.cpu_address,)
                    or save.mnemonic.upper() != 'MOVEM.L' or restore.mnemonic.upper() != 'MOVEM.L'
                    or not save.operands.upper().endswith('|-(SP)')
                    or not restore.operands.upper().startswith('(SP)+|')
                    or set(_register_list(save.operands.split('|')[0])) != {register.lower(), number[1].lower()}
                    or set(_register_list(restore.operands.split('|')[-1])) != {register.lower(), number[1].lower()}
                    or not _call(select) or _direct(select) is None
                    or _step(step, register) != pool.stride or loop.flows != (read.cpu_address,)
                    or loop.mnemonic.upper() not in {'DBF', 'DBRA'}
                    or loop.operands.split('|')[0].upper() != number[1] + 'W'
                    or end.raw != b'\x4e\x75'):
                continue
            selector = self.take(_direct(select), 8)
            if not selector:
                continue
            add1, add2, load, invoke, flag, skip, cleanup, ret = selector
            index = fields[1].upper()
            indexed = pc_indexed_target(load)
            bit = re.fullmatch(r'#(0x[0-9a-f]+)\|(.+)', flag.operands, re.I)
            clear = self.take(_direct(cleanup), 3) if _direct(cleanup) is not None else []
            if (not _straight(add1, add2, load, flag)
                    or any(f.mnemonic.upper() != 'ADD.W' or f.operands.upper() != f'{index}|{index}' for f in (add1, add2))
                    or indexed is None or indexed[1:] != (int(index[1]), 'd', 'w')
                    or load.mnemonic.upper() != 'MOVEA.L' or invoke.mnemonic.upper() != 'JSR'
                    or load.operands.split('|')[-1].upper() == register
                    or invoke.operands.upper() != '(' + load.operands.split('|')[-1].upper() + ')'
                    or invoke.flow_type.upper() != 'COMPUTED_CALL'
                    or flag.mnemonic.upper() != 'BTST.B' or bit is None or not 0 <= int(bit[1], 0) <= 7
                    or _field(bit[2]) is None or _field(bit[2])[1] != register
                    or not 0 <= _field(bit[2])[0] < pool.stride
                    or skip.mnemonic.upper() not in {'BEQ.B', 'BEQ.W'} or skip.flows != (ret.cpu_address,)
                    or ret.raw != b'\x4e\x75' or not _call(cleanup) or not clear):
                continue
            move, zero, tail = clear
            helper = _direct(tail)
            if (not _straight(move, zero)
                    or move.mnemonic.upper() != 'MOVEA.L' or move.operands.upper() != register + '|' + pool.register
                    or helper not in helpers or not _long_zero(zero, helpers[helper])
                    or tail.mnemonic.upper().split('.')[0] not in {'BRA', 'JMP'}):
                continue
            yield _Executor(first.cpu_address, selector[0].cpu_address, register,
                            indexed[0], _field(bit[2])[0], int(bit[1], 0), move.cpu_address)

    def state_dispatch(self, callback, register):
        code = self.take(callback, 2)
        if not code:
            return None
        table = _lea(code[0])
        target = _direct(code[1])
        if (not _straight(code[0]) or table is None or table[1] == register or target is None
                or code[1].mnemonic.upper().split('.')[0] not in {'BRA', 'JMP'}):
            return None
        body = _body(self.facts, target)
        if len(body) != 4 or any(self.fact(f.cpu_address) is None for f in body):
            return None
        schema = _schema(body)
        field = _field(body[0].operands.split('|')[0])
        if schema != (table[1], 'signed table-relative') or field is None or field[1] != register:
            return None
        return table[0], field[0], body[-1].cpu_address

    def read(self, address, width):
        offset = address - self.image.header.rom_start
        return (self.image.data[offset:offset + width]
                if 0 <= offset <= len(self.image.data) - width else None)


def _write(fact):
    """A memory destination and width; read-only operations are not writes."""
    op, fields = fact.mnemonic.upper(), fact.operands.split('|')
    if op.split('.')[0] in {'CMP', 'CMPA', 'CMPI', 'CMPM', 'TST', 'BTST', 'LEA', 'JSR', 'JMP'}:
        return None
    destination = _field(fields[-1])
    if destination is None:
        return None
    width = {'.B': 1, '.W': 2, '.L': 4}.get(op[-2:], 1 if op in {'ST', 'SF'} else None)
    return (destination, width, fields[0]) if width is not None else (destination, 0, '')


def _producer_paths(model, pool, executor, allocator_call):
    """Follow the allocator's success branch and complete local constructors."""
    branch = model.fact(allocator_call.cpu_address + allocator_call.length)
    if branch is None or branch.mnemonic.upper() not in {'BNE.B', 'BNE.W'}:
        return ()
    pending = deque([(branch.cpu_address + branch.length, (), frozenset(range(pool.stride)), None)])
    seen, results = set(), set()
    while pending and len(seen) < 512:
        address, returns, zero, published = pending.popleft()
        state = address, returns, zero, published
        if state in seen:
            continue
        seen.add(state)
        fact = model.fact(address)
        if fact is None or pool.register.lower() in _writes(fact):
            continue
        if fact.raw == b'\x4e\x75':
            if returns:
                pending.append((returns[-1], returns[:-1], zero, published))
            elif published is not None:
                value, writer = published
                pointer = model.read(executor.table + 4 * value, 4)
                schema = model.state_dispatch(int.from_bytes(pointer, 'big'), executor.register) if pointer else None
                if schema and {schema[1], schema[1] + 1} <= zero:
                    results.add((value, writer, *schema))
            continue
        if _unsupported_frame_or_exception(fact) or _STACK.search(fact.operands):
            continue
        if _call(fact):
            target = _direct(fact)
            if target is not None and target != pool.allocator and len(returns) < 4:
                pending.append((target, (*returns, address + fact.length), zero, published))
            continue
        fields = fact.operands.upper().split('|')
        # Escaped aliases cannot prove that later writes preserve this record.
        if _escapes_pointer(fact, pool.register):
            continue
        write = _write(fact)
        if write:
            (offset, register), width, value = write
            if register != pool.register or width == 0 or not 0 <= offset <= pool.stride - width:
                continue
            changed = set(range(offset, offset + width))
            zero = zero - changed
            constant = re.fullmatch(r'#(-?0x[0-9a-f]+)', value, re.I)
            if fact.mnemonic.upper().startswith('CLR.'):
                zero |= changed
            elif constant and fact.mnemonic.upper().startswith('MOVE.'):
                number = int(constant[1], 0) & ((1 << (8 * width)) - 1)
                zero |= {offset + i for i, byte in enumerate(number.to_bytes(width, 'big')) if byte == 0}
                if offset == pool.type_offset and width == 2 and 0 < number < 256:
                    published = number, address
            if changed & set(range(pool.type_offset, pool.type_offset + 2)):
                if not (constant and fact.mnemonic.upper() == 'MOVE.W' and offset == pool.type_offset
                        and 0 < int(constant[1], 0) < 256):
                    published = None
        else:
            destination = fields[-1]
            if '(' in destination and not fact.mnemonic.upper().startswith(('CMP', 'TST', 'BTST', 'LEA', 'JMP')):
                absolute = re.fullmatch(r'\((-?0X[0-9A-F]+)\)\.[WL]', destination)
                if absolute is None or pool.base - 3 <= (int(absolute[1], 0) & 0xffffff) < pool.base + pool.count * pool.stride:
                    continue
        successors = _successors(fact)
        if successors is not None:
            pending.extend((a, returns, frozenset(zero), published) for a in successors)
    return tuple(results) if not pending else ()


def _flagged_return(model, start, pool, executor, initially_flagged):
    """All local paths preserve the record and return with deletion marked."""
    pending, seen, returns = deque([(start, initially_flagged)]), set(), 0
    while pending and len(seen) < 512:
        address, flagged = pending.popleft()
        if (address, flagged) in seen:
            continue
        seen.add((address, flagged))
        fact = model.fact(address)
        if fact is None or _call(fact) or executor.register.lower() in _writes(fact):
            return False
        if fact.raw == b'\x4e\x75':
            if not flagged:
                return False
            returns += 1
            continue
        if (_unsupported_frame_or_exception(fact) or _STACK.search(fact.operands)
                or _escapes_pointer(fact, executor.register)):
            return False
        write = _write(fact)
        if write:
            (offset, register), width, _ = write
            if (register != executor.register or width == 0
                    or not 0 <= offset <= pool.stride - width):
                return False  # An untracked alias could erase the deletion mark.
            if register == executor.register and offset <= executor.flag_offset < offset + width:
                bit = re.fullmatch(r'#(0x[0-9a-f]+)\|(.+)', fact.operands, re.I)
                if bit and int(bit[1], 0) == executor.flag_bit and fact.mnemonic.upper() == 'BSET.B':
                    flagged = True
                else:
                    return False
        else:
            destination = fact.operands.upper().split('|')[-1]
            if '(' in destination and not fact.mnemonic.upper().startswith(('CMP', 'TST', 'BTST', 'LEA', 'JMP')):
                absolute = re.fullmatch(r'\((-?0X[0-9A-F]+)\)\.[WL]', destination)
                if absolute is None or pool.base - 3 <= (int(absolute[1], 0) & 0xffffff) < pool.base + pool.count * pool.stride:
                    return False
        successors = _successors(fact)
        if successors is None:
            return False
        pending.extend((a, flagged) for a in successors)
    return bool(returns) and not pending


def _lifecycle(model, pool, executor, producers):
    """Associate temporary free marks and return continuations with callbacks."""
    entries = set()
    for _, _, table, _, _ in producers:
        # Ownership needs only already-rooted state handlers. The first
        # forward entry bounds these small word arrays; it never seeds code.
        first = model.read(table, 2)
        if first is None:
            return False, 'state table bytes unavailable'
        end = table + int.from_bytes(first, 'big', signed=True)
        if not table + 2 <= end <= table + 512:
            return False, 'state table ownership boundary unavailable'
        for address in range(table, end, 2):
            raw = model.read(address, 2)
            if raw is None:
                return False, 'state table ownership bytes unavailable'
            target = table + int.from_bytes(raw, 'big', signed=True)
            if target in model.facts:
                entries.add(target)
    owned, pending = set(), deque(entries)
    while pending and len(owned) < 4096:
        address = pending.popleft()
        if address in owned:
            continue
        fact = model.fact(address)
        if fact is None:
            continue
        owned.add(address)
        nexts = _successors(fact)
        if nexts is not None:
            pending.extend(nexts)
        if _call(fact) and _direct(fact) is not None:
            pending.append(_direct(fact))
    if pending:
        return False, 'callback ownership budget exhausted'
    reverse = defaultdict(set)
    calls = []
    for fact in model.facts.values():
        nexts = _successors(fact)
        if nexts is not None:
            for target in nexts:
                reverse[target].add(fact.cpu_address)
        if _call(fact) and _direct(fact) is not None:
            calls.append(fact)
    zero_sites = []
    for fact in model.facts.values():
        write = _write(fact)
        if not write:
            base = fact.mnemonic.upper().split('.')[0]
            destination = fact.operands.upper().split('|')[-1]
            if (fact.cpu_address in owned and '(' in destination
                    and base not in {'CMP', 'CMPA', 'CMPI', 'CMPM', 'TST', 'BTST', 'LEA', 'JSR', 'JMP'}):
                absolute = re.fullmatch(r'\((-?0X[0-9A-F]+)\)\.[WL]', destination)
                if (re.search(r'(?<![A-Z0-9])' + executor.register + r'(?![A-Z0-9])', destination)
                        or absolute and pool.base - 3 <= (int(absolute[1], 0) & 0xffffff) < pool.base + pool.count * pool.stride):
                    return False, f'unsupported object write {fact.cpu_address:06X}'
            continue
        (offset, register), width, value = write
        if (fact.cpu_address in owned and register == executor.register
                and (not width or not 0 <= offset <= pool.stride - width)):
            return False, f'object write crosses record boundary {fact.cpu_address:06X}'
        if (register == executor.register and width
                and offset < pool.type_offset + 2 and offset + width > pool.type_offset):
            # A low-byte clear frees any published type 1..255. Unknown and
            # partial writes can also free a record, so they need the same
            # guarded cleanup path as an explicit whole-word zero store.
            immediate = re.fullmatch(r'#(-?0x[0-9a-f]+)', value, re.I)
            positive = (fact.mnemonic.upper() == 'MOVE.W' and width == 2
                        and offset == pool.type_offset and immediate
                        and 0 < int(immediate[1], 0) < 256)
            if not positive:
                zero_sites.append(fact.cpu_address)
    for zero in zero_sites:
        if zero not in owned or not _flagged_return(model, zero, pool, executor, False):
            return False, f'unproven temporary-free path {zero:06X}'
        ancestors, queue = set(), deque([zero])
        while queue and len(ancestors) < 4096:
            address = queue.popleft()
            if address in ancestors:
                continue
            ancestors.add(address)
            queue.extend(reverse[address])
        if queue:
            return False, 'temporary-free predecessor budget exhausted'
        checked = set()
        for _ in range(8):
            parents = [c for c in calls if _direct(c) in ancestors and c.cpu_address not in checked]
            if not parents:
                break
            for call in parents:
                checked.add(call.cpu_address)
                if call.cpu_address not in owned or not _flagged_return(
                        model, call.cpu_address + call.length, pool, executor, True):
                    return False, f'unproven delete continuation {call.cpu_address:06X}'
                queue = deque([call.cpu_address])
                while queue and len(ancestors) < 4096:
                    address = queue.popleft()
                    if address not in ancestors:
                        ancestors.add(address)
                        queue.extend(reverse[address])
                if queue:
                    return False, 'delete-continuation predecessor budget exhausted'
        else:
            return False, 'delete continuation depth exhausted'
    return True, ''


def discover_cleared_pool_state_seeds(image, facts, decoded, *, protected_ranges=(),
                                    render_instruction, diagnostics=None):
    """Identify state0 only; requests/probes and seed promotion remain separate."""
    model = _Model(image, facts, render_instruction)
    pools = tuple(model.pools())
    if not pools:
        return ()
    known = model.facts
    decoded = {f.cpu_address: f for f in decoded.values()}
    origin = image.header.rom_start
    protected = tuple((origin + a, origin + b) for a, b in protected_ranges)
    data = tuple(sorted(_absolute_referenced_addresses(known)))
    occupied = {byte for f in known.values() for byte in range(f.cpu_address, f.cpu_address + f.length)}
    starts = sorted(known)
    conflicts = None
    seeds = {}
    for pool in pools:
        helpers = model.clearing_helpers(pool)
        clear = model.pool_clear(pool, helpers)
        if clear is None:
            continue
        for executor in model.executor(pool, helpers):
            producers = set()
            for call in known.values():
                if _call(call) and _direct(call) == pool.allocator:
                    producers.update(_producer_paths(model, pool, executor, call))
            if not producers:
                continue
            valid, reason = _lifecycle(model, pool, executor, producers)
            if not valid:
                if diagnostics is not None:
                    diagnostics.append({'pool': pool.base, 'executor': executor.entry, 'reason': reason})
                continue
            for type_value, writer, table, state_offset, transfer in sorted(producers):
                raw = model.read(table, 2)
                if raw is None:
                    continue
                target = table + int.from_bytes(raw, 'big', signed=True)
                if target & 1 or target in occupied or not origin + 0x200 <= target < origin + len(image.data):
                    continue
                following = min(target + 2048, origin + len(image.data),
                                next((a for a in starts if a > target), origin + len(image.data)))
                candidate = OrphanCandidate(target, target, following, following - target,
                                            'high', 'cleared record state zero')
                body = _complete_cfg(logical_image(image), candidate, known, decoded,
                                     protected, render_instruction, data)
                if (len(body) < 4 or decoded[target].mnemonic.upper().startswith('ORI.')
                        or len({f.mnemonic.upper().split('.')[0] for f in body.values()}) < 3
                        or not _balanced_body(body, target, known.keys(), {})):
                    continue
                if conflicts is None:
                    conflicts = make_dispatch_closure_validator(image, known, decoded,
                        protected_ranges=protected, render_instruction=render_instruction)
                if conflicts.has_conflict(body):
                    continue
                evidence = (f'cleared pool {pool.base:06X} count={pool.count} stride={pool.stride}; '
                            f'allocator {pool.allocator:06X}, clear {clear:06X}, executor {executor.entry:06X}; '
                            f'producer {writer:06X} publishes type {type_value}, state field +{state_offset}=0; '
                            f'type table {executor.table:06X}, state table {table:06X} slot 0, transfer {transfer:06X}; '
                            'high confidence assumes the scoped rooted pool lifecycle; not whole-game reachability')
                seeds[target] = DecoderSeed(target, 'cleared_pool_state', 'high', evidence, writer)
    return tuple(seeds[a] for a in sorted(seeds))
