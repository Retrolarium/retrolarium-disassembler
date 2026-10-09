"""Finite ROM records whose rooted consumer calls a relative word field.

A bounded interpreter follows a rooted pointer-returning producer and its
selector domain, then the guarded header-field consumer. Layout constants
come from executed instructions; arbitrary neighboring records are not read.
Only independently complete callback bodies produce high-confidence seeds.

Supported: finite byte inputs, equality branches, ROM pointer/cursor reads,
MOVEM stack saves, strict ordinary producer helpers, and a word-indexed
consumer ending at JSR (An). Unknown operations, unbounded domains, alignment
faults, cycles without exits and resource exhaustion fail closed. This is a
local code-use heuristic, not proof of reachable whole-game world states.
"""
from collections import deque
from dataclasses import dataclass, replace
import re

from retrolarium_disassembler.m68k.abstract import _register_list
from retrolarium_disassembler.m68k.records.constructor import _preserved_registers
from retrolarium_disassembler.m68k.instructions import pc_displacement_target
from retrolarium_disassembler.m68k.abstract import OrphanCandidate
from retrolarium_disassembler.m68k.frames.call_frame import make_trap_call_frame_validator
from retrolarium_disassembler.m68k.dispatch.closure import _balanced_body, logical_image, make_dispatch_closure_validator
from retrolarium_disassembler.m68k.repair.fallthrough import _direct_data_ranges
from retrolarium_disassembler.m68k.records.packed import _complete_cfg
from retrolarium_disassembler.m68k.dispatch.ram import discover_inline_trap_calls
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from bisect import bisect_right


class Rejected(ValueError):
    pass


def _backed(image, fact):
    at = fact.cpu_address - image.header.rom_start
    return (not fact.cpu_address & 1 and fact.physical_offset == at
            and fact.length == len(fact.raw) and fact.length in range(2, 11, 2)
            and 0 <= at <= len(image.data) - fact.length
            and image.data[at:at + fact.length] == fact.raw)


@dataclass(frozen=True)
class State:
    pc: int
    pointers: tuple = (None,) * 7
    domains: tuple = (None,) * 8  # (known low-bit width, finite values)
    flags: object = None         # None/boolean or (Dn, width, equality value)
    stack: tuple = ()


def immediate(text):
    if not re.fullmatch(r'#?-?0x[0-9a-f]+', text, re.I):
        raise Rejected('unsupported immediate')
    return int(text.removeprefix('#'), 0)


def register(text):
    match = re.fullmatch(r'([AD])([0-7])(?:[BWL])?', text, re.I)
    return (match[1].upper(), int(match[2])) if match else None


def put_pointer(state, name, value):
    reg = register(name)
    if reg is None:
        raise Rejected('not a register')
    kind, number = reg
    if kind != 'A' or number == 7:
        raise Rejected('not a tracked address register')
    pointers = list(state.pointers)
    if value is not None and not 0 <= value <= 0xffffff:
        raise Rejected('address arithmetic wraps the 24-bit bus')
    pointers[number] = value
    return replace(state, pointers=tuple(pointers))


def put_domain(state, name, width, values):
    kind, number = register(name)
    if kind != 'D':
        raise Rejected('not a data register')
    mask = (1 << width) - 1
    values = frozenset(v & mask for v in values)
    if len(values) > 512:
        raise Rejected('finite register domain budget')
    domains = list(state.domains)
    domains[number] = (width, values)
    return replace(state, domains=tuple(domains))


def branch(state, equal):
    """Filter a finite selector domain; don't invent unreachable table slots."""
    if state.flags is None:
        return state
    if isinstance(state.flags, bool):
        return state if state.flags == equal else None
    name, width, value = state.flags
    _, number = register(name)
    current = state.domains[number]
    if current is None:
        if width != 8:
            raise Rejected('unbounded word comparison')
        current = (8, frozenset(range(256)))
    if current[0] < width:
        raise Rejected('unknown high comparison bits')
    mask = (1 << width) - 1
    values = frozenset(v for v in current[1] if ((v & mask) == value) == equal)
    return put_domain(state, name, current[0], values) if values else None


def _flags_before_restore(state, restored):
    """MOVEM preserves CCR, but a predicate cannot follow the restored Dn.

    Evaluate Z against the pre-restore value domain. A mixed domain loses
    its register relation; both outcomes remain possible, while a known
    equality or inequality remains exact.
    """
    if state.flags is None or isinstance(state.flags, bool):
        return state.flags
    name, width, value = state.flags
    kind, number = register(name)
    if f'{kind.lower()}{number}' not in restored:
        return state.flags
    current = state.domains[number]
    if current is None or current[0] < width:
        return None
    mask = (1 << width) - 1
    outcomes = {(v & mask) == value for v in current[1]}
    return next(iter(outcomes)) if len(outcomes) == 1 else None


class Engine:
    def __init__(self, image, facts, *, forbidden_reads=(), _occupied=None):
        self.image, self.facts = image, {f.cpu_address:f for f in facts.values()}
        self.origin = image.header.rom_start
        self.occupied = (_occupied if _occupied is not None else
                         {a for f in facts.values() for a in range(f.cpu_address, f.cpu_address + f.length)})
        self.forbidden_reads = forbidden_reads
        self.reads, self.calls, self.strides, self.relative_fields = set(), {}, set(), set()
        self.executors = set()
        self.save_cache = {}
        self.backed_facts = None
        self.return_states = set()

    def fact(self, address):
        fact = self.facts.get(address)
        physical = address - self.origin
        if (fact is None or fact.cpu_address != address or fact.physical_offset != physical
                or address & 1 or fact.length != len(fact.raw) or not 2 <= fact.length <= 10
                or fact.length & 1 or not 0 <= physical <= len(self.image.data)-fact.length
                or self.image.data[physical:physical+fact.length] != fact.raw):
            raise Rejected('missing, unrooted, or mismatched instruction')
        return fact

    def read(self, address, width):
        physical = address - self.origin
        if ((width > 1 and address & 1) or not 0x200 <= physical <= len(self.image.data)-width
                or any(a in self.occupied for a in range(address, address+width))
                or any(a < address+width and address < b for a,b in self.forbidden_reads)):
            raise Rejected('ROM data read outside bounds, inside code, or forbidden stream')
        self.reads.update(range(address, address+width))
        return int.from_bytes(self.image.data[physical:physical+width], 'big')

    def memory(self, text, state, width):
        absolute = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.([wl])', text, re.I)
        if absolute:
            value = int(absolute[1], 0)
            if absolute[2].lower() == 'w':
                value &= 0xffff
                value = value - 0x10000 if value & 0x8000 else value
            address = value & 0xffffff
            if address >= 0xff0000:
                return None, state
            return self.read(address, width), state
        indexed = re.fullmatch(r'\((?:(-?0x[0-9a-f]+),)?(A[0-6])(?:,(D[0-7])w\*0x1)?\)(\+)?', text, re.I)
        if indexed is None:
            raise Rejected('unsupported effective address')
        base = state.pointers[int(indexed[2][1])]
        if base is None:
            raise Rejected('unknown indirect data base')
        offset = int(indexed[1] or '0', 0)
        if indexed[3]:
            domain = state.domains[int(indexed[3][1])]
            if domain is None or domain[0] < 16 or len(domain[1]) != 1:
                raise Rejected('unknown or non-singleton record cursor')
            index = next(iter(domain[1]))
            offset += index - 0x10000 if index & 0x8000 else index
        value = self.read(base + offset, width)
        if indexed[4]:
            state = put_pointer(state, indexed[2], base + width)
        return value, state

    def step(self, state, *, required_pointers=(), consumer=False):
        fact = self.fact(state.pc)
        op = fact.mnemonic.upper()
        base = op.split('.')[0]
        args = fact.operands.upper().split('|')
        following = fact.cpu_address + fact.length
        next_state = replace(state, pc=following)
        if fact.raw == b'\x4e\x75':
            if state.stack or consumer:
                raise Rejected('unbalanced return or consumer returned before callback')
            return 'return', state
        if base in {'BEQ', 'BNE'} and fact.flow_type.upper() == 'CONDITIONAL_JUMP' and len(fact.flows) == 1:
            yes, no = branch(state, base == 'BEQ'), branch(state, base != 'BEQ')
            return 'next', tuple(replace(s, pc=pc) for s,pc in ((yes,fact.flows[0]), (no,following)) if s is not None)
        if base in {'BRA', 'JMP'} and fact.flow_type.upper() == 'UNCONDITIONAL_JUMP' and len(fact.flows) == 1:
            return 'next', (replace(state, pc=fact.flows[0]),)
        if base in {'JSR', 'BSR'}:
            if fact.flow_type.upper() == 'COMPUTED_CALL':
                if not consumer or len(args) != 1 or not re.fullmatch(r'\(A[0-6]\)', args[0]):
                    raise Rejected('unresolved call')
                value = state.pointers[int(args[0][2])]
                if value is None:
                    raise Rejected('unknown callback')
                self.executors.add(fact.cpu_address)
                return 'callback', value
            if consumer or len(fact.flows) != 1 or fact.flow_type.upper() not in {'UNCONDITIONAL_CALL','CALL_TERMINATOR'}:
                raise Rejected('unsupported call')
            registers = {f'd{i}' for i in range(8)} | {f'a{i}' for i in range(7)}
            if self.backed_facts is None:
                self.backed_facts = {a:f for a,f in self.facts.items() if _backed(self.image, f)}
            kept = _preserved_registers(self.backed_facts, fact.flows[0], registers, cache=self.save_cache)
            if kept is None or not set(required_pointers) <= kept:
                raise Rejected('callee lacks complete pointer preservation summary')
            self.calls[fact.cpu_address] = (fact.flows[0], tuple(sorted(kept)))
            pointers = tuple(v if f'a{i}' in kept else None for i,v in enumerate(state.pointers))
            domains = tuple(v if f'd{i}' in kept else None for i,v in enumerate(state.domains))
            return 'next', (replace(next_state, pointers=pointers, domains=domains, flags=None),)
        if fact.flow_type.upper() != 'FALL_THROUGH':
            raise Rejected('unsupported control flow')
        if op == 'MOVEM.L' and not consumer:
            if args[-1] == '-(SP)':
                names = tuple(sorted(_register_list(args[0])))
                if not names or 'a7' in names:
                    raise Rejected('invalid stack save')
                saved = tuple((name, state.pointers[int(name[1])] if name[0] == 'a' else state.domains[int(name[1])]) for name in names)
                next_state = replace(next_state, stack=(*state.stack, saved))
            elif args[0] == '(SP)+':
                names = tuple(sorted(_register_list(args[-1])))
                if not state.stack or names != tuple(name for name,_ in state.stack[-1]):
                    raise Rejected('invalid stack restore')
                pointers, domains = list(state.pointers), list(state.domains)
                for name,value in state.stack[-1]:
                    (pointers if name[0] == 'a' else domains)[int(name[1])] = value
                next_state = replace(next_state, pointers=tuple(pointers), domains=tuple(domains),
                                     stack=state.stack[:-1], flags=_flags_before_restore(state, names))
            else:
                raise Rejected('non-stack MOVEM')
        elif op == 'LEA' and not consumer:
            target = pc_displacement_target(fact)
            if target is None:
                match = re.fullmatch(r'\((0X[0-9A-F]+)\)\.L', args[0])
                if match:
                    target = int(match[1], 0)
            if target is None or not self.origin+0x200 <= target < self.origin+len(self.image.data):
                raise Rejected('LEA outside ROM')
            next_state = put_pointer(next_state, args[-1], target)
        elif op == 'CLR.W' and register(args[0]) and args[0].startswith('D'):
            next_state = replace(put_domain(next_state, args[0], 16, {0}), flags=True)
        elif op in {'MOVE.B','MOVE.W'} and len(args) == 2 and register(args[-1]) and args[-1].startswith('D'):
            width = 1 if op.endswith('.B') else 2
            value, next_state = self.memory(args[0], next_state, width)
            values = {value} if value is not None else set(range(256)) if width == 1 else None
            if values is None:
                raise Rejected('unbounded RAM word load')
            previous = state.domains[int(args[-1][1])]
            if width == 1 and previous and previous[0] >= 16:
                values = {(v & 0xff00) | byte for v in previous[1] for byte in values}
                bits = 16
            else:
                bits = width*8
            next_state = replace(put_domain(next_state, args[-1], bits, values), flags=(args[-1], width*8, 0))
        elif op == 'MOVEA.L':
            value, next_state = self.memory(args[0], next_state, 4)
            if value is None:
                raise Rejected('non-ROM returned pointer')
            next_state = put_pointer(next_state, args[-1], value)
        elif op in {'CMPI.B','CMPI.W','CMP.B','CMP.W'}:
            width = 1 if op.endswith('.B') else 2
            if base == 'CMPI':
                value = immediate(args[0]) & ((1 << (width*8))-1)
                if register(args[-1]):
                    flags = (args[-1], width*8, value)
                else:
                    other, next_state = self.memory(args[-1], next_state, width)
                    flags = None if other is None else other == value
            else:
                value, next_state = self.memory(args[0], next_state, width)
                if value is None or not register(args[-1]):
                    raise Rejected('unsupported selector comparison')
                flags = (args[-1], width*8, value)
            next_state = replace(next_state, flags=flags)
        elif op == 'ADDA.W':
            old = state.pointers[int(args[-1][1])]
            if old is None:
                raise Rejected('unknown pointer before ADDA')
            if args[0].startswith('#'):
                offset = immediate(args[0]) & 0xffff
            else:
                offset, next_state = self.memory(args[0], next_state, 2)
                if offset is None:
                    raise Rejected('non-ROM relative word')
                field = re.fullmatch(r'\((-?0X[0-9A-F]+),A[0-6],D[0-7]W\*0X1\)', args[0])
                if not consumer or field is None:
                    raise Rejected('unsupported relative pointer source')
                self.relative_fields.add(int(field[1], 0))
            offset = offset - 0x10000 if offset & 0x8000 else offset
            next_state = put_pointer(next_state, args[-1], old+offset)
        elif op == 'ADDQ.W' and consumer and register(args[-1]) and args[-1].startswith('D'):
            amount = immediate(args[0])
            domain = state.domains[int(args[-1][1])]
            if not 0 < amount <= 8 or domain is None or domain[0] != 16 or len(domain[1]) != 1:
                raise Rejected('unknown record stride or cursor')
            value = next(iter(domain[1])) + amount
            if value >= 0x8000:
                raise Rejected('record cursor wraps')
            self.strides.add(amount)
            next_state = replace(put_domain(next_state, args[-1], 16, {value}), flags=value == 0)
        else:
            raise Rejected(f'unsupported instruction {op} {fact.operands}')
        return 'next', (next_state,)

    def run(self, entry, *, output=None, initial=None, consumer=False, maximum=20000):
        initial = State(entry) if initial is None else replace(initial, pc=entry)
        pending = deque([initial])
        seen, edges, exits, values = set(), {}, set(), set()
        self.return_states = set()
        required = ()
        if not consumer:
            # Every statically named address register in the producer may be
            # its returned pointer or ROM cursor. Calls must preserve all of
            # these; summaries never assume an arbitrary callee is harmless.
            required = tuple(f'a{i}' for i in range(7))
        while pending and len(seen) < maximum:
            state = pending.popleft()
            if state in seen:
                continue
            if not entry <= state.pc < entry+1024:
                raise Rejected('consumer/producer leaves bounded rooted body')
            seen.add(state)
            kind, result = self.step(state, required_pointers=required, consumer=consumer)
            if kind in {'return','callback'}:
                value = result if kind == 'callback' else state.pointers[int(output[1])]
                if value is None or value & 1 or not self.origin+0x200 <= value <= self.origin+len(self.image.data)-2:
                    raise Rejected('unknown, odd, or non-ROM returned pointer')
                values.add(value)
                exits.add(state)
                if kind == 'return':
                    self.return_states.add(result)
                    if len(self.return_states) > 1024:
                        raise Rejected('correlated producer return-state budget')
                edges[state] = ()
            else:
                edges[state] = result
                pending.extend(s for s in result if s not in seen)
        if pending or not exits:
            raise Rejected('state budget or no returning path')
        reverse = {s:set() for s in seen}
        for state, successors in edges.items():
            for successor in successors:
                reverse[successor].add(state)
        reaches_exit = set(exits)
        pending.extend(exits)
        while pending:
            for previous in reverse[pending.popleft()] - reaches_exit:
                reaches_exit.add(previous)
                pending.append(previous)
        if reaches_exit != seen:
            raise Rejected('nonterminating supported-state cycle')
        return values, len(seen)


def _discover_models(image, facts, *, handler_validator=None, protected_ranges=(), forbidden_reads=(),
             direct_heads=None, render_instruction=None):
    """Return reports for rooted call/guard/field/strided-consumer candidates."""
    facts = {f.cpu_address:f for f in facts.values()}
    incoming = {}
    for a,fact in facts.items():
        if fact.flow_type.upper() in {'FALL_THROUGH','CONDITIONAL_JUMP','UNCONDITIONAL_CALL'}:
            incoming.setdefault(a+fact.length,set()).add(a)
        for target in fact.flows:
            incoming.setdefault(target,set()).add(a)
    results, summaries = [], {}
    for call in sorted(facts.values(), key=lambda f: f.cpu_address):
        if call.mnemonic.upper().split('.')[0] not in {'JSR','BSR'} or len(call.flows) != 1 or call.flow_type.upper() != 'UNCONDITIONAL_CALL':
            continue
        guard = facts.get(call.cpu_address+call.length)
        if guard is None or guard.mnemonic.upper() != 'CMPI.W':
            continue
        check = re.fullmatch(r'(#?-?0x[0-9a-f]+)\|\((A[0-6])\)', guard.operands, re.I)
        branch_fact = facts.get(guard.cpu_address+guard.length)
        if check is None or branch_fact is None or not branch_fact.mnemonic.upper().startswith('BEQ.') or len(branch_fact.flows) != 1:
            continue
        load = facts.get(branch_fact.cpu_address+branch_fact.length)
        if load is None or load.mnemonic.upper() != 'MOVEA.L':
            continue
        field = re.fullmatch(r'\((0x[0-9a-f]+),'+check[2]+r'\)\|'+check[2], load.operands, re.I)
        clear = facts.get(load.cpu_address+load.length)
        if field is None or clear is None or clear.mnemonic.upper() != 'CLR.W' or not re.fullmatch(r'D[0-7]w',clear.operands,re.I):
            continue
        if len(results) >= 32:
            break
        row = dict(call=call.cpu_address, producer=call.flows[0], consumer=load.cpu_address,
                   field=int(field[1],0), result_register=check[2], candidates=[], accepted=[])
        try:
            chain = Engine(image, facts, forbidden_reads=forbidden_reads)
            for predecessor,current in ((call,guard),(guard,branch_fact),(branch_fact,load),(load,clear)):
                chain.fact(predecessor.cpu_address)
                chain.fact(current.cpu_address)
                if incoming.get(current.cpu_address) != {predecessor.cpu_address}:
                    raise Rejected('other entry bypasses producer/guard/field chain')
            if call.cpu_address <= branch_fact.flows[0] <= clear.cpu_address:
                raise Rejected('null-header branch enters consumer')
            key = call.flows[0], check[2]
            if key not in summaries:
                producer = Engine(image,facts,forbidden_reads=forbidden_reads)
                headers, states = producer.run(key[0],output=key[1])
                summaries[key] = headers, states, producer.reads, producer.calls, producer.return_states
            headers, states, producer_reads, calls, return_states = summaries[key]
            row.update(headers=sorted(headers), producer_states=states, producer_calls=calls,
                       producer_read_bytes=len(producer_reads), producer_return_states=len(return_states))
            if len(headers) > 256:
                raise Rejected('returned header budget')
            selected, targets, consumed, record_reports = set(), set(), set(producer_reads), []
            consumer_states = 0
            # Keep each returned header paired with the domains and other
            # pointers that the rooted producer actually returned. Unioning
            # headers alone would invent selector/header combinations.
            for returned in sorted(return_states, key=repr):
                header = returned.pointers[int(check[2][1])]
                engine = Engine(image,facts,forbidden_reads=forbidden_reads,_occupied=chain.occupied)
                if engine.read(header,2) == immediate(check[1]) & 0xffff:
                    consumed |= engine.reads
                    continue
                table = engine.read(header+row['field'],4)
                initial = put_pointer(replace(returned, pc=clear.cpu_address, flags=False), check[2], table)
                found, count = engine.run(clear.cpu_address,initial=initial,consumer=True,maximum=4096)
                consumer_states += count
                if consumer_states > 65536:
                    raise Rejected('combined consumer state budget')
                # Width, stride and relative field are all derived from the
                # actual rooted instructions followed above. Default-only
                # tables may not execute ADDQ, so they have no observed stride.
                if len(engine.strides)>1 or len(engine.relative_fields)!=1:
                    raise Rejected('ambiguous relative record layout')
                selected.add(table)
                targets |= found
                consumed |= engine.reads
                record_reports.append(dict(header=header,table=table,targets=sorted(found),states=count,
                    strides=sorted(engine.strides),relative_fields=sorted(engine.relative_fields),
                    executors=sorted(engine.executors)))
            starts = set(facts)
            occupied = {a for f in facts.values() for a in range(f.cpu_address,f.cpu_address+f.length)}
            eligible = {a for a in targets if not any(b in consumed for b in (a,a+1))
                        and (a not in occupied or a in starts)
                        and not any(left < a+2 and a < right for left,right in protected_ranges)}
            if direct_heads is None:
                accepted = {a for a in eligible if a in starts or handler_validator is not None and handler_validator(a)}
            else:
                accepted, rejected_heads = set(), {}
                for a in sorted(eligible):
                    head = direct_heads.get(a)
                    physical = a - image.header.rom_start
                    if (head is None or head.cpu_address != a or head.physical_offset != physical
                            or head.length != len(head.raw) or head.length not in range(2,11,2)
                            or head.raw != image.data[physical:physical+head.length]):
                        rejected_heads[a] = 'missing or inconsistent head'
                    elif any(b in consumed for b in range(a,a+head.length)):
                        rejected_heads[a] = 'head overlaps consumed table bytes'
                    elif any(left < a+head.length and a < right for left,right in protected_ranges):
                        rejected_heads[a] = 'head overlaps protected data'
                    elif any(b in occupied for b in range(a,a+head.length)) and (
                            a not in facts or facts[a].raw != head.raw):
                        rejected_heads[a] = 'head overlaps rooted instructions'
                    elif render_instruction is None or render_instruction(head) is None:
                        rejected_heads[a] = 'head cannot render byte exactly'
                    else:
                        accepted.add(a)
                row['rejected_heads'] = rejected_heads
            row.update(status='returned_pointer_and_consumer_proved', tables=sorted(selected),records=record_reports,
                       candidates=sorted(targets),eligible=sorted(eligible),accepted=sorted(accepted),
                       typed_read_bytes=len(consumed), typed_read_addresses=sorted(consumed),
                       new_roots=sorted(accepted-starts))
        except Rejected as error:
            row.update(status='rejected',reason=str(error))
        results.append(row)
    return results


def _ranges(addresses):
    """Coalesce all bytes actually consumed as data before any code proposal."""
    result = []
    for address in sorted(addresses):
        if result and result[-1][1] == address:
            result[-1] = result[-1][0], address + 1
        else:
            result.append((address, address + 1))
    return tuple(result)


def discover_finite_record_callback_seeds(
    image, facts, *, execution_facts=None, protected_ranges=(), forbidden_reads=(),
    render_instruction, decode_request=None, diagnostics=None,
):
    """Return high-confidence seeds from finite rooted producer/consumer models.

    ``facts`` may contain speculative decodes. Only ``execution_facts`` may
    establish the producer, helper summaries, selector/record bounds and JSR.
    All ranges use logical CPU coordinates. Protected ranges forbid callback
    code; forbidden reads also forbid treating a different CPU's stream as a
    record. Exact rooted reads may consume previously typed pointer tables.

    Budgets: 32 candidate call sites, 20,000 producer states, 256 headers,
    1,024 correlated producer return states,
    4,096 states per consumer, 65,536 per model, 1,024-byte instruction bodies,
    and 4,096 callbacks of 2,048-byte CFGs. No recursion or unknown callees are admitted
    in a callback. Short leaf bodies qualify because independent code-use
    evidence already exists; they do not bootstrap arbitrary orphan islands.
    """
    if execution_facts is None:
        return ()
    rooted = {f.cpu_address:f for f in execution_facts.values() if _backed(image, f)}
    models = _discover_models(image, rooted, protected_ranges=protected_ranges,
                              forbidden_reads=forbidden_reads)
    useful = [row for row in models if row['status'] == 'returned_pointer_and_consumer_proved']
    if not useful:
        if diagnostics is not None:
            diagnostics.extend(models)
        return ()
    decoded = {f.cpu_address:f for f in facts.values() if _backed(image, f)}
    protected = (*protected_ranges, *_direct_data_ranges(image, rooted),
                 *_ranges({a for row in useful for a in row['typed_read_addresses']}))
    # A TRAP continuation needs the same strict frame witness as other
    # speculative handler bodies; the record proof does not waive that ABI.
    trap_sites = {a:f for a,f in decoded.items() if f.mnemonic.upper() == 'TRAP'}
    preserves_frame = make_trap_call_frame_validator(
        {a:f for a,f in rooted.items() if _backed(image, f)})
    inline = {call.call_address:call for call in discover_inline_trap_calls(
        image, {**trap_sites, **rooted})
        if call.handler in rooted and preserves_frame(call.handler)}
    starts = sorted(rooted)
    origin = image.header.rom_start
    rom_end = origin + len(image.data)
    occupied = {byte for f in rooted.values() for byte in range(f.cpu_address, f.cpu_address + f.length)}
    seeds, checked = {}, {}
    byte_image = logical_image(image)
    conflicts = make_dispatch_closure_validator(image, rooted, decoded,
        protected_ranges=protected, render_instruction=render_instruction,
        decode_request=decode_request, inline_traps=inline)

    def body_at(address):
        if address in checked:
            return checked[address]
        checked[address] = {}
        if address in occupied or address & 1 or not origin + 0x200 <= address <= rom_end - 2:
            return {}
        if address not in decoded and decode_request is not None:
            decode_request(address, address, 'finite record callback head')
        index = bisect_right(starts, address)
        end = min(address + 2048, rom_end, starts[index] if index < len(starts) else rom_end)
        candidate = OrphanCandidate(address, address, end, end-address,
                                    'high', 'rooted finite-record callback CFG')
        body = _complete_cfg(byte_image, candidate, rooted, decoded, protected,
                             render_instruction, (), inline, decode_request=decode_request)
        if (not body or not _balanced_body(body, address, rooted.keys(), inline)
                or conflicts.has_conflict(body)
                or any(f.mnemonic.upper() in {'RTE','RTR','ILLEGAL','STOP','RESET'}
                       or f.mnemonic.upper() == 'TRAP' and f.cpu_address not in inline
                       for f in body.values())):
            return {}
        checked[address] = body
        return checked[address]

    # Table targets can also compete with each other as short valid bodies.
    # The general alternate-CFG predicate deliberately requires a stronger
    # orphan signature, so explicitly reject both independently referenced
    # interpretations when either begins in the other's instruction operand.
    targets = sorted({address for row in useful for address in row['eligible'] if address not in rooted})[:4096]
    byte_owners, ambiguous = {}, set()
    for target in targets:
        for address, fact in body_at(target).items():
            end = inline[address].continuation if address in inline else address + fact.length
            for byte in range(address, end):
                owners = byte_owners.setdefault(byte, {})
                for other, other_address in owners.items():
                    if other_address != address:
                        ambiguous.update((other, target))
                owners[target] = address

    for row in useful:
        accepted = []
        for address in row['eligible']:
            if address not in checked or address in ambiguous or not checked[address]:
                continue
            records = [record for record in row['records'] if address in record['targets']]
            executors = sorted({site for record in records for site in record['executors']})
            witness = '; '.join(
                f"header {record['header']:06X} table {record['table']:06X}, "
                f"relative word fields {record['relative_fields']}, strides {record['strides']}"
                for record in records)
            evidence = (
                f"rooted call {row['call']:06X} -> producer {row['producer']:06X}; "
                f"finite returned headers {len(row['headers'])}, producer states {row['producer_states']}; "
                f"guarded field +{row['field']} consumer {row['consumer']:06X}; {witness}; "
                f"computed JSR sites {','.join(f'{a:06X}' for a in executors)}; "
                f"typed ROM data {row['typed_read_bytes']} bytes; "
                f"independent complete callback body {len(checked[address])} instructions")
            seeds.setdefault(address, DecoderSeed(address, 'finite_record_callback', 'high',
                                                   evidence, executors[0]))
            accepted.append(address)
        row['accepted'] = accepted
        row['new_roots'] = accepted
    if diagnostics is not None:
        diagnostics.extend(models)
    return tuple(seeds[address] for address in sorted(seeds))
