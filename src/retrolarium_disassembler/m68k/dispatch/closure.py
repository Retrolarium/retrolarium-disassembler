"""Bounded, independent CFG witnesses for speculative dispatch handlers.

Unknown direct callees and tail targets are checked recursively. By default,
every root needs its own connection to rooted code; another table entry never
supplies that connection. Dispatch consumers can opt into a separate large,
closed leaf heuristic. Neither witness proves that a branch executes.
"""
from bisect import bisect_left, bisect_right
from collections import deque
import re
from types import SimpleNamespace

from retrolarium_disasm.m68k.abstract import OrphanCandidate, _register_list
from retrolarium_disasm.m68k.records.constructor import _unsupported_frame_or_exception
from retrolarium_disasm.m68k.records.packed import _complete_cfg
from retrolarium_disasm.megadrive.pointers import _absolute_referenced_addresses


def logical_image(image):
    """Provide logical-address byte access without allocating a padded ROM."""
    origin = image.header.rom_start
    if not origin:
        return image

    class LogicalBytes:
        def __len__(self):
            return origin + len(image.data)

        def __getitem__(self, key):
            start, end = key.start - origin, key.stop - origin
            return image.data[start:end] if 0 <= start <= end <= len(image.data) else b''

    return SimpleNamespace(data=LogicalBytes())


def _supervisor_immediate_in_code(fact):
    """An executed immediate MOVE to SR keeps the 68000 supervisor stack.

    MOVE to SR traps before changing SR when entered in user mode. On its
    normal path S is therefore already set. Requiring S=1, T=0 and zero
    reserved bits leaves the active stack bank unchanged. This only supports
    code classification: it does not establish that a callee returns from
    arbitrary machine state and must not relax constructor/inline-call ABIs.
    """
    if (fact.mnemonic.upper() not in {'MOVE', 'MOVE.W'} or fact.length != 4
            or len(fact.raw) != 4 or fact.raw[:2] != b'\x46\xfc'
            or fact.flow_type.upper() != 'FALL_THROUGH'):
        return False
    match = re.fullmatch(r'#?(0x[0-9a-f]+)\|SR', fact.operands, re.I)
    if match is None:
        return False
    value = int(match[1], 0)
    return (value == int.from_bytes(fact.raw[2:], 'big')
            and value & 0xf8e0 == 0x2000)


def _balanced_body(body, entry, exits, inline_traps):
    """Keep normal calls distinct from stack aliases and return-PC tricks."""
    pending, seen = deque([(entry, 0)]), set()
    while pending and len(seen) < 512:
        address, stack = pending.popleft()
        if (address, stack) in seen:
            continue
        seen.add((address, stack))
        fact = body[address]
        op, operands = fact.mnemonic.upper(), fact.operands.upper().split('|')
        inline = inline_traps.get(address) if op == 'TRAP' else None
        if (fact.flow_type.upper() in {'COMPUTED_CALL', 'COMPUTED_JUMP'}
                or inline is None and _unsupported_frame_or_exception(fact)
                and not _supervisor_immediate_in_code(fact)):
            return False
        if re.search(r'(?<![A-Z0-9])(?:SP|A7|USP)[BWL]?(?![A-Z0-9])', fact.operands.upper()):
            if op in {'MOVEM.W', 'MOVEM.L'}:
                width = 4 if op.endswith('.L') else 2
                if operands[-1] == '-(SP)':
                    registers = _register_list(operands[0])
                    direction = 1
                elif operands[0] == '(SP)+':
                    registers = _register_list(operands[-1])
                    direction = -1
                else:
                    return False
                if not registers or 'a7' in registers:
                    return False
                stack += direction * width * len(registers)
            elif op in {'MOVE.W', 'MOVE.L', 'MOVEA.W', 'MOVEA.L'} and len(operands) == 2:
                width = 4 if op.endswith('.L') else 2
                if operands[-1] == '-(SP)' and re.fullmatch(r'[DA][0-6]|D7', operands[0]):
                    stack += width
                elif operands[0] == '(SP)+' and re.fullmatch(r'[DA][0-6]|D7', operands[-1]):
                    stack -= width
                else:
                    return False
            else:
                return False
            if not 0 <= stack <= 256:
                return False
        if op == 'RTS':
            if stack:
                return False
            continue
        opcode, following = int.from_bytes(fact.raw[:2], 'big'), address + fact.length
        call = opcode & 0xffc0 == 0x4e80 or opcode & 0xff00 == 0x6100
        jump = opcode & 0xffc0 == 0x4ec0 or opcode & 0xff00 == 0x6000
        conditional = fact.flow_type.upper() == 'CONDITIONAL_JUMP'
        edges = [following] if call or fact.flow_type.upper() == 'FALL_THROUGH' else []
        if inline is not None:
            edges = [inline.continuation]
        if jump or conditional:
            edges.extend(fact.flows)
        if conditional:
            edges.append(following)
        for target in edges:
            if target in body:
                pending.append((target, stack))
            elif target not in exits or stack:
                return False
    return not pending


def _strong_closed_leaf(body):
    """Recognize substantial independent leaf code after complete CFG checks.

    These thresholds guard a high-confidence code heuristic, not reachability
    or a calling convention proof. Every successor stays within the body and
    every terminal is RTS. Calls are excluded by raw opcode as well as backend
    metadata, so recursive callees cannot lend their complexity to the witness.
    """
    if (len(body) < 24
            or len({f.mnemonic.upper().split('.')[0] for f in body.values()}) < 8
            or sum(f.raw == b'\x4e\x75' for f in body.values()) < 2
            or sum('(' in f.operands
                   and f.mnemonic.upper().split('.')[0] not in {'LEA', 'JMP', 'JSR', 'PEA'}
                   for f in body.values()) < 8):
        return False
    has_conditional = False
    for address, fact in body.items():
        if not set(fact.flows) <= body.keys():
            return False
        if fact.raw == b'\x4e\x75':
            continue
        base = fact.mnemonic.upper().split('.')[0]
        flow = fact.flow_type.upper()
        opcode = int.from_bytes(fact.raw[:2], 'big')
        if (opcode & 0xffc0 == 0x4e80 or opcode & 0xff00 == 0x6100
                or base in {'JSR', 'BSR', 'TRAP', 'TRAPV', 'RTE', 'RTR', 'STOP', 'RESET', 'ILLEGAL'}
                or flow in {'COMPUTED_CALL', 'COMPUTED_JUMP'}):
            return False
        following = address + fact.length
        if base in {'JMP', 'BRA'}:
            if not fact.flows:
                return False
        elif flow == 'CONDITIONAL_JUMP':
            if not fact.flows or not {*fact.flows, following} <= body.keys():
                return False
            has_conditional |= any(target != following for target in fact.flows)
        elif flow == 'FALL_THROUGH':
            if following not in body:
                return False
        else:
            return False
    return has_conditional


def make_dispatch_closure_validator(image, known, decoded, *, protected_ranges=(),
                                    render_instruction, decode_request=None, inline_traps=None,
                                    allow_closed_leaves=False):
    """Return a facts-scoped predicate; protected ranges use logical addresses.

    An optional observer requests missing speculative decodes. Requests never
    qualify code, enter this factory's caches, or alter supplied facts.
    The closed-leaf option is reserved for structural dispatch consumers; it
    does not relax the default rooted-connection or callee/frame ABI contracts.
    """
    known = {f.cpu_address: f for f in known.values()}
    decoded = {f.cpu_address: f for f in decoded.values()}
    starts, available = sorted(known), sorted(decoded)
    origin, rom_end = image.header.rom_start, image.header.rom_start + len(image.data)
    byte_image = logical_image(image)
    occupied = {byte for f in known.values() for byte in range(f.cpu_address, f.cpu_address + f.length)}
    data = tuple(sorted(_absolute_referenced_addresses(known)))
    completed, depths, checked = {}, {}, {}
    inline_traps = dict(inline_traps or {})
    longest_span = max((max(f.length, inline_traps[a].continuation - a
                            if a in inline_traps else 0)
                        for a, f in decoded.items()), default=0)

    def instruction_spans(body):
        for address, fact in body.items():
            end = address + fact.length
            if address in inline_traps and fact.mnemonic.upper() == 'TRAP':
                end = inline_traps[address].continuation
            yield address, end

    def request(address, source, reason):
        if decode_request is not None and not address & 1 and origin + 0x200 <= address < rom_end:
            decode_request(address, source, reason)

    def prove(entry, active=()):
        if entry in active or len(active) >= 8:
            return None
        if entry in completed:
            return completed[entry] if len(active) + depths[entry] <= 8 else None
        if entry & 1 or not origin + 0x200 <= entry < rom_end or entry in occupied:
            return None
        if entry not in decoded:
            request(entry, entry, 'missing dispatch handler entry')
            return None
        index = bisect_right(starts, entry)
        end = min(entry + 2048, rom_end, starts[index] if index < len(starts) else rom_end)
        external = set()
        for point in available[bisect_left(available, entry):bisect_left(available, end)]:
            fact = decoded[point]
            opcode = int.from_bytes(fact.raw[:2], 'big')
            call = opcode & 0xffc0 == 0x4e80 or opcode & 0xff00 == 0x6100
            branch = (fact.flow_type.upper() in {'CONDITIONAL_JUMP', 'UNCONDITIONAL_JUMP'}
                      or opcode & 0xffc0 == 0x4ec0 or opcode & 0xff00 == 0x6000)
            external.update(target for target in fact.flows if target not in known
                            and (call or branch and not entry <= target < end))
        virtual = {**known, **{a: decoded.get(a) for a in external}}
        candidate = OrphanCandidate(entry, entry, end, end-entry, 'high', 'bounded dispatch CFG closure')
        body = _complete_cfg(byte_image, candidate, virtual, decoded, protected_ranges,
                             render_instruction, data, inline_traps, decode_request=decode_request)
        if not body:
            return None
        used = {target for f in body.values() for target in f.flows if target in external}
        used.update(end for a, end in instruction_spans(body) if end in external
                    and body[a].mnemonic.upper().split('.')[0] not in {'BRA', 'JMP', 'RTS'})
        if not _balanced_body(body, entry, known.keys() | used, inline_traps):
            return None
        closure = dict(body)
        depth = 1
        owners = {byte: a for a, end in instruction_spans(body) for byte in range(a, end)}
        for target in sorted(used):
            request(target, entry, 'unrooted dispatch dependency')
            child = prove(target, (*active, entry))
            if child is None:
                return None
            depth = max(depth, 1 + depths[target])
            for a, end in instruction_spans(child):
                for byte in range(a, end):
                    if byte in owners and owners[byte] != a:
                        return None
                    owners[byte] = a
                closure[a] = child[a]
            if len(closure) > 1024:
                return None
        completed[entry] = closure
        depths[entry] = depth
        return closure

    def qualifies(entry, body):
        return bool(
            body and len(body) >= 4 and not decoded[entry].mnemonic.upper().startswith('ORI.')
            and len({f.mnemonic.upper().split('.')[0] for f in body.values()}) >= 3
            and (any(set(f.flows) & known.keys() for f in body.values())
                 or allow_closed_leaves and _strong_closed_leaf(body)))

    class Validator:
        def has_conflict(self, body):
            """Reject both coherent overlapping hypotheses, independent of query order.

            Probe decoding can legally start in another instruction's operand.
            Neither such CFG gets priority merely because it was requested first.
            Rooted facts can resolve the ambiguity on a subsequent analysis pass.
            Only instruction spans intersecting this closure are inspected.
            """
            competitors = set()
            for address, fact in body.items():
                # A rooted TRAP ABI has already established its inline bytes as
                # arguments. Speculative instructions there are not rivals.
                end = address + fact.length
                left = bisect_right(available, address - longest_span)
                right = bisect_left(available, end)
                for other in available[left:right]:
                    if other in body or other in known:
                        continue
                    fact = decoded[other]
                    other_end = inline_traps[other].continuation if other in inline_traps else other + fact.length
                    if other_end > address:
                        competitors.add(other)
            # This is a heuristic witness budget, never a reason to choose one
            # interpretation of ambiguous bytes over another.
            if len(competitors) > 256:
                return True
            return any(qualifies(other, prove(other)) for other in sorted(competitors))

        def __call__(self, entry):
            if entry not in checked:
                body = prove(entry)
                checked[entry] = qualifies(entry, body) and not self.has_conflict(body)
            return checked[entry]

    return Validator()
