"""Typed absolute RAM callbacks installed by rooted LEA paths.

Each direct slot read needs a rooted route to indirect execution with the
loaded address register unchanged. Direct helpers are crossed only with the
existing balanced register-preservation summary. Other whole-long pointer
assignments are allowed but never supply target evidence. This is a high
confidence code-use witness, not a proof of runtime write/read ordering.
"""
from collections import deque
from dataclasses import dataclass
import re

from retrolarium_disasm.m68k.abstract import _register_list
from retrolarium_disasm.m68k.frames.call_frame import _STACK
from retrolarium_disasm.m68k.records.constructor import _writes, _unsupported_frame_or_exception, _preserved_registers
from retrolarium_disasm.m68k.repair.fallthrough import _direct_data_ranges
from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_disasm.megadrive.emit import _asm_instruction
from retrolarium_disasm.megadrive.symbols import pc_displacement_target


def _backed(image, fact):
    physical = fact.cpu_address - image.header.rom_start
    return (not fact.cpu_address & 1 and fact.physical_offset == physical
            and 2 <= fact.length <= 10 and not fact.length & 1 and len(fact.raw) == fact.length
            and 0 <= physical <= len(image.data) - fact.length
            and image.data[physical:physical + fact.length] == fact.raw)


def _absolute(operand):
    match = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.([wl])', operand, re.I)
    if match is None:
        return None
    value = int(match[1], 0)
    if match[2].lower() == 'w':
        value &= 0xffff
        value -= 0x10000 if value & 0x8000 else 0
    return value & 0xffffff


def _direct(fact):
    if (fact.mnemonic.upper().split('.')[0] in {'BSR', 'JSR', 'BRA', 'JMP'}
            and len(fact.flows) == 1 and not fact.flow_type.upper().startswith('COMPUTED')):
        return fact.flows[0] & 0xffffff
    return None


def _successors(fact):
    flow = fact.flow_type.upper()
    base = fact.mnemonic.upper().split('.')[0]
    if base in {'BRA', 'JMP'}:
        target = _direct(fact)
        return (target,) if target is not None else ()
    if flow == 'CONDITIONAL_JUMP':
        return (*fact.flows, fact.cpu_address + fact.length)
    if flow == 'FALL_THROUGH':
        return (fact.cpu_address + fact.length,)
    return ()


def _mentions(fact, register):
    return re.search(r'(?<![A-Z0-9])' + register + r'[BWL]?(?![A-Z0-9])', fact.operands.upper())


def _scalar_test(fact, register):
    return (fact.mnemonic.upper().split('.')[0] in {'CMP', 'CMPA', 'CMPI', 'TST', 'BTST'}
            and not re.search(r'\([^)]*' + register, fact.operands.upper()))


def _replaces_pointer(fact, register):
    args = fact.operands.upper().split('|')
    return (fact.mnemonic.upper().split('.')[0] in {'MOVEA', 'LEA'} and len(args) == 2
            and args[-1] == register
            and not re.search(r'(?<![A-Z0-9])' + register + r'[BWL]?(?![A-Z0-9])', args[0]))


def _unsafe_pointer_use(fact, register):
    if not _mentions(fact, register) or _scalar_test(fact, register) or _replaces_pointer(fact, register):
        return False
    args = fact.operands.upper().split('|')
    return not (fact.mnemonic.upper() == 'MOVEM.L' and len(args) == 2
                and (args[-1] == '-(SP)' or args[0] == '(SP)+'))


def _transparent(fact, register):
    """Keep a loaded pointer untouched until its typed store or execution."""
    op = fact.mnemonic.upper()
    if _unsupported_frame_or_exception(fact) or register.lower() in _writes(fact):
        return False
    if op in {'MOVEM.L', 'MOVEM.W'}:
        args = fact.operands.upper().split('|')
        registers = _register_list(args[0] if args[-1] == '-(SP)' else args[-1])
        return (len(args) == 2 and (args[-1] == '-(SP)' or args[0] == '(SP)+')
                and registers and register.lower() not in registers and 'a7' not in registers)
    if _STACK.search(fact.operands):
        return False
    if _mentions(fact, register):
        # Testing a pointer's scalar value does not dereference or copy it.
        return _scalar_test(fact, register)
    return True


class _Paths:
    def __init__(self, rooted):
        self.rooted = rooted
        self.preserved = {}
        self.unread = {}

    def preserves(self, target, register):
        result = _preserved_registers(self.rooted, target, {register.lower()}, cache=self.preserved)
        return result is not None and register.lower() in result

    def unread_return(self, start, register, active=()):
        """Track the incoming pointer through balanced MOVEM and local reuse.

        Register preservation alone permits dereferencing the original pointer.
        This additional summary rejects that use, including a sibling branch,
        while allowing a saved register to hold an unrelated local data pointer.
        It is called only for helpers with an existing balanced return summary.
        """
        if start in active or len(active) >= 4:
            return None
        key = start, register, len(active)
        if key in self.unread:
            return self.unread[key]
        pending = deque([(start, True, ())])
        seen, returns = set(), set()
        while pending and len(seen) < 512:
            state = pending.popleft()
            if state in seen:
                continue
            seen.add(state)
            address, original, stack = state
            fact = self.rooted.get(address)
            if fact is None or _unsupported_frame_or_exception(fact):
                return None
            op = fact.mnemonic.upper()
            args = fact.operands.upper().split('|')
            if fact.raw == b'\x4e\x75':
                if stack:
                    return None
                returns.add(original)
                continue
            if op == 'MOVEM.L' and args[-1] == '-(SP)':
                saved = frozenset(_register_list(args[0]))
                stack += ((saved, original),)
            elif op == 'MOVEM.L' and args[0] == '(SP)+':
                restored = frozenset(_register_list(args[-1]))
                if not stack or stack[-1][0] != restored:
                    return None
                if register.lower() in restored:
                    original = stack[-1][1]
                stack = stack[:-1]
            elif original:
                if _unsafe_pointer_use(fact, register):
                    return None
                if register.lower() in _writes(fact):
                    if not _replaces_pointer(fact, register):
                        return None
                    original = False
            if op.split('.')[0] in {'BSR', 'JSR'}:
                target = _direct(fact)
                if target is None:
                    return None
                child = self.unread_return(target, register, (*active, start)) if original else {False}
                if child is None:
                    return None
                pending.extend((address + fact.length, value, stack) for value in child)
            else:
                successors = _successors(fact)
                if not successors:
                    return None
                pending.extend((target, original, stack) for target in successors)
        if pending or not returns:
            return None
        result = frozenset(returns)
        self.unread[key] = result
        return result

    def executors(self, start, register, active=()):
        if start in active or len(active) >= 4:
            return {}, True
        pending, seen, found = deque([(start, ())]), set(), {}
        while pending and len(seen) < 256:
            address, helpers = pending.popleft()
            if address in seen:
                continue
            seen.add(address)
            fact = self.rooted.get(address)
            if fact is None:
                return {}, True
            op = fact.mnemonic.upper().split('.')[0]
            if (op in {'JSR', 'JMP'} and fact.operands.upper() == f'({register})'
                    and fact.flow_type.upper() in {'COMPUTED_CALL', 'COMPUTED_JUMP'}
                    and fact.length == 2 and int.from_bytes(fact.raw, 'big') ==
                    (0x4e90 if op == 'JSR' else 0x4ed0) + int(register[1])):
                found.setdefault(address, helpers)
                continue  # The callback's return effects have not been proved.
            if not _transparent(fact, register):
                if _replaces_pointer(fact, register):
                    continue
                return {}, True
            if op in {'JSR', 'BSR'}:
                target = _direct(fact)
                if target is None:
                    return {}, True
                if self.preserves(target, register):
                    if self.unread_return(target, register) is None:
                        return {}, True
                    pending.append((address + fact.length, (*helpers, (address, target))))
                else:
                    # A preservation summary already excludes computed
                    # transfers. Only unsummarized helpers can contain the
                    # desired indirect execution; do not rescan every leaf.
                    children, unsafe = self.executors(target, register, (*active, start))
                    if unsafe:
                        return {}, True
                    for call, child in children.items():
                        found.setdefault(call, (*helpers, *child))
            else:
                successors = _successors(fact)
                if not successors and fact.raw != b'\x4e\x75':
                    return {}, True
                pending.extend((target, helpers) for target in successors)
        return (found, False) if not pending else ({}, True)

    def stores(self, start, register, image):
        pending, seen, found = deque([start]), set(), set()
        while pending and len(seen) < 64:
            address = pending.popleft()
            if address in seen:
                continue
            seen.add(address)
            fact = self.rooted.get(address)
            if fact is None:
                continue
            args = fact.operands.upper().split('|')
            slot = _absolute(args[-1])
            if (fact.mnemonic.upper() == 'MOVE.L' and len(args) == 2 and args[0] == register
                    and slot is not None and not slot & 1
                    and image.header.ram_start <= slot <= image.header.ram_end - 3):
                found.add((slot, address))
                continue
            if not _transparent(fact, register):
                if _unsafe_pointer_use(fact, register):
                    return set()
                continue
            if fact.mnemonic.upper().split('.')[0] in {'JSR', 'BSR'}:
                target = _direct(fact)
                if (target is not None and self.preserves(target, register)
                        and self.unread_return(target, register) is not None):
                    pending.append(address + fact.length)
            else:
                pending.extend(_successors(fact))
        return found if not pending else set()


@dataclass(frozen=True)
class AbsoluteRamCallback:
    target: int
    lea: int
    writer: int
    slot: int
    reader: int
    executor: int
    preserved_helpers: tuple[tuple[int, int], ...]


def discover_absolute_ram_callbacks(image, trusted_facts, decoded_facts, *, protected_ranges=(), decode_request=None):
    """Protection ranges and returned addresses are logical CPU addresses."""
    rooted = {f.cpu_address:f for f in trusted_facts.values() if _backed(image, f)}
    decoded = {f.cpu_address:f for f in decoded_facts.values() if _backed(image, f)}
    paths, origin = _Paths(rooted), image.header.rom_start
    readers, writes = {}, {}
    for load in rooted.values():
        args = load.operands.upper().split('|')
        if load.mnemonic.upper() != 'MOVEA.L' or len(args) != 2 or not re.fullmatch(r'A[0-6]', args[1]):
            continue
        slot = _absolute(args[0])
        if slot is None or slot & 1 or not image.header.ram_start <= slot <= image.header.ram_end - 3:
            continue
        executors, _ = paths.executors(load.cpu_address + load.length, args[1])
        readers.setdefault(slot, {})[load.cpu_address] = executors
    if not readers:
        return ()
    for lea in rooted.values():
        args = lea.operands.upper().split('|')
        if (lea.mnemonic.upper() != 'LEA' or lea.flow_type.upper() != 'FALL_THROUGH'
                or len(args) != 2 or not re.fullmatch(r'A[0-6]', args[1])):
            continue
        target = pc_displacement_target(lea)
        if target is None or target & 1 or not origin+0x200 <= target <= origin+len(image.data)-2:
            target = _absolute(args[0])
        if target is None or target & 1 or not origin+0x200 <= target <= origin+len(image.data)-2:
            continue
        for slot, writer in paths.stores(lea.cpu_address + lea.length, args[1], image):
            if slot in readers:
                writes.setdefault(slot, []).append((target, lea.cpu_address, writer))
    rejected = {slot for slot, loads in readers.items() if any(not calls for calls in loads.values())}
    for fact in rooted.values():
        op = fact.mnemonic.upper()
        args = fact.operands.upper().split('|')
        width = {'.B':1,'.W':2,'.L':4}.get(op[-2:], 4)
        if op.startswith('MOVEM'):
            width = 64  # Conservative whole-register-mask overlap guard.
        for index, operand in enumerate(args):
            address = _absolute(operand)
            if address is None:
                continue
            for slot in readers.keys() & writes.keys() - rejected:
                if not address < slot + 4 or not slot < address + width:
                    continue
                if address != slot or width != 4:
                    rejected.add(slot)
                elif fact.cpu_address in readers[slot]:
                    pass
                elif op in {'TST.L','CMP.L','CMPA.L','CMPI.L'}:
                    pass
                elif op == 'CLR.L' and index == len(args)-1:
                    pass
                elif op == 'MOVE.L' and index == 1:
                    immediate = re.fullmatch(r'#(-?0X[0-9A-F]+)', args[0])
                    value = int(immediate[1],0) & 0xffffff if immediate else None
                    pointer_register = re.fullmatch(r'A[0-6]', args[0])
                    if not (pointer_register or value == 0 or value is not None and
                            (image.header.ram_start <= value <= image.header.ram_end
                             or not value & 1 and origin+0x200 <= value <= origin+len(image.data)-2)):
                        rejected.add(slot)
                else:
                    rejected.add(slot)
    occupied = {a for f in rooted.values() for a in range(f.cpu_address, f.cpu_address+f.length)}
    interiors = {a for f in rooted.values() for a in range(f.cpu_address+1, f.cpu_address+f.length)}
    results = []
    for slot, assignments in writes.items():
        if slot in rejected:
            continue
        # These precise LEAs have typed code-use evidence. Their address
        # construction is not a scalar data read of the callback's bytes.
        writer_leas = {lea for _, lea, _ in assignments}
        data_ranges = _direct_data_ranges(image, {a:f for a,f in rooted.items() if a not in writer_leas})
        for target, lea, writer in assignments:
            if target & 1 or not origin+0x200 <= target <= origin+len(image.data)-2 or target in interiors:
                continue
            entry = rooted.get(target) or decoded.get(target)
            if entry is None:
                if decode_request is not None:
                    decode_request(target, writer, 'typed absolute RAM callback first instruction')
                continue
            end = target + entry.length
            if (_asm_instruction(entry) is None
                    or any(a < end and target < b for a,b in (*protected_ranges,*data_ranges))
                    or target not in rooted and any(a in occupied for a in range(target,end))):
                continue
            reader = min(readers[slot])
            executor = min(readers[slot][reader])
            results.append(AbsoluteRamCallback(target,lea,writer,slot,reader,executor,readers[slot][reader][executor]))
    return tuple(results)


def discover_absolute_ram_callback_seeds(image, trusted_facts, decoded_facts, *, protected_ranges=(), decode_request=None):
    seeds = {}
    for proof in discover_absolute_ram_callbacks(image,trusted_facts,decoded_facts,
            protected_ranges=protected_ranges,decode_request=decode_request):
        helpers = ','.join(f'{site:06X}->{callee:06X}' for site,callee in proof.preserved_helpers)
        evidence = (f'rooted LEA {proof.lea:06X} reaches longword writer {proof.writer:06X}; '
                    f'absolute RAM callback slot {proof.slot:06X}; reader {proof.reader:06X} '
                    f'preserves pointer until indirect execution {proof.executor:06X}; '
                    f'balanced preserving helper calls [{helpers}]; high confidence typed code use, not runtime ordering')
        seeds.setdefault(proof.target, DecoderSeed(proof.target,'absolute_ram_callback','high',evidence,proof.writer))
    return tuple(seeds[a] for a in sorted(seeds))
