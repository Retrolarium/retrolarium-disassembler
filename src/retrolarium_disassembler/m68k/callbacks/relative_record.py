"""Code-use witnesses for relative ROM records copied into object callbacks.

The record layout comes from a rooted producer's complete cursor walk. A
separate rooted reader must execute the same object field without changing
the callback register. Closed, ordered relative tables are deliberately the
only supported layout. This is a structural witness, not a claim that every
selector value occurs at runtime.
"""
from collections import deque
from dataclasses import dataclass
import re

from .m68k_call_frame import _STACK
from .m68k_constructor_records import _writes, _successors, _unsupported_frame_or_exception
from .m68k_fallthrough_repair import _direct_data_ranges
from .m68k_seeds import DecoderSeed
from .megadrive_emit import _asm_instruction
from .megadrive_symbols import pc_displacement_target


@dataclass(frozen=True)
class RelativeRecordCallbacks:
    producer: int
    table: int
    records: tuple[int, ...]
    stride: int
    object_register: str
    field: int
    reader: int
    executor: int
    targets: tuple[int, ...]


def _backed(image, fact):
    at = fact.cpu_address - image.header.rom_start
    return (not fact.cpu_address & 1 and 2 <= fact.length <= 10
            and fact.length == len(fact.raw) and not fact.length & 1
            and fact.physical_offset == at
            and 0 <= at <= len(image.data) - fact.length
            and image.data[at:at + fact.length] == fact.raw)


def _word(fact):
    return int.from_bytes(fact.raw[:2], 'big')


def _matches_displacement(fact, opcode, displacement):
    return (fact.length == 4 and _word(fact) == opcode
            and int.from_bytes(fact.raw[2:], 'big', signed=True) == displacement)


def _cursor_stride(rooted, start, cursor, obj, field):
    """All decoded RTS exits consume the same complete record, without calls."""
    pending = deque([(start, 0)])
    visited, returned = set(), set()
    while pending and len(visited) < 512:
        address, offset = state = pending.popleft()
        if state in visited:
            continue
        visited.add(state)
        fact = rooted.get(address)
        if fact is None or offset > 256:
            return None
        if fact.raw == b'\x4e\x75':
            returned.add(offset)
            continue
        if (fact.mnemonic.upper().split('.')[0] in {'JSR', 'BSR'}
                or _unsupported_frame_or_exception(fact) or _STACK.search(fact.operands)):
            return None
        args = fact.operands.upper().split('|')
        writes = _writes(fact)
        if obj.lower() in writes:
            return None
        # A captured cursor alias or an unmodelled pointer update invalidates
        # the layout. Each accepted read consumes the next bytes exactly once.
        if re.search(r'(?<![A-Z0-9])' + cursor + r'[BWL]?(?![A-Z0-9])', fact.operands.upper()):
            widths = {'MOVE.B': 1, 'MOVE.W': 2, 'MOVE.L': 4, 'MOVEA.W': 2, 'MOVEA.L': 4}
            width = widths.get(fact.mnemonic.upper())
            if (width is None or len(args) != 2 or args[0] != f'({cursor})+'
                    or cursor in args[1] or _word(fact) & 0x3f != 0x18 + int(cursor[1])
                    or _word(fact) >> 12 != {1: 1, 2: 3, 4: 2}[width]):
                return None
            offset += width
        elif cursor.lower() in writes:
            return None
        # The initial longword must remain the value subsequently executed.
        operation = fact.mnemonic.upper().split('.')[0]
        readonly = operation in {'CMP', 'CMPA', 'CMPI', 'CMPM', 'TST', 'BTST'}
        object_token = r'(?<![A-Z0-9])' + obj + r'[BWL]?(?![A-Z0-9])'
        if (len(args) == 2 and not readonly
                and (re.fullmatch(obj + r'[BWL]?', args[0])
                     or operation == 'LEA' and re.search(object_token, args[0]))):
            return None  # No newly captured alias may rewrite the callback.
        if (not readonly and '(' in args[-1] and re.search(object_token, args[-1])
                and address != start):
            destination = re.fullmatch(r'\((?:(-?0X[0-9A-F]+),)?' + obj + r'\)', args[-1])
            width = {'.B': 1, '.W': 2, '.L': 4}.get(fact.mnemonic.upper()[-2:])
            if destination is None or width is None:
                return None  # Indexed/unknown object offsets may alias the field.
            at = int(destination[1] or '0', 0)
            if at < field + 4 and field < at + width:
                return None
        successors = _successors(fact)
        if not successors:
            return None
        pending.extend((successor, offset) for successor in successors)
    return next(iter(returned)) if not pending and len(returned) == 1 else None


def _executors(rooted):
    """Keep the exact loaded callback register live through a bounded chain."""
    results = {}
    for load in rooted.values():
        match = re.fullmatch(r'\((-?0x[0-9a-f]+),(A[0-6])\)\|(A[0-6])', load.operands, re.I)
        if load.mnemonic.upper() != 'MOVEA.L' or match is None or load.flow_type.upper() != 'FALL_THROUGH':
            continue
        field, obj, callback = int(match[1], 0), match[2].upper(), match[3].upper()
        if (obj == callback or not _matches_displacement(
                load, 0x2068 | int(callback[1]) << 9 | int(obj[1]), field)):
            continue
        address = load.cpu_address + load.length
        for _ in range(24):
            current = rooted.get(address)
            if current is None:
                break
            if (current.mnemonic.upper() in {'JSR', 'JMP'}
                    and current.operands.upper() == f'({callback})'
                    and current.length == 2
                    and _word(current) == (0x4e90 if current.mnemonic.upper() == 'JSR' else 0x4ed0) + int(callback[1])):
                results.setdefault((obj, field), []).append((load.cpu_address, address))
                break
            if (current.flow_type.upper() != 'FALL_THROUGH'
                    or _unsupported_frame_or_exception(current) or _STACK.search(current.operands)
                    or callback.lower() in _writes(current)):
                break
            address += current.length
    return results


def discover_relative_record_callbacks(image, trusted_facts, decoded_facts, *,
                                       protected_ranges=(), protected_record_ranges=(),
                                       decode_request=None):
    """Both protection arguments contain logical CPU address ranges.

    Pointer-table DATA may be read by the proven record consumer but cannot
    become callback code. ``protected_record_ranges`` additionally excludes
    payloads such as Z80 programs from the table and record inputs.
    """
    origin = image.header.rom_start
    rooted = {f.cpu_address: f for f in trusted_facts.values() if _backed(image, f)}
    decoded = {f.cpu_address: f for f in decoded_facts.values() if _backed(image, f)}
    occupied = {a for f in rooted.values() for a in range(f.cpu_address, f.cpu_address + f.length)}
    interiors = {a for f in rooted.values() for a in range(f.cpu_address + 1, f.cpu_address + f.length)}
    explicit_data = _direct_data_ranges(image, rooted)
    readers = _executors(rooted)
    results = []

    def span(address, length, protected=(), no_code=False):
        at = address - origin
        return (not address & 1 and 0x200 <= at <= len(image.data) - length
                and not any(a < address + length and address < b for a, b in protected)
                and not (no_code and any(a in occupied for a in range(address, address + length))))

    def number(address, width, signed=False):
        at = address - origin
        return int.from_bytes(image.data[at:at + width], 'big', signed=signed)

    for zero in rooted.values():
        match = re.fullmatch(r'#?0x0\|D([0-7])', zero.operands, re.I)
        if zero.mnemonic.upper() != 'MOVEQ' or match is None or zero.flow_type.upper() != 'FALL_THROUGH':
            continue
        index = int(match[1])
        if zero.length != 2 or _word(zero) != 0x7000 | index << 9:
            continue
        code, address = [], zero.cpu_address + zero.length
        for _ in range(4):
            fact = rooted.get(address)
            if fact is None or fact.flow_type.upper() != 'FALL_THROUGH':
                break
            code.append(fact)
            address += fact.length
        if len(code) != 4:
            continue
        selector, lea, add, store = code
        selector_field = re.fullmatch(r'\((-?0x[0-9a-f]+),(A[0-6])\)\|D' + str(index) + 'b', selector.operands, re.I)
        copied = re.fullmatch(r'\((A[0-6])\)\+\|\((-?0x[0-9a-f]+),(A[0-6])\)', store.operands, re.I)
        if selector.mnemonic.upper() != 'MOVE.B' or selector_field is None or store.mnemonic.upper() != 'MOVE.L' or copied is None:
            continue
        cursor, field, obj = copied[1].upper(), int(copied[2], 0), copied[3].upper()
        if (obj == cursor or selector_field[2].upper() != obj or (obj, field) not in readers
                or not _matches_displacement(selector, 0x1028 | index << 9 | int(obj[1]), int(selector_field[1], 0))
                or not _matches_displacement(store, 0x2158 | int(obj[1]) << 9 | int(cursor[1]), field)):
            continue
        absolute = re.fullmatch(r'\((0x[0-9a-f]+)\)\.l\|' + cursor, lea.operands, re.I)
        table = int(absolute[1], 0) if absolute else pc_displacement_target(lea)
        if (lea.mnemonic.upper() != 'LEA' or lea.operands.split('|')[-1].upper() != cursor or table is None
                or absolute and (lea.length != 6 or _word(lea) != 0x41f9 | int(cursor[1]) << 9 or number(lea.cpu_address + 2, 4) != table)
                or not absolute and (lea.length != 4 or _word(lea) != 0x41fa | int(cursor[1]) << 9)):
            continue
        if (add.mnemonic.upper() != 'ADDA.W' or add.operands.upper() != f'(0X0,{cursor},D{index}W*0X1)|{cursor}'
                or add.length != 4 or _word(add) != 0xd0f0 | int(cursor[1]) << 9 | int(cursor[1])
                or int.from_bytes(add.raw[2:], 'big') != index << 12):
            continue
        stride = _cursor_stride(rooted, store.cpu_address, cursor, obj, field)
        if stride is None or not 4 <= stride <= 256 or stride & 1 or not span(table, 2, protected_record_ranges, True):
            continue
        # First record closes the word table. Every slot must corroborate the
        # exact same extent and the stride derived from the producer, rather
        # than merely looking like another positive offset after the table.
        extent = number(table, 2, True)
        if not 4 <= extent <= 256 or extent & 1 or not span(table, extent, protected_record_ranges, True):
            continue
        count = extent // 2
        first = table + extent
        records = tuple(first + slot * stride for slot in range(count))
        if (not span(first, count * stride, protected_record_ranges, True)
                or any(table + number(table + 2 * slot, 2, True) != record for slot, record in enumerate(records))):
            continue
        targets = tuple(number(record, 4) for record in records)
        if len(set(targets)) < 2 or not set(targets) & rooted.keys():
            continue
        valid = True
        for target in targets:
            entry = rooted.get(target) or decoded.get(target)
            if entry is None:
                if decode_request is not None and span(target, 2, protected_ranges):
                    decode_request(target, store.cpu_address, 'relative record callback first instruction')
                valid = False
                continue
            if (_asm_instruction(entry) is None
                    or target in interiors or not span(target, entry.length, (*protected_ranges, *explicit_data))
                    or table < target + entry.length and target < first + count * stride
                    or any(a in occupied for a in range(target, target + entry.length)) and target not in rooted):
                valid = False
        if valid:
            reader, executor = min(readers[(obj, field)])
            results.append(RelativeRecordCallbacks(store.cpu_address, table, records, stride,
                           obj, field, reader, executor, targets))
    return tuple(results)


def discover_relative_record_callback_seeds(image, trusted_facts, decoded_facts, *,
                                            protected_ranges=(), protected_record_ranges=(),
                                            decode_request=None):
    seeds = {}
    for model in discover_relative_record_callbacks(image, trusted_facts, decoded_facts,
            protected_ranges=protected_ranges, protected_record_ranges=protected_record_ranges,
            decode_request=decode_request):
        evidence = (f'rooted relative record producer {model.producer:06X}; signed word table {model.table:06X}, '
                    f'{len(model.records)} contiguous records, complete cursor stride {model.stride}; '
                    f'longword callback field {model.object_register}+{model.field}; rooted reader {model.reader:06X} '
                    f'preserves callback register through indirect execution {model.executor:06X}')
        for target in model.targets:
            seeds.setdefault(target, DecoderSeed(target, 'relative_record_callback', 'high', evidence, model.producer))
    return tuple(seeds[a] for a in sorted(seeds))
