"""Recover ROM callbacks from a narrow persistent-cursor interpreter ABI.

No opcode numbers, ROM addresses, game names or reference listings appear in
the recognizer. It supports only summaries directly witnessed by rooted
machine instructions. An unknown command, cursor update, indirect transfer
or callee effect terminates that stream path.
"""
from collections import deque
from dataclasses import dataclass
import re

from retrolarium_kit.m68k_seeds import DecoderSeed

from retrolarium_kit.megadrive_symbols import pc_indexed_target
from retrolarium_kit.megadrive_pointers import _instruction_sets, _absolute_referenced_addresses
from retrolarium_kit.m68k_constructor_records import _unsupported_frame_or_exception


def _absolute_address(operand):
    match = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.([wl])', operand, re.I)
    if match is None:
        return None
    value = int(match[1], 0)
    if match[2].lower() == 'w':
        value &= 0xffff
        value = value - 0x10000 if value & 0x8000 else value
    return value & 0xffffff


def _immediate(operand):
    match = re.fullmatch(r'#?(-?0x[0-9a-f]+)', operand, re.I)
    return int(match[1], 0) if match else None


def _operands(fact):
    return fact.operands.upper().split('|')


def _chain(facts, start, length):
    result = []
    for index in range(length):
        fact = facts.get(start)
        if fact is None or index < length - 1 and fact.flow_type.upper() != 'FALL_THROUGH':
            return None
        result.append(fact)
        start += fact.length
    return result


@dataclass(frozen=True)
class CursorConsumer:
    read: int
    cursor: int
    cursor_register: str
    selector_register: str
    parameter_register: str
    selector_width: int
    parameter_width: int
    stride: int
    table: int
    call: int


@dataclass(frozen=True)
class _HandlerEffect:
    kind: str
    extra: int = 0
    branch: int | None = None
    indirect: int | None = None
    operand_read: int | None = None


@dataclass(frozen=True)
class CursorCallback:
    target: int
    initialization: int
    cursor: int
    command: int
    selector: int
    selector_width: int
    parameter_width: int
    table: int
    handler: int
    indirect: int
    operand_read: int
    high_word_address: int
    low_word_address: int


def _consumers(image, rooted):
    """Match typed prefetches, cursor writeback and indexed handler execution."""
    result = []
    for first in rooted.values():
        if first.mnemonic.upper() != 'MOVEA.L':
            continue
        args = _operands(first)
        cursor = _absolute_address(args[0])
        if len(args) != 2 or cursor is None or not re.fullmatch(r'A[0-6]', args[1]):
            continue
        if not image.header.ram_start <= cursor <= image.header.ram_end - 3:
            continue
        code = _chain(rooted, first.cpu_address, 7)
        if code is None:
            continue
        _, selector, parameter, save, scale, load, call = code
        a = args[1]
        s, p = _operands(selector), _operands(parameter)
        if (selector.mnemonic.upper() != 'MOVE.W' or parameter.mnemonic.upper() != 'MOVE.W'
                or len(s) != 2 or len(p) != 2 or s[0] != f'({a})+' or p[0] != f'({a})+'
                or not re.fullmatch(r'D[0-7]W', s[1]) or not re.fullmatch(r'D[0-7]W', p[1])
                or s[1] == p[1]):
            continue
        saved, scaled, loaded = _operands(save), _operands(scale), _operands(load)
        table = pc_indexed_target(load)
        if (save.mnemonic.upper() != 'MOVE.L' or len(saved) != 2
                or saved[0] != a or _absolute_address(saved[1]) != cursor
                or scale.mnemonic.upper() not in {'ASL.W', 'LSL.W'} or len(scaled) != 2
                or _immediate(scaled[0]) != 2 or scaled[1] != s[1]
                or load.mnemonic.upper() != 'MOVEA.L' or table is None
                or table[1:] != (int(s[1][1]), 'd', 'w')
                or len(loaded) != 2 or not re.fullmatch(r'A[0-6]', loaded[1])
                or call.mnemonic.upper() != 'JSR' or call.operands.upper() != f'({loaded[1]})'
                or call.flow_type.upper() != 'COMPUTED_CALL'):
            continue
        result.append(CursorConsumer(first.cpu_address, cursor, a, s[1][:-1], p[1][:-1],
                               2, 2, 4, table[0], call.cpu_address))
    return tuple(result)


def _summarize(rooted, consumer, address, *, active=()):
    """Strict handler templates; each accepted template covers its complete CFG."""
    if address in active or len(active) >= 8:
        return None
    first = rooted.get(address)
    if first is None or _unsupported_frame_or_exception(first):
        return None
    args = _operands(first)
    next_address = address + first.length
    # Conditions do not choose one concrete flag value: retain both branches.
    if (first.mnemonic.upper() in {'TST.B', 'TST.W', 'TST.L'} and len(args) == 1
            and _absolute_address(args[0]) is not None):
        branch = rooted.get(next_address)
        if (branch and branch.flow_type.upper() == 'CONDITIONAL_JUMP' and len(branch.flows) == 1
                and branch.mnemonic.upper().startswith('B')):
            left = _summarize(rooted, consumer, branch.flows[0], active=(*active, address))
            right = _summarize(rooted, consumer, next_address + branch.length, active=(*active, address))
            return (*left, *right) if left is not None and right is not None else None
    if (first.mnemonic.upper() in {'BRA.B', 'BRA.W', 'JMP'} and len(first.flows) == 1
            and first.flow_type.upper() in {'UNCONDITIONAL_JUMP', 'CALL_TERMINATOR'}):
        return _summarize(rooted, consumer, first.flows[0], active=(*active, address))
    if first.mnemonic.upper() in {'ADDQ.L', 'SUBQ.L'} and len(args) == 2:
        amount = _immediate(args[0])
        end = rooted.get(next_address)
        if (amount is not None and 1 <= amount <= 8 and _absolute_address(args[1]) == consumer.cursor
                and end and end.raw == b'\x4e\x75'):
            return (_HandlerEffect('advance', amount if first.mnemonic.upper() == 'ADDQ.L' else -amount),)
    if first.raw == b'\x4e\x75':
        return (_HandlerEffect('advance'),)
    # Reassemble a full code/stream pointer from the prefetched high word and
    # one explicitly read low word. SWAP moves the unknown old high bits down;
    # MOVE.W overwrites exactly those bits, leaving no unknown target bits.
    if (first.mnemonic.upper() != 'MOVEA.L' or len(args) != 2
            or _absolute_address(args[0]) != consumer.cursor or not re.fullmatch(r'A[0-6]', args[1])):
        return None
    code = _chain(rooted, address, 4)
    if code is None:
        return None
    _, swap, low, store = code
    a, d = args[1], consumer.parameter_register
    low_args, store_args = _operands(low), _operands(store)
    if (swap.mnemonic.upper() != 'SWAP' or swap.operands.upper() != d
            or low.mnemonic.upper() != 'MOVE.W' or len(low_args) != 2
            or low_args[0] not in {f'({a})', f'({a})+'} or low_args[1] != d + 'W'
            or store.mnemonic.upper() != 'MOVE.L' or len(store_args) != 2
            or _absolute_address(store_args[1]) != consumer.cursor):
        return None
    end = store.cpu_address + store.length
    if store_args[0] == d and low_args[0] == f'({a})':
        ret = rooted.get(end)
        return (_HandlerEffect('jump', operand_read=low.cpu_address),) if ret and ret.raw == b'\x4e\x75' else None
    tail = _chain(rooted, end, 2)
    if store_args[0] != a or low_args[0] != f'({a})+' or tail is None:
        return None
    move, jump = tail
    target_args = _operands(move)
    if (move.mnemonic.upper() != 'MOVEA.L' or len(target_args) != 2 or target_args[0] != d
            or not re.fullmatch(r'A[0-6]', target_args[1]) or jump.mnemonic.upper() != 'JMP'
            or jump.operands.upper() != f'({target_args[1]})'
            or jump.flow_type.upper() != 'COMPUTED_JUMP'):
        return None
    return (_HandlerEffect('callback', 2, indirect=jump.cpu_address, operand_read=low.cpu_address),)


def discover_bytecode_callbacks(image, facts, *, execution_facts=None, protected_ranges=(),
                                protected_stream_ranges=(), max_commands=256):
    """Read proved VM data, protecting callback targets from code promotion.

    Both range arguments use logical CPU addresses. ``protected_ranges`` can
    contain accepted pointer tables: their bytes may be read by the exact
    typed consumer, but never promoted as callback code. Separate stream
    protection can exclude Z80 payloads without excluding pointer data.
    """
    if execution_facts is None:
        return (), (), ()
    origin = image.header.rom_start
    rooted = {f.cpu_address: f for f in execution_facts.values()
              if 0 <= f.cpu_address - origin <= len(image.data) - f.length
              and image.data[f.cpu_address-origin:f.cpu_address-origin+f.length] == f.raw}
    occupied, interiors, _ = _instruction_sets(facts)
    data_targets = _absolute_referenced_addresses(rooted)

    def rom_span(address, length, *, no_code=False, protected=()):
        physical = address - origin
        return (address & 1 == 0 and 0x200 <= physical <= len(image.data) - length
                and not any(a < address + length and address < b for a, b in protected)
                and not (no_code and any(a in occupied for a in range(physical, physical + length))))

    def u16(address):
        p = address - origin
        return int.from_bytes(image.data[p:p+2], 'big')

    def u32(address):
        p = address - origin
        return int.from_bytes(image.data[p:p+4], 'big')

    models = _consumers(image, rooted)
    found, stops, consumed_data = {}, [], set()
    for model in models:
        roots = []
        for initializer in rooted.values():
            args = _operands(initializer)
            if initializer.mnemonic.upper() != 'MOVE.L' or len(args) != 2:
                continue
            root = _immediate(args[0])
            if (root is not None and _absolute_address(args[1]) == model.cursor
                    and rom_span(root, 4, no_code=True, protected=protected_stream_ranges)):
                roots.append((initializer.cpu_address, root))
        for init, root in roots:
            todo, visited = deque([root]), set()
            while todo and len(visited) < max_commands:
                cursor = todo.popleft()
                if cursor in visited:
                    continue
                visited.add(cursor)
                if not rom_span(cursor, 4, no_code=True, protected=protected_stream_ranges):
                    stops.append((init, cursor, 'invalid_or_protected_command'))
                    continue
                selector = u16(cursor)
                consumed_data.update(range(cursor, cursor + 4))
                # The real .W index is signed after a .W shift. Exclude
                # negative/wrapped indices instead of inventing table bounds.
                slot = model.table + selector * model.stride
                if selector * model.stride > 0x7fff or not rom_span(slot, 4, no_code=True):
                    stops.append((init, cursor, 'invalid_selector_slot'))
                    continue
                handler = u32(slot)
                consumed_data.update(range(slot, slot + 4))
                summary = _summarize(rooted, model, handler)
                if summary is None:
                    stops.append((init, cursor, 'unsupported_opcode_handler'))
                    continue
                next_cursor = cursor + model.selector_width + model.parameter_width
                for effect in summary:
                    if effect.kind == 'advance':
                        todo.append(next_cursor + effect.extra)
                        continue
                    if not rom_span(next_cursor, 2, no_code=True, protected=protected_stream_ranges):
                        stops.append((init, cursor, 'invalid_low_word'))
                        continue
                    target = u16(cursor + model.selector_width) << 16 | u16(next_cursor)
                    consumed_data.update(range(next_cursor, next_cursor + 2))
                    if effect.kind == 'jump':
                        todo.append(target)
                        continue
                    if (not rom_span(target, 2, protected=protected_ranges)
                            or target-origin in interiors or target in data_targets
                            or image.data[target-origin:target-origin+2] in {b'\x00\x00', b'\xff\xff'}):
                        stops.append((init, cursor, 'protected_or_invalid_callback'))
                        continue
                    found[(target, init, cursor)] = CursorCallback(target, init, model.cursor, cursor, selector,
                        model.selector_width, model.parameter_width, model.table, handler, effect.indirect,
                        effect.operand_read, cursor + model.selector_width, next_cursor)
                    # A callback can write the persistent cursor. Do not assume
                    # the interpreter resumes at the locally advanced pointer.
                    stops.append((init, cursor, 'callback_return_effect_not_summarized'))
            if todo:
                stops.append((init, root, 'command_limit'))
    callbacks = tuple(c for c in found.values()
                      if not any(address in consumed_data for address in range(c.target, c.target + 2)))
    return callbacks, models, tuple(stops)


def discover_bytecode_cursor_seeds(image, facts, *, execution_facts=None, protected_ranges=(),
                                  protected_stream_ranges=()):
    """Expose proved stream callback operands; never assume callback return effects."""
    callbacks, _, _ = discover_bytecode_callbacks(image, facts,
        execution_facts=execution_facts, protected_ranges=protected_ranges,
        protected_stream_ranges=protected_stream_ranges)
    seeds = {}
    for call in callbacks:
        evidence = (
            f"rooted cursor initialization {call.initialization:06X}; RAM cursor {call.cursor:06X}; "
            f"command {call.command:06X}, selector {call.selector}, "
            f"selector width {call.selector_width}, parameter width {call.parameter_width}; "
            f"indexed handler table {call.table:06X}, handler {call.handler:06X}; "
            f"callback high/low words at {call.high_word_address:06X}/{call.low_word_address:06X}; "
            f"SWAP plus word read {call.operand_read:06X}, indirect execution {call.indirect:06X}; "
            "stream walk stops after callback without assuming cursor preservation"
        )
        seeds.setdefault(call.target, DecoderSeed(call.target, "bytecode_cursor_callback",
                                                  "proven", evidence, call.indirect))
    return tuple(seeds[address] for address in sorted(seeds))
