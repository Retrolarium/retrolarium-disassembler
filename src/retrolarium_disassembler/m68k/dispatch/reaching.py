"""Recover word dispatch tables through reaching register definitions.

Only rooted instructions may be supplied. Every predecessor must preserve a
table base from a LEA and a word index from its scale to the consuming load.
Alternative bases remain independent: offsets from one table are never added
to another base. Unknown calls, unsupported exceptions and cycles reject the
proof; the reference listing does not participate.
"""
from collections import defaultdict
from dataclasses import dataclass
import re

from retrolarium_disassembler.m68k.records.constructor import _writes, _unsupported_frame_or_exception
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_disassembler.m68k.instructions import pc_displacement_target
from retrolarium_disassembler.m68k.instructions import absolute_referenced_addresses, instruction_sets


@dataclass(frozen=True)
class ReachingWordTable:
    lea: int
    table: int
    load: int
    transfer: int
    scales: tuple[int, ...]
    end: int
    targets: tuple[int, ...]
    witness: str


def _predecessors(facts):
    incoming = defaultdict(set)
    for address, fact in facts.items():
        base = fact.mnemonic.upper().split('.')[0]
        flow = fact.flow_type.upper()
        call = base in {'JSR', 'BSR'}
        if flow in {'FALL_THROUGH', 'CONDITIONAL_JUMP'} or call:
            incoming[address + fact.length].add((address, 'normal'))
        for target in fact.flows:
            if call:
                incoming[target & 0xFFFFFF].add((address, 'external_call'))
            elif flow in {'CONDITIONAL_JUMP', 'UNCONDITIONAL_JUMP', 'COMPUTED_JUMP'}:
                incoming[target & 0xFFFFFF].add((address, 'normal'))
    return incoming


def _direct_table(fact):
    table = pc_displacement_target(fact)
    absolute = re.fullmatch(r'\((-?0x[0-9a-f]+)\)\.[wl]\|A[0-6]', fact.operands, re.I)
    if table is None and absolute:
        table = int(absolute[1], 0) & 0xFFFFFF
    return table


class _Definitions:
    def __init__(self, facts, incoming, roots, consumer):
        self.facts, self.incoming, self.roots = facts, incoming, roots
        self.consumer = consumer

    def find(self, register, kind):
        memo, active = {}, set()

        def before(address):
            if address in self.roots or not self.incoming[address]:
                return None
            result = set()
            for predecessor, edge in self.incoming[address]:
                if edge != 'normal':
                    return None
                child = visit(predecessor)
                if child is None:
                    return None
                result.update(child)
            return frozenset(result)

        def visit(address):
            if address in memo:
                return memo[address]
            if address in active or len(memo) + len(active) >= 128:
                return None
            fact = self.facts.get(address)
            if fact is None or not self.consumer - 128 <= address < self.consumer:
                return None
            operation = fact.mnemonic.upper()
            base = operation.split('.')[0]
            if base in {'JSR', 'BSR', 'RTS'} or _unsupported_frame_or_exception(fact):
                return None
            if kind == 'table' and operation == 'LEA' and fact.operands.split('|')[-1].lower() == register:
                table = _direct_table(fact)
                return frozenset({(address, table)}) if table is not None else None
            if register in _writes(fact):
                if (kind == 'scale' and operation == 'ADD.W'
                        and fact.operands.lower() == register + 'w|' + register + 'w'):
                    return frozenset({(address, 2)})
                return None
            flow = fact.flow_type.upper()
            if (flow not in {'FALL_THROUGH', 'CONDITIONAL_JUMP', 'UNCONDITIONAL_JUMP'}
                    or flow == 'UNCONDITIONAL_JUMP' and (base not in {'BRA', 'JMP'} or len(fact.flows) != 1)):
                return None
            active.add(address)
            result = before(address)
            active.remove(address)
            memo[address] = result
            return result

        return before(self.consumer)

    def has_prior_scale(self, scale, register):
        """Do not interpret a four-byte record as two independent pointers.

        A memory load supplies fresh low bits; constants used by arithmetic
        and logical operations do not erase the earlier value's provenance.
        Walk through those operations to detect an earlier scale, and reject
        any other unsupported write instead of treating it as fresh input.
        """
        seen, active = set(), set()
        def before(address):
            # A root permits an unknown incoming index, but must not hide a
            # visible earlier scale on another decoded incoming path.
            for predecessor, edge in self.incoming[address]:
                if edge != 'normal' or visit(predecessor):
                    return True
            return False
        def visit(address):
            if address in active:
                return True
            if address in seen:
                return False
            fact = self.facts.get(address)
            if fact is None or not scale - 128 <= address < scale or len(seen) >= 128:
                return True
            operation = fact.mnemonic.upper()
            base = operation.split('.')[0]
            if base in {'JSR', 'BSR', 'RTS'} or _unsupported_frame_or_exception(fact):
                return True
            if (operation in {'ADD.W', 'ADD.L'} and
                    fact.operands.lower().replace('w', '') == register + '|' + register):
                return True
            if operation.startswith(('ASL', 'LSL', 'MUL')) and register in _writes(fact):
                return True
            if register in _writes(fact):
                operands = fact.operands.lower().split('|')
                # Even a byte load replaces the low index bits, so a scale
                # before that fresh memory value cannot imply a record stride.
                if (operation in {'MOVE.B', 'MOVE.W', 'MOVE.L'} and len(operands) == 2
                        and operands[0].startswith('(')
                        and re.fullmatch(register + r'[bwl]?', operands[-1])):
                    return False
                immediate = (len(operands) == 2
                             and re.fullmatch(r'#?-?0x[0-9a-f]+', operands[0])
                             and re.fullmatch(register + r'[bwl]?', operands[-1]))
                if not (immediate and base in {'ADD', 'ADDI', 'ADDQ', 'SUB', 'SUBI', 'SUBQ',
                                               'ANDI', 'ORI', 'EORI'}):
                    return True
            flow = fact.flow_type.upper()
            if (flow not in {'FALL_THROUGH', 'CONDITIONAL_JUMP', 'UNCONDITIONAL_JUMP'}
                    or flow == 'UNCONDITIONAL_JUMP' and (base not in {'BRA', 'JMP'} or len(fact.flows) != 1)):
                return True
            active.add(address)
            result = before(address)
            active.remove(address)
            seen.add(address)
            return result
        return before(scale)

    def index_masks(self, scale, register):
        """Find a dominating word AND on every incoming path, if available.

        Unknown input is allowed before the AND. No intervening index write
        is ignored, so a later ADD/SUB or partial register load makes this
        bound unavailable. Returning None keeps the separately validated
        structural scan; it does not invent an index range.
        """
        memo, active = {}, set()

        def before(address):
            if address in self.roots or not self.incoming[address]:
                return None
            result = set()
            for predecessor, edge in self.incoming[address]:
                if edge != 'normal':
                    return None
                masks = visit(predecessor)
                if masks is None:
                    return None
                result.update(masks)
            return frozenset(result)

        def visit(address):
            if address in memo:
                return memo[address]
            if address in active or len(memo) + len(active) >= 128:
                return None
            fact = self.facts.get(address)
            if fact is None or not scale - 128 <= address < scale:
                return None
            if _unsupported_frame_or_exception(fact) or fact.mnemonic.upper().split('.')[0] in {'JSR', 'BSR'}:
                return None
            if register in _writes(fact):
                match = re.fullmatch(r'#?(0x[0-9a-f]+)\|' + register + 'w', fact.operands, re.I)
                if fact.mnemonic.upper() != 'ANDI.W' or match is None:
                    return None
                mask = int(match[1], 0)
                return frozenset({mask}) if 0 <= mask < 0x4000 else None
            active.add(address)
            result = before(address)
            active.remove(address)
            memo[address] = result
            return result

        return before(scale)


def make_word_index_mask_reader(facts, *, entrypoints=()):
    """Return a cached, facts-scoped query for masks before an ADD.W scale.

    A result is the union of possible AND masks over every incoming path;
    None means no safe finite restriction was established. Later writes,
    including arithmetic, invalidate this narrow bound instead of silently
    reusing an earlier mask. No ROM-specific state is retained globally.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    incoming = _predecessors(by_address)
    roots = frozenset(entrypoints)
    cache = {}

    def masks_before(scale_address, register):
        key = scale_address, register.lower()
        if key not in cache:
            proof = _Definitions(by_address, incoming, roots, scale_address)
            cache[key] = proof.index_masks(scale_address, register.lower())
        return cache[key]

    return masks_before


def discover_reaching_word_dispatch_tables(image, facts, *, entrypoints=(), handler_validator=None):
    """Inspect a supplied trusted CFG; do not use raw backend islands here."""
    facts = {fact.cpu_address: fact for fact in facts.values()}
    incoming = _predecessors(facts)
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    roots = frozenset(entrypoints) | {vector.address for vector in image.vector_table[1:]}
    occupied, interiors, starts = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    results = []
    validated = {}

    def is_code_target(target):
        if target in starts:
            return True
        if handler_validator is None:
            return False
        if target not in validated:
            validated[target] = handler_validator(target)
        return validated[target]
    for call in facts.values():
        if call.mnemonic.upper() not in {'JSR', 'JMP'} or call.flow_type.upper() not in {'COMPUTED_CALL', 'COMPUTED_JUMP'}:
            continue
        match = re.fullmatch(r'\(0x0,(A[0-6]),(D[0-7])w\*0x1\)', call.operands, re.I)
        if match is None:
            continue
        ar, dr = match[1].lower(), match[2].lower()
        load = ends.get(call.cpu_address)
        if (load is None or load.mnemonic.upper() != 'MOVE.W'
                or load.flow_type.upper() != 'FALL_THROUGH'
                or load.operands.lower() != f'(0x0,{ar},{dr}w*0x1)|{dr}w'
                or call.cpu_address in roots
                or incoming[call.cpu_address] != {(load.cpu_address, 'normal')}):
            continue
        proof = _Definitions(facts, incoming, roots, load.cpu_address)
        bases, scales = proof.find(ar, 'table'), proof.find(dr, 'scale')
        if (not bases or not scales
                or any(proof.has_prior_scale(address, dr) for address, _ in scales)):
            continue
        mask_paths = [proof.index_masks(address, dr) for address, _ in scales]
        masks = frozenset().union(*mask_paths) if all(mask_paths) else None
        for lea, table in sorted(bases):
            physical, at = table - image.header.rom_start, table - image.header.rom_start
            limit = min(at + 512, len(image.data))
            if masks:
                limit = min(limit, physical + 2 * (max(masks) + 1))
            targets, count = [], 0
            while 0x200 <= at and at + 2 <= limit and not at & 1:
                if count and image.header.rom_start + at in boundaries:
                    break
                if at in occupied or at + 1 in occupied or image.header.rom_start + at + 1 in boundaries:
                    break
                index = (at - physical) // 2
                if masks and not any(index & ~mask == 0 for mask in masks):
                    at += 2
                    continue
                target = table + int.from_bytes(image.data[at:at + 2], 'big', signed=True)
                target_physical = target - image.header.rom_start
                if (target & 1 or not 0x200 <= target_physical <= len(image.data) - 2
                        or physical <= target_physical < at + 2
                        or image.data[target_physical:target_physical + 2] in {b'\0\0', b'\xff\xff'}):
                    break
                if target_physical not in interiors and is_code_target(target):
                    targets.append(target)
                count += 1
                if target_physical > at:
                    limit = min(limit, target_physical)
                at += 2
            if masks:
                extent = 'index restricted by dominating word AND mask(s) ' + ','.join(f'{m:04X}' for m in sorted(masks))
            else:
                extent = 'heuristic extent bounded by references, occupied bytes and forward targets'
            witness = extent + '; every target is rooted or has its own complete bounded handler CFG'
            if count >= 2 and targets:
                results.append(ReachingWordTable(lea, table, load.cpu_address, call.cpu_address,
                                                tuple(sorted(address for address, _ in scales)),
                                                image.header.rom_start + at, tuple(sorted(set(targets))), witness))
    return tuple(results)


def discover_reaching_word_dispatch_seeds(image, facts, *, entrypoints=(), handler_validator=None):
    """Return decoder roots from the ROM-only reaching-definition proofs."""
    seeds = {}
    for table in discover_reaching_word_dispatch_tables(
            image, facts, entrypoints=entrypoints, handler_validator=handler_validator):
        evidence = (
            f'rooted LEA {table.lea:06X} loads table {table.table:06X}; '
            f'all incoming paths retain word scale at '
            f'{",".join(f"{address:06X}" for address in table.scales)}; '
            f'MOVE.W {table.load:06X} reads a signed offset and unchanged-base '
            f'indexed transfer {table.transfer:06X} consumes it; {table.witness}'
        )
        for target in table.targets:
            seeds.setdefault(target, DecoderSeed(target, 'reaching_word_dispatch', 'high',
                                                 evidence, table.transfer))
    return tuple(seeds[address] for address in sorted(seeds))
