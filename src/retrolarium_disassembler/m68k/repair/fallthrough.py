"""Canonical next-instruction proofs, never independent code roots.

A rooted ordinary instruction fixes the next PC. A pseudo decode at exactly
that PC can replace conflicting unrooted backend boundaries after checking
the entire cleared span. These proofs persist across fresh decoder imports;
they do not permit clearing data or following an unproved call return.
"""
from dataclasses import dataclass

from .m68k_abstract import _register_list
from .m68k_constructor_records import _unsupported_frame_or_exception
from .megadrive_emit import _asm_instruction
from .megadrive_pointers import _absolute_referenced_addresses


def _intersects(start, end, ranges):
    return any(a < end and start < b for a, b in ranges)


def _ordinary_source(fact):
    base = fact.mnemonic.upper().split('.')[0]
    word = int.from_bytes(fact.raw[:2], 'big')
    return (fact.flow_type.upper() in {'FALL_THROUGH', 'CONDITIONAL_JUMP'}
            and base not in {'JSR', 'BSR', 'JMP', 'BRA', 'RTS', 'RTE', 'RTR',
                            'DIVU', 'DIVS', 'DIVUL', 'DIVSL'}
            and not _unsupported_frame_or_exception(fact)
            and fact.operands.upper().split('|')[-1] != 'SR'
            and not any(address & 1 for address in fact.flows)
            and word & 0xffc0 not in {0x4e80, 0x4ec0}
            and word & 0xff00 != 0x6100)


def _direct_data_ranges(image, facts):
    origin = image.header.rom_start
    ranges = set()
    for fact in facts.values():
        width = (4 if fact.mnemonic.upper().endswith('.L') else
                 1 if fact.mnemonic.upper().endswith('.B') else 2)
        if fact.mnemonic.upper().split('.')[0] == 'MOVEM':
            registers = _register_list(fact.operands.split('|')[-1])
            width *= len(registers) if registers else 16
        # Register, immediate and inferred (An) references are not direct ROM
        # reads. In particular, inferred values cannot turn operand bytes into
        # protected objects. MOVEM reads protect every register's scalar.
        for address in _absolute_referenced_addresses({fact.cpu_address: fact}):
            address &= 0xffffff
            if origin <= address < origin + len(image.data):
                ranges.add((address, address + width))
    return tuple(sorted(ranges))


@dataclass(frozen=True)
class M68kRepairConflict:
    address: int
    raw_bytes: str


@dataclass(frozen=True)
class M68kFallthroughRepair:
    source_address: int
    source_bytes: str
    address: int
    raw_bytes: str
    conflicts: tuple[M68kRepairConflict, ...]
    confidence: str = 'proven'
    kind: str = 'ordinary_fallthrough_repair'

    @property
    def evidence(self):
        return (f'rooted ordinary fallthrough from {self.source_address:06X}; '
                f'canonical instruction at {self.address:06X}; '
                'full conflicting-unit spans exclude trusted code, roots and data')


class M68kFallthroughRepairs:
    """Image-scoped repair evidence and current replay protections.

    All public addresses and protected ranges are logical addresses. A probe
    request is only a hypothesis. The next decoder pass rechecks a successful
    proof against its actual listing before it may clear any code unit.
    """

    def __init__(self, image, *, minimum_address=None, max_repairs=4096):
        if not 1 <= max_repairs <= 4096:
            raise ValueError('invalid M68K repair budget')
        self.image = image
        self.minimum_address = (image.header.rom_start + 0x200
                                if minimum_address is None else minimum_address)
        if self.minimum_address < image.header.rom_start:
            raise ValueError('M68K repair lower bound precedes image')
        self.max_repairs = max_repairs
        self.repairs: dict[int, M68kFallthroughRepair] = {}
        self.deferred: set[int] = set()
        self._trusted = {}
        self._protected = ()
        self._strong = ()
        self._planned = set()

    def _backed(self, fact):
        physical = fact.cpu_address - self.image.header.rom_start
        return (fact.physical_offset == physical and physical >= 0
                and fact.length == len(fact.raw) and 2 <= fact.length <= 10
                and not fact.length & 1
                and physical + fact.length <= len(self.image.data)
                and self.image.data[physical:physical + fact.length] == fact.raw)

    def discover(self, raw_facts, trusted_facts, probe_facts, *,
                 protected_ranges=(), planned_roots=(), decode_request=None):
        self._trusted = {f.cpu_address: f for f in trusted_facts.values()}
        self._protected = tuple(protected_ranges)
        self._planned = set(planned_roots)
        self._strong = _direct_data_ranges(self.image, self._trusted)
        raw = {f.cpu_address: f for f in raw_facts.values()}
        probes = {f.cpu_address: f for f in probe_facts.values()}
        spans = tuple((f.cpu_address, f.cpu_address + f.length)
                      for f in self._trusted.values())
        forbidden = (*self._protected, *self._strong)
        image_end = self.image.header.rom_start + len(self.image.data)
        added = []
        for source in sorted(self._trusted.values(), key=lambda f: f.cpu_address):
            if not _ordinary_source(source) or not self._backed(source):
                continue
            target = source.cpu_address + source.length
            if (target in raw or target & 1
                    or not self.minimum_address <= target <= image_end - 2
                    or _intersects(target, target + 2, (*spans, *forbidden))):
                continue
            candidate = probes.get(target)
            if candidate is None:
                if decode_request is not None:
                    decode_request(target, source.cpu_address, 'rooted ordinary missing fallthrough')
                continue
            if (not self._backed(candidate) or _asm_instruction(candidate) is None
                    or any(address & 1 for address in candidate.flows)):
                continue
            end = target + candidate.length
            conflicts = tuple(f for f in raw.values()
                              if f.cpu_address < end and target < f.cpu_address + f.length)
            cleanup_end = max([end, *(f.cpu_address + f.length for f in conflicts)])
            if (cleanup_end > image_end
                    or _intersects(target, cleanup_end, (*spans, *forbidden))
                    or any(target < address < cleanup_end for address in self._planned)
                    or any(f.cpu_address < target or f.cpu_address in self._trusted
                           or not self._backed(f) for f in conflicts)):
                continue
            if target not in self.repairs and len(self.repairs) >= self.max_repairs:
                self.deferred.add(target)
                continue
            repair = M68kFallthroughRepair(
                source.cpu_address, source.raw.hex(), target, candidate.raw.hex(),
                tuple(M68kRepairConflict(f.cpu_address, f.raw.hex())
                      for f in sorted(conflicts, key=lambda f: f.cpu_address)))
            # A fresh backend import can choose a different orphan boundary.
            # Reprove its complete current span and report a changed plan as
            # progress; an unchanged failed proof cannot keep the loop alive.
            if self.repairs.get(target) == repair:
                continue
            self.repairs[target] = repair
            self.deferred.discard(target)
            added.append(repair)
        return tuple(added)

    def plan_text(self, *, trusted_facts=None, protected_ranges=None, planned_roots=None):
        if trusted_facts is not None:
            self._trusted = {f.cpu_address: f for f in trusted_facts.values()}
            self._strong = _direct_data_ranges(self.image, self._trusted)
        if protected_ranges is not None:
            self._protected = tuple(protected_ranges)
        if planned_roots is not None:
            self._planned = set(planned_roots)
        lines = [f'TRUSTED\t{a:06X}\t{f.raw.hex()}' for a, f in sorted(self._trusted.items())]
        lines += [f'PROTECT_DATA\t{a:06X}\t{b:06X}'
                  for a, b in sorted(set((*self._protected, *self._strong)))]
        lines += [f'ROOT\t{a:06X}' for a in sorted(self._planned)]
        # Insertion order preserves dependencies: a later source may itself
        # be the instruction restored by an earlier proof.
        for repair in self.repairs.values():
            conflicts = ','.join(f'{c.address:06X}:{c.raw_bytes}' for c in repair.conflicts) or '-'
            lines.append(f'REPAIR\t{repair.source_address:06X}\t{repair.source_bytes}\t'
                         f'{repair.address:06X}\t{repair.raw_bytes}\t{conflicts}')
        return '\n'.join(lines) + ('\n' if lines else '')
