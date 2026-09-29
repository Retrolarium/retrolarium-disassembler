"""Abstract values and conservative entry-point evidence for Motorola 68000."""

from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from enum import Enum
from math import gcd
import re

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .megadrive_symbols import pc_indexed_target


MAX_SMALL_SET = 32
MAX_BACKEND_COMPUTED_FLOW_TARGETS = 32
MAX_TRUSTED_ROOT_PASSES = 64
REGISTER_NAMES = tuple(
    [f"d{index}" for index in range(8)]
    + [f"a{index}" for index in range(8)]
)
FLAG_NAMES = tuple("XNZVC")


class ValueKind(str, Enum):
    UNKNOWN = "unknown"
    CONSTANT = "constant"
    SMALL_SET = "small_set"
    RANGE = "range"


class TruthValue(str, Enum):
    FALSE = "false"
    TRUE = "true"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AbstractValue:
    kind: ValueKind
    bits: int = 32
    values: tuple[int, ...] = ()
    lower: int = 0
    upper: int = 0
    step: int = 1
    address_space: str = "scalar"

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    @classmethod
    def unknown(cls, bits: int = 32) -> AbstractValue:
        return cls(ValueKind.UNKNOWN, bits=bits)

    @classmethod
    def constant(
        cls, value: int, bits: int = 32, *, address_space: str = "scalar"
    ) -> AbstractValue:
        return cls(
            ValueKind.CONSTANT,
            bits=bits,
            values=(value & ((1 << bits) - 1),),
            address_space=address_space,
        )

    @classmethod
    def small_set(
        cls,
        values: set[int] | frozenset[int] | tuple[int, ...] | list[int],
        bits: int = 32,
        *,
        address_space: str = "scalar",
    ) -> AbstractValue:
        normalized = tuple(sorted({value & ((1 << bits) - 1) for value in values}))
        if not normalized:
            return cls.unknown(bits)
        if len(normalized) == 1:
            return cls.constant(
                normalized[0], bits, address_space=address_space
            )
        if len(normalized) <= MAX_SMALL_SET:
            return cls(
                ValueKind.SMALL_SET,
                bits=bits,
                values=normalized,
                address_space=address_space,
            )
        steps = [
            right - left for left, right in zip(normalized, normalized[1:])
        ]
        step = gcd(*steps) if steps else 1
        return cls.interval(
            normalized[0],
            normalized[-1],
            step,
            bits,
            address_space=address_space,
        )

    @classmethod
    def interval(
        cls,
        lower: int,
        upper: int,
        step: int = 1,
        bits: int = 32,
        *,
        address_space: str = "scalar",
    ) -> AbstractValue:
        mask = (1 << bits) - 1
        if lower < 0 or upper < lower or upper > mask or step <= 0:
            return cls.unknown(bits)
        if lower == upper:
            return cls.constant(lower, bits, address_space=address_space)
        return cls(
            ValueKind.RANGE,
            bits=bits,
            lower=lower,
            upper=upper,
            step=step,
            address_space=address_space,
        )

    def concrete_values(self, limit: int = MAX_SMALL_SET) -> tuple[int, ...] | None:
        if self.kind in {ValueKind.CONSTANT, ValueKind.SMALL_SET}:
            return self.values if len(self.values) <= limit else None
        if self.kind == ValueKind.RANGE:
            count = (self.upper - self.lower) // self.step + 1
            if count <= limit:
                return tuple(range(self.lower, self.upper + 1, self.step))
        return None

    def bounds(self) -> tuple[int, int] | None:
        if self.kind in {ValueKind.CONSTANT, ValueKind.SMALL_SET}:
            return self.values[0], self.values[-1]
        if self.kind == ValueKind.RANGE:
            return self.lower, self.upper
        return None

    def stride(self) -> int:
        if self.kind == ValueKind.RANGE:
            return self.step
        if len(self.values) > 1:
            return gcd(*(
                right - left
                for left, right in zip(self.values, self.values[1:])
            ))
        return 0

    def join(self, other: AbstractValue) -> AbstractValue:
        if self == other:
            return self
        if self.bits != other.bits:
            return AbstractValue.unknown(max(self.bits, other.bits))
        if self.kind == ValueKind.UNKNOWN or other.kind == ValueKind.UNKNOWN:
            return AbstractValue.unknown(self.bits)
        space = (
            self.address_space
            if self.address_space == other.address_space
            else "scalar"
        )
        left = self.concrete_values()
        right = other.concrete_values()
        if left is not None and right is not None:
            return AbstractValue.small_set(
                set(left) | set(right), self.bits, address_space=space
            )
        left_bounds = self.bounds()
        right_bounds = other.bounds()
        if left_bounds is None or right_bounds is None:
            return AbstractValue.unknown(self.bits)
        lower = min(left_bounds[0], right_bounds[0])
        upper = max(left_bounds[1], right_bounds[1])
        differences = [self.step, other.step, abs(left_bounds[0] - right_bounds[0])]
        step = gcd(*(value for value in differences if value)) or 1
        return AbstractValue.interval(
            lower, upper, step, self.bits, address_space=space
        )

    def widen(self, other: AbstractValue) -> AbstractValue:
        joined = self.join(other)
        if self.kind != ValueKind.RANGE:
            return joined
        bounds = joined.bounds()
        if bounds is None:
            return joined
        lower = 0 if bounds[0] < self.lower else self.lower
        upper = self.mask if bounds[1] > self.upper else self.upper
        strides = [value for value in (self.stride(), other.stride()) if value]
        return AbstractValue.interval(
            lower,
            upper,
            gcd(*strides) if strides else 1,
            self.bits,
            address_space=joined.address_space,
        )

    def add(self, other: AbstractValue) -> AbstractValue:
        left = self.concrete_values()
        right = other.concrete_values()
        if left is None or right is None or len(left) * len(right) > 64:
            return AbstractValue.unknown(max(self.bits, other.bits))
        bits = max(self.bits, other.bits)
        return AbstractValue.small_set(
            {a + b for a in left for b in right},
            bits,
            address_space=self.address_space,
        )

    def subtract(self, other: AbstractValue) -> AbstractValue:
        values = other.concrete_values()
        if values is None:
            return AbstractValue.unknown(max(self.bits, other.bits))
        negated = AbstractValue.small_set(
            {-value for value in values}, max(self.bits, other.bits)
        )
        return self.add(negated)

    def bitwise_and(self, mask: int) -> AbstractValue:
        mask &= self.mask
        values = self.concrete_values()
        if values is not None:
            return AbstractValue.small_set(
                {value & mask for value in values}, self.bits
            )
        # Every possible result of x & mask is a submask of mask. Keeping the
        # exact submasks for small masks is especially useful for 68000 branch
        # selectors such as ANDI.W #$C,D0 -> {0, 4, 8, 12}.
        if (1 << mask.bit_count()) <= MAX_SMALL_SET:
            submasks = {0}
            value = mask
            while value:
                submasks.add(value)
                value = (value - 1) & mask
            return AbstractValue.small_set(submasks, self.bits)
        return AbstractValue.interval(0, mask, 1, self.bits)


@dataclass(frozen=True)
class AbstractState:
    registers: tuple[AbstractValue, ...]
    flags: tuple[TruthValue, ...]
    memory: tuple[tuple[int, AbstractValue], ...] = ()

    @classmethod
    def initial(cls) -> AbstractState:
        return cls(
            registers=tuple(AbstractValue.unknown() for _ in REGISTER_NAMES),
            flags=tuple(TruthValue.UNKNOWN for _ in FLAG_NAMES),
        )

    def register(self, name: str) -> AbstractValue:
        return self.registers[REGISTER_NAMES.index(name.lower())]

    def with_register(self, name: str, value: AbstractValue) -> AbstractState:
        index = REGISTER_NAMES.index(name.lower())
        registers = list(self.registers)
        registers[index] = value
        return AbstractState(tuple(registers), self.flags, self.memory)

    def flag(self, name: str) -> TruthValue:
        return self.flags[FLAG_NAMES.index(name.upper())]

    def with_flags(self, **updates: TruthValue) -> AbstractState:
        flags = list(self.flags)
        for name, value in updates.items():
            flags[FLAG_NAMES.index(name.upper())] = value
        return AbstractState(self.registers, tuple(flags), self.memory)

    def with_memory(self, address: int, value: AbstractValue) -> AbstractState:
        memory = dict(self.memory)
        memory[address & 0xFFFFFF] = value
        return AbstractState(
            self.registers, self.flags, tuple(sorted(memory.items()))
        )

    def without_memory(
        self, address: int | None = None, size: int = 4
    ) -> AbstractState:
        """Forget memory facts that a write may have overwritten.

        Tracked entries are longwords, so an entry overlaps a write when
        their byte ranges intersect. ``address=None`` forgets everything.
        """
        if address is None:
            memory: tuple[tuple[int, AbstractValue], ...] = ()
        else:
            start = address & 0xFFFFFF
            memory = tuple(
                (key, value) for key, value in self.memory
                if not (key < start + size and start < key + 4)
            )
        return AbstractState(self.registers, self.flags, memory)

    def join(self, other: AbstractState) -> AbstractState:
        registers = tuple(
            left.join(right)
            for left, right in zip(self.registers, other.registers)
        )
        flags = tuple(
            left if left == right else TruthValue.UNKNOWN
            for left, right in zip(self.flags, other.flags)
        )
        left_memory = dict(self.memory)
        right_memory = dict(other.memory)
        memory = tuple(
            (address, left_memory[address].join(right_memory[address]))
            for address in sorted(left_memory.keys() & right_memory.keys())
        )
        return AbstractState(registers, flags, memory)

    def widen(self, other: AbstractState) -> AbstractState:
        joined = self.join(other)
        registers = tuple(
            left.widen(right)
            for left, right in zip(self.registers, joined.registers)
        )
        return AbstractState(registers, joined.flags, joined.memory)


@dataclass(frozen=True)
class EntryPointCandidate:
    address: int
    source_address: int
    storage_address: int
    confidence: str
    evidence: str


@dataclass(frozen=True)
class OrphanCandidate:
    address: int
    preceding_address: int
    following_address: int
    gap_size: int
    confidence: str
    evidence: str


@dataclass(frozen=True)
class IndirectEdge:
    source_address: int
    target_address: int
    mnemonic: str
    evidence: str
    confidence: str


@dataclass(frozen=True)
class BranchDecision:
    source_address: int
    target_address: int
    fallthrough_address: int
    condition: str
    outcome: TruthValue


@dataclass(frozen=True)
class InterpretationResult:
    reached_addresses: tuple[int, ...]
    indirect_edges: tuple[IndirectEdge, ...]
    branch_decisions: tuple[BranchDecision, ...]
    unresolved_indirect_addresses: tuple[int, ...]
    state_updates: int
    widened_addresses: tuple[int, ...]


_IMMEDIATE_TO_ABSOLUTE = re.compile(
    r"#(-?0x[0-9a-f]+|-?\d+)\|\((-?0x[0-9a-f]+|-?\d+)\)\.[wl]$",
    re.I,
)
_RAM_SLOT_BASE = re.compile(r"\((-?0x[0-9a-f]+|-?\d+)\)\.w\|A([0-7])$", re.I)
_RAM_SLOT_STEP = re.compile(r"\((-?0x[0-9a-f]+|-?\d+),A([0-7])\)\|A\2$", re.I)
_IMMEDIATE_TO_FIELD = re.compile(
    r"#(-?0x[0-9a-f]+|-?\d+)\|\((-?0x[0-9a-f]+|-?\d+),(A[0-7])\)$", re.I
)
_IMMEDIATE_TO_OBJECT_BASE = re.compile(
    r"#(-?0x[0-9a-f]+|-?\d+)\|\(A([01])\)$", re.I
)
_FIELD_TO_ADDRESS = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),(A[0-7])\)\|(A[0-7])$", re.I
)


def _executed_ram_callback_slots(facts: dict[int, InstructionFact]) -> set[int]:
    """Prove object-RAM slots read and called by a counted strided loop."""
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    slots: set[int] = set()
    for read in facts.values():
        if read.mnemonic.upper() != "MOVE.L":
            continue
        match = re.fullmatch(r"\(A([0-7])\)\|(D[0-7])", read.operands, re.I)
        if match is None:
            continue
        address_register, value_register = match.group(1), match.group(2).upper()
        branch = by_address.get(read.cpu_address + read.length)
        if branch is None or branch.mnemonic.upper() not in {"BEQ.B", "BEQ.W"}:
            continue
        load = by_address.get(branch.cpu_address + branch.length)
        if (load is None or load.mnemonic.upper() != "MOVEA.L"
                or not re.fullmatch(rf"{value_register}\|A[0-7]", load.operands, re.I)):
            continue
        destination = load.operands.rsplit("|", 1)[1].upper()
        call = by_address.get(load.cpu_address + load.length)
        if (call is None or call.mnemonic.upper() not in {"JSR", "JMP"}
                or call.operands.upper() != f"({destination})"):
            continue
        step = by_address.get(call.cpu_address + call.length)
        stride = _RAM_SLOT_STEP.fullmatch(step.operands) if step is not None else None
        if (step is None or step.mnemonic.upper() != "LEA" or stride is None
                or stride.group(2) != address_register):
            continue
        skip = branch.flows[0] if branch.flows else None
        if skip != step.cpu_address:
            continue
        loop = by_address.get(step.cpu_address + step.length)
        if (loop is None or loop.mnemonic.upper() != "DBF"
                or "|" not in loop.operands
                or int(loop.operands.rsplit("|", 1)[1], 0) != read.cpu_address):
            continue
        loop_register = loop.operands.split("|", 1)[0].upper()
        setup = [fact for fact in facts.values()
                 if read.cpu_address - 0x40 <= fact.cpu_address < read.cpu_address]
        starts = [fact for fact in setup if fact.mnemonic.upper() == "LEA"
                  and (base := _RAM_SLOT_BASE.fullmatch(fact.operands)) is not None
                  and base.group(2) == address_register]
        counts = [fact for fact in setup if fact.mnemonic.upper() == "MOVEQ"
                  and fact.operands.upper().endswith(f"|{loop_register[0:2]}")]
        if not starts or not counts:
            continue
        start = max(starts, key=lambda fact: fact.cpu_address)
        base_match = _RAM_SLOT_BASE.fullmatch(start.operands)
        assert base_match is not None
        base = int(base_match.group(1), 0) & 0xFFFFFF
        increment = int(stride.group(1), 0)
        count = int(max(counts, key=lambda fact: fact.cpu_address).operands.split("|", 1)[0], 0)
        if not 0 < increment <= 256 or not 0 <= count <= 255:
            continue
        slots.update((base + index * increment) & 0xFFFFFF for index in range(count + 1))
    return slots


def _slot_call_reads(
    facts: dict[int, InstructionFact],
) -> dict[int, dict[int, int]]:
    """Map absolute longwords to reads that immediately call their value.

    Accepted shapes are ``MOVEA.L (slot),An; JSR/JMP (An)`` and the
    null-guarded ``MOVE.L (slot),Dn; BEQ; MOVEA.L Dn,An; JSR/JMP (An)``.
    The result maps slot -> {read address: call address}.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}

    def call_through(fact: InstructionFact | None, register: str) -> InstructionFact | None:
        if (fact is None or fact.mnemonic.upper() not in {"JSR", "JMP"}
                or fact.operands.upper() != f"({register.upper()})"):
            return None
        return fact

    reads: dict[int, dict[int, int]] = {}
    for read in facts.values():
        mnemonic = read.mnemonic.upper()
        if mnemonic not in {"MOVEA.L", "MOVE.L"} or read.operands.count("|") != 1:
            continue
        source, destination = read.operands.split("|")
        absolute = _ABSOLUTE.fullmatch(source.strip())
        if absolute is None:
            continue
        call = None
        following = by_address.get(read.cpu_address + read.length)
        if mnemonic == "MOVEA.L" and re.fullmatch(r"A[0-6]", destination.strip(), re.I):
            call = call_through(following, destination.strip())
        elif mnemonic == "MOVE.L" and re.fullmatch(r"D[0-7]", destination.strip(), re.I):
            if following is None or following.mnemonic.upper() not in {"BEQ.B", "BEQ.W"}:
                continue
            load = by_address.get(following.cpu_address + following.length)
            if load is None or load.mnemonic.upper() != "MOVEA.L":
                continue
            moved = re.fullmatch(
                rf"{destination.strip()}\|(A[0-6])", load.operands, re.I
            )
            if moved is not None:
                call = call_through(
                    by_address.get(load.cpu_address + load.length), moved.group(1)
                )
        if call is not None:
            slot = int(absolute.group(1), 0) & 0xFFFFFF
            reads.setdefault(slot, {})[read.cpu_address] = call.cpu_address
    return reads


def _direct_ram_callback_slots(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> dict[int, tuple[int, ...]]:
    """Prove absolute work-RAM longwords used only as callback pointers.

    A slot qualifies when known code loads it and immediately calls the
    value, and every other known access to its four bytes is a whole-long
    test or compare, ``CLR.L``, or a ``MOVE.L`` of a checked immediate.
    Reading the slot as data, taking its address, a partial access, any
    other write (including ``MOVE.L`` from a register or memory), or an
    immediate that is neither null, a RAM address nor a code-shaped even
    ROM address disqualifies it. Aliasing
    through a computed pointer is not visible in static operands; that is
    the remaining limit of this proof. Returns slot -> call addresses.
    """
    ram_start, ram_end = image.header.ram_start, image.header.ram_end
    reads = {
        slot: sites for slot, sites in _slot_call_reads(facts).items()
        if ram_start <= slot <= ram_end - 3
    }
    if not reads:
        return {}
    rejected: set[int] = set()
    for fact in facts.values():
        mnemonic = fact.mnemonic.upper()
        operands = fact.operands.split("|") if fact.operands else []
        size = 64 if mnemonic.startswith("MOVEM") else _operation_bits(mnemonic) // 8
        for index, operand in enumerate(operands):
            absolute = _ABSOLUTE.fullmatch(operand.strip())
            if absolute is None:
                continue
            address = int(absolute.group(1), 0) & 0xFFFFFF
            for slot in range(address - 3, address + size):
                if slot not in reads or slot in rejected:
                    continue
                if slot != address or size != 4:
                    rejected.add(slot)
                elif fact.cpu_address in reads[slot]:
                    continue
                elif mnemonic.startswith(("TST.", "CMP")):
                    continue
                elif index == len(operands) - 1 and mnemonic == "CLR.L":
                    continue
                elif index == len(operands) - 1 and mnemonic == "MOVE.L":
                    immediate = _IMMEDIATE_TO_ABSOLUTE.fullmatch(fact.operands)
                    if immediate is None:
                        # A register or memory source may hold data or an
                        # arbitrary address that later calls would reach.
                        rejected.add(slot)
                        continue
                    target = int(immediate.group(1), 0) & 0xFFFFFF
                    if target == 0 or ram_start <= target <= ram_end:
                        continue
                    if (target < 0x200 or target + 2 > len(image.data) or target & 1
                            or not _plausible_orphan_start(
                                int.from_bytes(image.data[target:target + 2], "big"))):
                        rejected.add(slot)
                else:
                    rejected.add(slot)
    return {
        slot: tuple(sorted(set(sites.values())))
        for slot, sites in reads.items() if slot not in rejected
    }


def _plausible_orphan_start(first_word: int) -> bool:
    """Reject obvious data while retaining selected legal line-0 opcodes."""
    if first_word == 0xFFFF or first_word >> 12 in {0xA, 0xF}:
        return False
    if first_word >= 0x1000:
        return True
    # CMPI is a common function/block entry after an unconditional branch.
    # The old blanket rejection of line-0 opcodes hid valid code such as
    # Flicky's `cmpi.w #$f,d2` at $000D86. Other line-0 families remain
    # excluded until they have similarly strong structural evidence.
    return first_word & 0xFF00 == 0x0C00


def discover_ram_handler_candidates(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[EntryPointCandidate, ...]:
    """Find ROM addresses installed into work-RAM callback or vector slots."""
    candidates: dict[int, EntryPointCandidate] = {}
    by_storage: dict[int, list[EntryPointCandidate]] = {}
    decoded_starts = {fact.cpu_address for fact in facts.values()}
    executed_slots = _executed_ram_callback_slots(facts)
    called_slots = _direct_ram_callback_slots(image, facts)
    ram_vector_starts = {
        vector.address
        for vector in image.vector_table[1:]
        if image.header.ram_start <= vector.address <= image.header.ram_end
    }
    for fact in facts.values():
        if fact.mnemonic.upper() != "MOVE.L":
            continue
        match = _IMMEDIATE_TO_ABSOLUTE.fullmatch(fact.operands)
        if match is None:
            continue
        target = int(match.group(1), 0) & 0xFFFFFF
        storage = int(match.group(2), 0) & 0xFFFFFF
        if not image.header.ram_start <= storage <= image.header.ram_end:
            continue
        if target < 0x200 or target >= len(image.data) or target & 1:
            continue
        interrupt_trampoline = (storage - 2) & 0xFFFFFF in ram_vector_starts
        candidate = EntryPointCandidate(
            address=target,
            source_address=fact.cpu_address,
            storage_address=storage,
            confidence="proven" if interrupt_trampoline else "candidate",
            evidence=(
                "ROM address stored after RAM interrupt vector trampoline"
                if interrupt_trampoline
                else "immediate ROM address stored in work RAM"
            ),
        )
        # A later unproven assignment must not demote a proven one.
        if candidates.get(target) is None or candidates[target].confidence != "proven":
            candidates[target] = candidate
        by_storage.setdefault(storage, []).append(candidate)
    for storage, calls in called_slots.items():
        # Known code only ever consumes this slot by calling it and never
        # reads it as data, so one assignment suffices. _direct_ram_callback_slots
        # has already checked that each assigned ROM target looks like code.
        for candidate in by_storage.get(storage, ()):
            candidates[candidate.address] = EntryPointCandidate(
                address=candidate.address,
                source_address=candidate.source_address,
                storage_address=storage,
                confidence="proven",
                evidence=(f"RAM slot {storage:06X} is only used as a callback "
                          "called at " + ", ".join(f"{call:06X}" for call in calls)),
            )
    for storage, assignments in by_storage.items():
        targets = {candidate.address for candidate in assignments}
        if storage not in executed_slots or len(targets) < 2:
            continue
        # The counted loop reads and invokes this RAM slot. Two independent
        # ROM assignments prove a callback field even when neither handler
        # has yet been decoded.
        for candidate in assignments:
            if candidate.address in decoded_starts:
                continue
            first_word = int.from_bytes(image.data[candidate.address:candidate.address + 2], "big")
            if not _plausible_orphan_start(first_word):
                continue
            candidates[candidate.address] = EntryPointCandidate(
                address=candidate.address,
                source_address=candidate.source_address,
                storage_address=storage,
                confidence="proven",
                evidence=(f"RAM slot {storage:06X} is called by a counted loop "
                          f"and has {len(targets)} ROM handler assignments"),
            )
    return tuple(candidates[address] for address in sorted(candidates))


def discover_object_field_handler_candidates(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[EntryPointCandidate, ...]:
    """Find callbacks stored in a struct field and invoked through that field.

    Require the target to begin exactly after known terminating code. This
    separates callbacks from asset pointers stored in overloaded fields.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    executed_object_slots = _executed_ram_callback_slots(facts)
    readers: dict[tuple[int, str], int] = {}
    for load in facts.values():
        if load.mnemonic.upper() != "MOVEA.L":
            continue
        match = _FIELD_TO_ADDRESS.fullmatch(load.operands)
        if match is None:
            continue
        call = by_address.get(load.cpu_address + load.length)
        if (call is None or call.mnemonic.upper() not in {"JSR", "JMP"}
                or call.operands.upper() != f"({match.group(3).upper()})"):
            continue
        readers[(int(match.group(1), 0), match.group(2).upper())] = call.cpu_address
    candidates = {}
    for store in facts.values():
        if store.mnemonic.upper() != "MOVE.L":
            continue
        match = _IMMEDIATE_TO_FIELD.fullmatch(store.operands)
        if match is not None:
            field = (int(match.group(2), 0), match.group(3).upper())
            reader = readers.get(field)
            if reader is None:
                continue
            proof = f"called at {reader:06X}"
        else:
            match = _IMMEDIATE_TO_OBJECT_BASE.fullmatch(store.operands)
            if match is None or not executed_object_slots:
                continue
            field = (0, f"A{match.group(2)}")
            proof = "first object longword is invoked by a counted RAM callback loop"
        target = int(match.group(1), 0) & 0xFFFFFF
        if not 0x200 <= target < len(image.data) - 1 or target & 1:
            continue
        preceding = ends.get(target)
        if (preceding is None or preceding.flow_type.upper() not in {
                "TERMINATOR", "UNCONDITIONAL_JUMP", "CALL_TERMINATOR"}):
            continue
        first_word = int.from_bytes(image.data[target:target + 2], "big")
        if first_word in {0, 0xFFFF}:
            continue
        candidates[target] = EntryPointCandidate(
            address=target,
            source_address=store.cpu_address,
            storage_address=field[0],
            confidence="proven",
            evidence=(f"ROM callback stored in {field[0]:X}({field[1]}); {proof}; "
                      f"begins after terminal at {preceding.cpu_address:06X}"),
        )
    return tuple(candidates[address] for address in sorted(candidates))


def discover_packed_orphan_candidates(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    *,
    maximum_gap: int = 2048,
) -> tuple[OrphanCandidate, ...]:
    """Find bounded code-shaped gaps immediately after a terminal instruction.

    This deliberately avoids scanning arbitrary ROM. A candidate needs known
    code on both sides, an exact boundary after a terminating flow, a
    non-table-like first word, and either a short gap, a return opcode or a
    relative branch back into known code. Gaps over 128 bytes additionally
    require a branch/call to an existing instruction boundary; a return-looking
    word alone does not qualify. Ghidra still decodes the candidate.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    addresses = sorted(by_address)
    instruction_interiors = {
        address for fact in facts.values()
        for address in range(fact.cpu_address + 1, fact.cpu_address + fact.length)
    }
    referenced_data = {
        reference.address & 0xFFFFFF
        for fact in facts.values()
        for reference in fact.references
        if reference.reference_type.upper() in {"DATA", "READ"}
    }
    terminal_flows = {
        "TERMINATOR",
        "CALL_TERMINATOR",
        "UNCONDITIONAL_JUMP",
        "COMPUTED_JUMP",
    }
    return_opcodes = {0x4E73, 0x4E75, 0x4E77}
    candidates = []
    for index, fact_address in enumerate(addresses[:-1]):
        fact = by_address[fact_address]
        start = fact.cpu_address + fact.length
        following = addresses[index + 1]
        gap_size = following - start
        if (
            fact.flow_type.upper() not in terminal_flows
            or start in by_address
            or start in referenced_data
            or start & 1
            or not 2 <= gap_size <= maximum_gap
            or following > len(image.data)
        ):
            continue
        payload = image.data[start:following]
        first_word = int.from_bytes(payload[:2], "big")
        bit_operation_entry = (
            first_word & 0xFF00 == 0x0800
            and (first_word >> 3) & 7 != 1
            and (first_word & 0x38 != 0x38 or first_word & 7 <= 1)
        )
        immediate_entry = (
            # ORI encodings start with zero words very common in assets.
            # A branch-looking word elsewhere in a gap does not disambiguate
            # them; keep these entries unrooted without stronger evidence.
            first_word & 0xFF00 in {0x0200, 0x0400, 0x0600, 0x0A00}
            and (first_word >> 6) & 3 != 3
            and (first_word >> 3) & 7 != 1
            and (first_word & 0x38 != 0x38 or first_word & 7 <= 1)
        )
        if (not (_plausible_orphan_start(first_word) or bit_operation_entry or immediate_entry)
                or len(set(payload)) <= 1):
            continue
        if first_word & 0xF000 == 0x6000:
            displacement = first_word & 0xFF
            if displacement == 0:
                if len(payload) < 4:
                    continue
                displacement = int.from_bytes(payload[2:4], "big", signed=True)
            elif displacement & 0x80:
                displacement -= 0x100
            target = (start + 2 + displacement) & 0xFFFFFF
            if (target & 1 or not 0x200 <= target < len(image.data)
                    or target in instruction_interiors):
                # Data can resemble BSR.W. A target inside already known code
                # contradicts this speculative entry and must not split it.
                continue
        words = {
            int.from_bytes(payload[offset:offset + 2], "big")
            for offset in range(0, len(payload) - 1, 2)
        }
        has_return = bool(words & return_opcodes)
        known_branch = False
        for offset in range(0, len(payload) - 1, 2):
            opcode = int.from_bytes(payload[offset:offset + 2], "big")
            if opcode in {0x4EB9, 0x4EF9} and offset + 6 <= len(payload):
                target = int.from_bytes(payload[offset + 2:offset + 6], "big") & 0xFFFFFF
                if target in by_address:
                    known_branch = True
                    break
            if opcode in {0x4EBA, 0x4EFA} and offset + 4 <= len(payload):
                target = start + offset + 2 + int.from_bytes(
                    payload[offset + 2:offset + 4], "big", signed=True)
                if target in by_address:
                    known_branch = True
                    break
            if opcode & 0xF000 != 0x6000:
                continue
            displacement = opcode & 0xFF
            if displacement == 0:
                if offset + 4 > len(payload):
                    continue
                displacement = int.from_bytes(
                    payload[offset + 2:offset + 4], "big", signed=True
                )
            elif displacement & 0x80:
                displacement -= 0x100
            if start + offset + 2 + displacement in by_address:
                known_branch = True
                break
        if gap_size > 24 and not has_return and not known_branch:
            continue
        if gap_size > 128 and not known_branch:
            continue
        if (bit_operation_entry or immediate_entry) and not known_branch:
            continue
        candidates.append(
            OrphanCandidate(
                address=start,
                preceding_address=fact.cpu_address,
                following_address=following,
                gap_size=gap_size,
                confidence="high",
                evidence=(
                    "packed gap after terminal flow with return opcode"
                    if has_return and gap_size <= 128
                    else "packed gap after terminal flow with branch to known code"
                    if known_branch
                    else "short packed gap after terminal flow"
                ),
            )
        )
    return tuple(candidates)


_REGISTER = re.compile(r"([DA][0-7]|SP)(?:[bwl])?$", re.I)
_IMMEDIATE = re.compile(r"#?(-?0x[0-9a-f]+|-?\d+)$", re.I)
_ABSOLUTE = re.compile(r"\((-?0x[0-9a-f]+|-?\d+)\)\.[wl]$", re.I)
_INDIRECT_REGISTER = re.compile(r"\(([Aa][0-7])\)$")
_AUTO_ADJUST = re.compile(r"-\(([A][0-7]|SP)\)|\(([A][0-7]|SP)\)\+", re.I)
_REGISTER_LIST_ITEM = re.compile(
    r"([DA][0-7]|SP)(?:[bwl])?(?:\s*-\s*([DA][0-7]|SP)(?:[bwl])?)?", re.I
)
_NON_WRITING_FLOWS = {
    "CONDITIONAL_JUMP",
    "UNCONDITIONAL_JUMP",
    "COMPUTED_JUMP",
    "TERMINATOR",
}
_READ_ONLY_PREFIXES = ("CMP", "TST", "BTST", "CHK")
_CALL_FLOWS = {"UNCONDITIONAL_CALL", "COMPUTED_CALL"}


def _canonical_register(name: str) -> str:
    name = name.lower()
    return "a7" if name == "sp" else name


def _register_name(operand: str) -> str | None:
    match = _REGISTER.fullmatch(operand.strip())
    return _canonical_register(match.group(1)) if match else None


def _register_list(operand: str) -> tuple[str, ...]:
    """Expand a MOVEM register list such as ``D0-D1/A0`` or ``{A0 D1}``."""
    registers: list[str] = []
    for match in _REGISTER_LIST_ITEM.finditer(operand):
        first = REGISTER_NAMES.index(_canonical_register(match.group(1)))
        last = first
        if match.group(2):
            last = REGISTER_NAMES.index(_canonical_register(match.group(2)))
        low, high = sorted((first, last))
        registers.extend(REGISTER_NAMES[low:high + 1])
    return tuple(dict.fromkeys(registers))


def _narrow(value: AbstractValue, bits: int) -> AbstractValue:
    """Return the low ``bits`` of a value, or unknown if they are not known."""
    if value.bits == bits:
        return value
    if value.bits < bits:
        return AbstractValue.unknown(bits)
    mask = (1 << bits) - 1
    values = value.concrete_values()
    if values is not None:
        return AbstractValue.small_set(
            {item & mask for item in values},
            bits,
            address_space=value.address_space,
        )
    bounds = value.bounds()
    if bounds is not None and bounds[1] <= mask:
        return AbstractValue.interval(
            bounds[0],
            bounds[1],
            value.stride() or 1,
            bits,
            address_space=value.address_space,
        )
    return AbstractValue.unknown(bits)


def _sign_extend(value: AbstractValue) -> AbstractValue:
    if value.bits == 32:
        return value
    values = value.concrete_values()
    if values is None:
        return AbstractValue.unknown()
    sign = 1 << (value.bits - 1)
    return AbstractValue.small_set(
        {item - (1 << value.bits) if item & sign else item for item in values},
        address_space=value.address_space,
    )


def _write_register(
    state: AbstractState, name: str, value: AbstractValue, bits: int = 32
) -> AbstractState:
    """Write a register, preserving the 68000's partial-width semantics.

    Address registers always receive a sign-extended 32-bit value. A byte or
    word write to a data register leaves the upper bits intact; if they are
    not exactly known, the register only records the low ``bits`` and
    full-width consumers treat it as unknown.
    """
    value = _narrow(value, bits)
    if name.startswith("a"):
        return state.with_register(name, _sign_extend(value))
    if bits == 32:
        return state.with_register(name, value)
    old = state.register(name)
    old_values = old.concrete_values() if old.bits == 32 else None
    new_values = value.concrete_values()
    if (
        old_values is not None
        and new_values is not None
        and len(old_values) * len(new_values) <= 64
    ):
        mask = (1 << bits) - 1
        return state.with_register(name, AbstractValue.small_set(
            {
                (high & ~mask) | low
                for high in old_values
                for low in new_values
            },
            address_space=value.address_space,
        ))
    return state.with_register(name, value)


def _source_value(
    operand: str,
    state: AbstractState,
    *,
    address: bool = False,
    bits: int = 32,
) -> AbstractValue:
    register = _register_name(operand)
    if register is not None:
        return _narrow(state.register(register), bits)
    immediate = _IMMEDIATE.fullmatch(operand.strip())
    if immediate is not None:
        return _narrow(AbstractValue.constant(
            int(immediate.group(1), 0),
            address_space="rom" if address else "scalar",
        ), bits)
    absolute = _ABSOLUTE.fullmatch(operand.strip())
    if absolute is not None:
        value = int(absolute.group(1), 0) & 0xFFFFFF
        if address:
            space = "ram" if value >= 0xFF0000 else "rom"
            return AbstractValue.constant(value, address_space=space)
        # Memory facts are longwords; a narrower read at the same address
        # would see the high-order bytes, which are not modelled here.
        if bits == 32:
            return dict(state.memory).get(value, AbstractValue.unknown())
    return AbstractValue.unknown(bits)


def _operation_bits(mnemonic: str, default: int = 32) -> int:
    suffix = mnemonic.rsplit(".", 1)[-1].upper()
    return {"B": 8, "W": 16, "L": 32}.get(suffix, default)


def _uniform_truth(values: set[bool]) -> TruthValue:
    if values == {True}:
        return TruthValue.TRUE
    if values == {False}:
        return TruthValue.FALSE
    return TruthValue.UNKNOWN


def _logic_flags(value: AbstractValue, bits: int) -> dict[str, TruthValue]:
    concrete = value.concrete_values()
    if concrete is None:
        negative = zero = TruthValue.UNKNOWN
    else:
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        negative = _uniform_truth({bool(item & sign) for item in concrete})
        zero = _uniform_truth({(item & mask) == 0 for item in concrete})
    return {
        "n": negative,
        "z": zero,
        "v": TruthValue.FALSE,
        "c": TruthValue.FALSE,
    }


def _with_logic_flags(
    state: AbstractState, value: AbstractValue, bits: int
) -> AbstractState:
    return state.with_flags(**_logic_flags(value, bits))


def _arithmetic_flags(
    left: AbstractValue,
    right: AbstractValue,
    bits: int,
    *,
    subtract: bool,
) -> dict[str, TruthValue]:
    left_values = left.concrete_values()
    right_values = right.concrete_values()
    if (
        left_values is None
        or right_values is None
        or len(left_values) * len(right_values) > 128
    ):
        return {name: TruthValue.UNKNOWN for name in "nzvc"}
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    outcomes = {name: set() for name in "nzvc"}
    for raw_left in left_values:
        for raw_right in right_values:
            a = raw_left & mask
            b = raw_right & mask
            if subtract:
                result = (a - b) & mask
                carry = a < b
                overflow = bool(((a ^ b) & (a ^ result) & sign))
            else:
                result = (a + b) & mask
                carry = a + b > mask
                overflow = bool((~(a ^ b) & (a ^ result) & sign))
            outcomes["n"].add(bool(result & sign))
            outcomes["z"].add(result == 0)
            outcomes["v"].add(overflow)
            outcomes["c"].add(carry)
    return {
        name: _uniform_truth(values)
        for name, values in outcomes.items()
    }


def _truth_not(value: TruthValue) -> TruthValue:
    if value == TruthValue.TRUE:
        return TruthValue.FALSE
    if value == TruthValue.FALSE:
        return TruthValue.TRUE
    return TruthValue.UNKNOWN


def _truth_and(left: TruthValue, right: TruthValue) -> TruthValue:
    if TruthValue.FALSE in {left, right}:
        return TruthValue.FALSE
    if left == right == TruthValue.TRUE:
        return TruthValue.TRUE
    return TruthValue.UNKNOWN


def _truth_or(left: TruthValue, right: TruthValue) -> TruthValue:
    if TruthValue.TRUE in {left, right}:
        return TruthValue.TRUE
    if left == right == TruthValue.FALSE:
        return TruthValue.FALSE
    return TruthValue.UNKNOWN


def _truth_equal(left: TruthValue, right: TruthValue) -> TruthValue:
    if TruthValue.UNKNOWN in {left, right}:
        return TruthValue.UNKNOWN
    return TruthValue.TRUE if left == right else TruthValue.FALSE


def _branch_outcome(fact: InstructionFact, state: AbstractState) -> TruthValue:
    condition = fact.mnemonic.upper().split(".", 1)[0]
    if condition.startswith("DB"):
        return TruthValue.UNKNOWN
    n = state.flag("N")
    z = state.flag("Z")
    v = state.flag("V")
    c = state.flag("C")
    conditions = {
        "BEQ": z,
        "BNE": _truth_not(z),
        "BCS": c,
        "BLO": c,
        "BCC": _truth_not(c),
        "BHS": _truth_not(c),
        "BMI": n,
        "BPL": _truth_not(n),
        "BVS": v,
        "BVC": _truth_not(v),
        "BHI": _truth_and(_truth_not(c), _truth_not(z)),
        "BLS": _truth_or(c, z),
        "BGE": _truth_equal(n, v),
        "BLT": _truth_not(_truth_equal(n, v)),
        "BGT": _truth_and(_truth_not(z), _truth_equal(n, v)),
        "BLE": _truth_or(z, _truth_not(_truth_equal(n, v))),
    }
    return conditions.get(condition, TruthValue.UNKNOWN)


def transfer_instruction(
    fact: InstructionFact, state: AbstractState
) -> AbstractState:
    """Apply register, selected memory, and condition-code effects."""
    mnemonic = fact.mnemonic.upper()
    operands = fact.operands.split("|") if fact.operands else []
    state = _invalidate_written_memory(fact, operands, state)
    state = _transfer_values(fact, mnemonic, operands, state)
    # (An)+ and -(An) change the address register whatever the operation.
    for operand in operands:
        for match in _AUTO_ADJUST.finditer(operand):
            register = _canonical_register(match.group(1) or match.group(2))
            state = state.with_register(register, AbstractValue.unknown())
    return state


def _invalidate_written_memory(
    fact: InstructionFact, operands: list[str], state: AbstractState
) -> AbstractState:
    """Drop memory facts that the destination operand may overwrite."""
    mnemonic = fact.mnemonic.upper()
    if (
        not operands
        or not state.memory
        or fact.flow_type.upper() in _NON_WRITING_FLOWS
        or mnemonic.startswith(_READ_ONLY_PREFIXES)
    ):
        return state
    destination = operands[-1].strip()
    if "(" not in destination:
        return state
    absolute = _ABSOLUTE.fullmatch(destination)
    if absolute is None:
        # A register-relative write may alias any tracked address.
        return state.without_memory()
    return state.without_memory(
        int(absolute.group(1), 0), _operation_bits(mnemonic) // 8
    )


def _transfer_values(
    fact: InstructionFact,
    mnemonic: str,
    operands: list[str],
    state: AbstractState,
) -> AbstractState:
    if mnemonic.startswith("MOVEM") and len(operands) == 2:
        if "(" not in operands[1]:
            for register in _register_list(operands[1]):
                state = state.with_register(register, AbstractValue.unknown())
        return state
    if mnemonic.startswith("EXG") and len(operands) == 2:
        left = _register_name(operands[0])
        right = _register_name(operands[1])
        if left is not None and right is not None:
            left_value = state.register(left)
            return state.with_register(
                left, state.register(right)
            ).with_register(right, left_value)
    if mnemonic.startswith("DB") and operands:
        counter = _register_name(operands[0])
        if counter is not None:
            return _write_register(
                state, counter, AbstractValue.unknown(16), 16
            )
        return state
    if mnemonic == "LEA" and len(operands) == 2:
        destination = _register_name(operands[1])
        if destination is not None:
            return state.with_register(
                destination, _source_value(operands[0], state, address=True)
            )
    if mnemonic == "MOVEQ" and len(operands) == 2:
        destination = _register_name(operands[1])
        immediate = _IMMEDIATE.fullmatch(operands[0].strip())
        if destination is not None and immediate is not None:
            value = int(immediate.group(1), 0) & 0xFF
            if value & 0x80:
                value -= 0x100
            result = AbstractValue.constant(value)
            updated = state.with_register(
                destination, AbstractValue.constant(value)
            )
            return _with_logic_flags(updated, result, 32)
    if mnemonic.startswith("MOVEA.") and len(operands) == 2:
        destination = _register_name(operands[1])
        if destination is not None:
            bits = _operation_bits(mnemonic)
            return _write_register(
                state,
                destination,
                _source_value(operands[0], state, bits=bits),
                bits,
            )
    if mnemonic.startswith("MOVE.") and len(operands) == 2:
        bits = _operation_bits(mnemonic)
        value = _source_value(operands[0], state, bits=bits)
        updated = state
        destination = _register_name(operands[1])
        if destination is not None:
            updated = _write_register(updated, destination, value, bits)
        immediate = _IMMEDIATE.fullmatch(operands[0].strip())
        absolute = _ABSOLUTE.fullmatch(operands[1].strip())
        if mnemonic == "MOVE.L" and immediate is not None and absolute is not None:
            updated = updated.with_memory(
                int(absolute.group(1), 0),
                AbstractValue.constant(
                    int(immediate.group(1), 0), address_space="rom"
                ),
            )
        return _with_logic_flags(updated, value, bits)
    if mnemonic.startswith("CLR.") and len(operands) == 1:
        bits = _operation_bits(mnemonic)
        value = AbstractValue.constant(0, bits)
        updated = state
        destination = _register_name(operands[0])
        if destination is not None:
            updated = _write_register(updated, destination, value, bits)
        return _with_logic_flags(updated, value, bits)
    arithmetic = (
        "ADD" if mnemonic.startswith("ADD") and not mnemonic.startswith("ADDX")
        else "SUB" if mnemonic.startswith("SUB")
        and not mnemonic.startswith("SUBX")
        else None
    )
    if arithmetic is not None and len(operands) == 2:
        destination = _register_name(operands[1])
        if destination is not None:
            bits = _operation_bits(mnemonic)
            subtract = arithmetic == "SUB"
            if destination.startswith("a"):
                # Address arithmetic is always 32-bit with a sign-extended
                # source and leaves the condition codes alone.
                left = state.register(destination)
                right = _sign_extend(
                    _source_value(operands[0], state, bits=bits)
                )
                result = left.subtract(right) if subtract else left.add(right)
                return _write_register(state, destination, result)
            left = _narrow(state.register(destination), bits)
            right = _source_value(operands[0], state, bits=bits)
            result = left.subtract(right) if subtract else left.add(right)
            updated = _write_register(state, destination, result, bits)
            flags = _arithmetic_flags(left, right, bits, subtract=subtract)
            return updated.with_flags(**flags, x=flags["c"])
    if mnemonic.startswith("ANDI.") and len(operands) == 2:
        destination = _register_name(operands[1])
        immediate = _IMMEDIATE.fullmatch(operands[0].strip())
        if destination is not None and immediate is not None:
            bits = _operation_bits(mnemonic)
            value = _narrow(state.register(destination), bits).bitwise_and(
                int(immediate.group(1), 0)
            )
            updated = _write_register(state, destination, value, bits)
            return _with_logic_flags(updated, value, bits)
    if mnemonic.startswith("AND.") and len(operands) == 2:
        destination = _register_name(operands[1])
        if destination is not None:
            bits = _operation_bits(mnemonic)
            left = _narrow(state.register(destination), bits)
            right = _source_value(operands[0], state, bits=bits)
            left_values = left.concrete_values(1)
            right_values = right.concrete_values(1)
            if left_values is not None:
                value = right.bitwise_and(left_values[0])
            elif right_values is not None:
                value = left.bitwise_and(right_values[0])
            else:
                value = AbstractValue.unknown(bits)
            updated = _write_register(state, destination, value, bits)
            return _with_logic_flags(updated, value, bits)
    if mnemonic.startswith("TST.") and len(operands) == 1:
        bits = _operation_bits(mnemonic)
        return _with_logic_flags(
            state, _source_value(operands[0], state, bits=bits), bits
        )
    if mnemonic.startswith("CMPA") and len(operands) == 2:
        right = _sign_extend(_source_value(
            operands[0], state, bits=_operation_bits(mnemonic)
        ))
        left = _source_value(operands[1], state)
        return state.with_flags(**_arithmetic_flags(
            left, right, 32, subtract=True
        ))
    if mnemonic.startswith("CMP") and len(operands) == 2:
        bits = _operation_bits(mnemonic)
        right = _source_value(operands[0], state, bits=bits)
        left = _source_value(operands[1], state, bits=bits)
        return state.with_flags(**_arithmetic_flags(
            left, right, bits, subtract=True
        ))
    if mnemonic.startswith("BTST") and len(operands) == 2:
        bit_value = _source_value(operands[0], state).concrete_values(1)
        tested = None
        if _register_name(operands[1]) is not None:
            tested = _source_value(operands[1], state).concrete_values()
        zero = TruthValue.UNKNOWN
        if bit_value is not None and tested is not None:
            bit = bit_value[0] % 32
            zero = _uniform_truth({not bool(value & (1 << bit)) for value in tested})
        return state.with_flags(z=zero)
    # Any other instruction that names a register as its last operand is
    # treated as writing it. A stale constant is unsafe when it later controls
    # an indirect branch.
    if operands:
        destination = _register_name(operands[-1])
        if destination is not None:
            value = AbstractValue.unknown()
            updated = state.with_register(destination, value)
            if mnemonic.startswith(("OR.", "EOR.", "NOT.", "EXT.", "SWAP")):
                return _with_logic_flags(
                    updated, value, _operation_bits(mnemonic)
                )
            return updated.with_flags(**{
                name: TruthValue.UNKNOWN for name in "xnzvc"
            })
    return state


def _successors(
    image: MegaDriveImage, fact: InstructionFact, state: AbstractState
) -> tuple[tuple[int, ...], tuple[IndirectEdge, ...], bool]:
    next_address = fact.cpu_address + fact.length
    flow = fact.flow_type.upper()
    direct = tuple(fact.flows)
    edges: list[IndirectEdge] = []
    indirect = _INDIRECT_REGISTER.fullmatch(fact.operands.strip())
    unresolved = False
    if flow in {"COMPUTED_CALL", "COMPUTED_JUMP"} and indirect is not None:
        register_name = indirect.group(1).lower()
        values = _narrow(
            state.register(register_name), 32
        ).concrete_values(32)
        if values is None:
            unresolved = True
        else:
            for target in values:
                edges.append(
                    IndirectEdge(
                        source_address=fact.cpu_address,
                        target_address=target & 0xFFFFFF,
                        mnemonic=fact.mnemonic,
                        evidence=f"{register_name} abstract value",
                        confidence="proven",
                    )
                )
    elif flow in {"COMPUTED_CALL", "COMPUTED_JUMP"}:
        indexed = pc_indexed_target(fact)
        if indexed is None:
            unresolved = True
        else:
            base, register, kind, size = indexed
            register_name = f"{kind}{register}"
            values = _narrow(
                state.register(register_name), 16 if size == "w" else 32
            ).concrete_values(32)
            if values is None:
                unresolved = True
            else:
                for value in values:
                    if size == "w":
                        value &= 0xFFFF
                        if value & 0x8000:
                            value -= 0x10000
                    target = (base + value) & 0xFFFFFF
                    branch_stub = False
                    if target + 4 <= len(image.data):
                        opcode = int.from_bytes(
                            image.data[target:target + 2], "big"
                        )
                        displacement = int.from_bytes(
                            image.data[target + 2:target + 4],
                            "big",
                            signed=True,
                        )
                        destination = target + 2 + displacement
                        branch_stub = (
                            opcode == 0x6000
                            and 0x200 <= destination < len(image.data)
                            and destination % 2 == 0
                        )
                    edges.append(
                        IndirectEdge(
                            source_address=fact.cpu_address,
                            target_address=target,
                            mnemonic=fact.mnemonic,
                            evidence=(
                                f"PC-indexed {register_name} abstract value"
                            ),
                            confidence="proven" if branch_stub else "candidate",
                        )
                    )
    computed = tuple(edge.target_address for edge in edges)
    if flow == "FALL_THROUGH":
        return (next_address,), tuple(edges), unresolved
    if flow == "CONDITIONAL_JUMP":
        return tuple(dict.fromkeys((*direct, next_address))), tuple(edges), unresolved
    if flow == "UNCONDITIONAL_CALL":
        return tuple(dict.fromkeys((*direct, next_address))), tuple(edges), unresolved
    if flow == "COMPUTED_CALL":
        return tuple(dict.fromkeys((*computed, next_address))), tuple(edges), unresolved
    if flow in {"UNCONDITIONAL_JUMP", "CALL_TERMINATOR"}:
        return direct, tuple(edges), unresolved
    if flow == "COMPUTED_JUMP":
        return computed, tuple(edges), unresolved
    return (), tuple(edges), unresolved


def interpret_known_cfg(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    *,
    widening_after: int = 3,
    additional_entrypoints: set[int] | frozenset[int] = frozenset(),
) -> InterpretationResult:
    """Propagate abstract states over backend-decoded instructions.

    Additional entrypoints are validated planned seeds; each one present
    among the decoded facts starts from the initial state even when no
    call path from reset reaches it.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    entrypoints = {image.reset_address}
    entrypoints.update(
        address for address in additional_entrypoints if address in by_address
    )
    entrypoints.update(
        target
        for fact in facts.values()
        if fact.flow_type.upper() in {"UNCONDITIONAL_CALL", "CALL_TERMINATOR"}
        for target in fact.flows
        if target in by_address
    )
    entrypoints.update(
        vector.address
        for vector in image.vector_table[1:]
        if vector.address in by_address
    )
    queue = deque(
        (address, AbstractState.initial()) for address in sorted(entrypoints)
    )
    states: dict[int, AbstractState] = {}
    updates: dict[int, int] = {}
    widened: set[int] = set()
    edges: dict[tuple[int, int], IndirectEdge] = {}
    branch_decisions: dict[int, BranchDecision] = {}
    unresolved: set[int] = set()
    state_updates = 0
    while queue:
        address, incoming = queue.popleft()
        fact = by_address.get(address)
        if fact is None:
            continue
        current = states.get(address)
        if current is not None:
            count = updates.get(address, 0)
            merged = (
                current.widen(incoming)
                if count >= widening_after
                else current.join(incoming)
            )
            if merged == current:
                continue
            if count >= widening_after:
                widened.add(address)
            incoming = merged
        states[address] = incoming
        updates[address] = updates.get(address, 0) + 1
        state_updates += 1
        outgoing = transfer_instruction(fact, incoming)
        successors, indirect_edges, was_unresolved = _successors(
            image, fact, outgoing
        )
        if fact.flow_type.upper() == "CONDITIONAL_JUMP" and fact.flows:
            decision = BranchDecision(
                source_address=fact.cpu_address,
                target_address=fact.flows[0],
                fallthrough_address=fact.cpu_address + fact.length,
                condition=fact.mnemonic.upper().split(".", 1)[0],
                outcome=_branch_outcome(fact, outgoing),
            )
            previous = branch_decisions.get(fact.cpu_address)
            if previous is not None and previous.outcome != decision.outcome:
                decision = BranchDecision(
                    source_address=decision.source_address,
                    target_address=decision.target_address,
                    fallthrough_address=decision.fallthrough_address,
                    condition=decision.condition,
                    outcome=TruthValue.UNKNOWN,
                )
            branch_decisions[fact.cpu_address] = decision
        if was_unresolved:
            unresolved.add(address)
        for edge in indirect_edges:
            if (
                0x200 <= edge.target_address < len(image.data)
                and edge.target_address % 2 == 0
            ):
                edges[(edge.source_address, edge.target_address)] = edge
        # The callee may change any register or memory before returning, so
        # the return path must not inherit the caller's facts.
        return_address = (
            fact.cpu_address + fact.length
            if fact.flow_type.upper() in _CALL_FLOWS
            else None
        )
        for successor in successors:
            if successor in by_address:
                queue.append((
                    successor,
                    AbstractState.initial()
                    if successor == return_address
                    else outgoing,
                ))
    return InterpretationResult(
        reached_addresses=tuple(sorted(states)),
        indirect_edges=tuple(edges[key] for key in sorted(edges)),
        branch_decisions=tuple(
            branch_decisions[address] for address in sorted(branch_decisions)
        ),
        unresolved_indirect_addresses=tuple(sorted(unresolved)),
        state_updates=state_updates,
        widened_addresses=tuple(sorted(widened)),
    )


def retain_trusted_instruction_facts(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    *,
    additional_entrypoints: set[int] | frozenset[int] = frozenset(),
) -> dict[int, InstructionFact]:
    """Remove backend code islands that have no trusted control-flow root.

    Roots are the reset vector, validated exception vectors and planned
    seeds. Call targets are trusted only when the call itself is reached;
    a backend function label alone does not make an island trusted.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    roots = {image.reset_address, *additional_entrypoints}
    roots.update(
        vector.address
        for vector in image.vector_table[1:]
        if vector.address in by_address
    )
    reached: set[int] = set()
    pending = list(roots)
    while pending:
        address = pending.pop()
        fact = by_address.get(address)
        if fact is None or address in reached:
            continue
        reached.add(address)
        flow = fact.flow_type.upper()
        # Ghidra may attach hundreds of speculative targets to a computed
        # jump through a word-offset table. Following them as proven control
        # flow can turn the neighboring pointer table into trusted code.
        # The abstract interpreter and structural table readers supply
        # independently proven targets through additional_entrypoints.
        if (flow not in {"COMPUTED_JUMP", "COMPUTED_CALL"}
                or len(fact.flows) <= MAX_BACKEND_COMPUTED_FLOW_TARGETS):
            pending.extend(fact.flows)
        if flow in {
            "FALL_THROUGH",
            "CONDITIONAL_JUMP",
            "UNCONDITIONAL_CALL",
            "COMPUTED_CALL",
        }:
            pending.append(fact.cpu_address + fact.length)
    return {
        offset: fact for offset, fact in facts.items()
        if fact.cpu_address in reached
    }


@dataclass(frozen=True)
class TrustedCfg:
    facts: dict[int, InstructionFact]
    interpretation: InterpretationResult
    # Entrypoints plus proven indirect targets; retaining backend facts from
    # exactly these roots reproduces ``facts``.
    roots: frozenset[int]
    # Instruction starts reachable from the entrypoints alone, before any
    # indirect target was promoted to a root.
    entry_reached: frozenset[int]
    iterations: int


def interpret_trusted_cfg(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    *,
    entrypoints: set[int] | frozenset[int],
    max_iterations: int = MAX_TRUSTED_ROOT_PASSES,
) -> TrustedCfg:
    """Interpret only rooted code and promote its proven indirect targets.

    Backend code islands are never interpreted, so an edge computed inside
    unrooted code cannot make its target trusted. Each round retains facts
    from the current roots, interprets them and adds newly proven indirect
    targets. Roots only grow, so the bounded loop reaches a fixpoint.
    """
    entrypoints = frozenset(entrypoints)
    roots = entrypoints
    entry_reached: frozenset[int] | None = None
    for iteration in range(1, max_iterations + 1):
        trusted = retain_trusted_instruction_facts(
            image, facts, additional_entrypoints=roots
        )
        if entry_reached is None:
            entry_reached = frozenset(fact.cpu_address for fact in trusted.values())
        result = interpret_known_cfg(
            image, trusted, additional_entrypoints=entrypoints
        )
        proven = {
            edge.target_address
            for edge in result.indirect_edges
            if edge.confidence == "proven"
        }
        if proven <= roots:
            return TrustedCfg(trusted, result, roots, entry_reached, iteration)
        roots = roots | proven
    raise ValueError(
        "trusted M68K control flow did not reach a fixpoint after "
        f"{max_iterations} passes"
    )
