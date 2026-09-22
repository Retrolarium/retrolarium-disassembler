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
        candidates[target] = EntryPointCandidate(
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
    return tuple(candidates[address] for address in sorted(candidates))


def discover_packed_orphan_candidates(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    *,
    maximum_gap: int = 128,
) -> tuple[OrphanCandidate, ...]:
    """Find short code-shaped gaps immediately after a terminal instruction.

    This deliberately avoids scanning arbitrary ROM. A candidate needs known
    code on both sides, an exact boundary after a terminating flow, a
    non-table-like first word, and either a short gap or a return opcode before
    the next known instruction. Ghidra still has to decode the candidate.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    addresses = sorted(by_address)
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
        if not _plausible_orphan_start(first_word) or len(set(payload)) <= 1:
            continue
        words = {
            int.from_bytes(payload[offset:offset + 2], "big")
            for offset in range(0, len(payload) - 1, 2)
        }
        has_return = bool(words & return_opcodes)
        if gap_size > 24 and not has_return:
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
                    if has_return
                    else "short packed gap after terminal flow"
                ),
            )
        )
    return tuple(candidates)


_REGISTER = re.compile(r"([DA][0-7])(?:[bwl])?$", re.I)
_IMMEDIATE = re.compile(r"#?(-?0x[0-9a-f]+|-?\d+)$", re.I)
_ABSOLUTE = re.compile(r"\((-?0x[0-9a-f]+|-?\d+)\)\.[wl]$", re.I)
_INDIRECT_REGISTER = re.compile(r"\(([Aa][0-7])\)$")


def _register_name(operand: str) -> str | None:
    match = _REGISTER.fullmatch(operand.strip())
    return match.group(1).lower() if match else None


def _source_value(
    operand: str, state: AbstractState, *, address: bool = False
) -> AbstractValue:
    register = _register_name(operand)
    if register is not None:
        return state.register(register)
    immediate = _IMMEDIATE.fullmatch(operand.strip())
    if immediate is not None:
        return AbstractValue.constant(
            int(immediate.group(1), 0),
            address_space="rom" if address else "scalar",
        )
    absolute = _ABSOLUTE.fullmatch(operand.strip())
    if absolute is not None:
        value = int(absolute.group(1), 0) & 0xFFFFFF
        if address:
            space = "ram" if value >= 0xFF0000 else "rom"
            return AbstractValue.constant(value, address_space=space)
        return dict(state.memory).get(value, AbstractValue.unknown())
    return AbstractValue.unknown()


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
            return state.with_register(
                destination, _source_value(operands[0], state)
            )
    if mnemonic.startswith("MOVE.") and len(operands) == 2:
        value = _source_value(operands[0], state)
        updated = state
        destination = _register_name(operands[1])
        if destination is not None:
            updated = updated.with_register(destination, value)
        immediate = _IMMEDIATE.fullmatch(operands[0].strip())
        absolute = _ABSOLUTE.fullmatch(operands[1].strip())
        if mnemonic == "MOVE.L" and immediate is not None and absolute is not None:
            updated = updated.with_memory(
                int(absolute.group(1), 0),
                AbstractValue.constant(
                    int(immediate.group(1), 0), address_space="rom"
                ),
            )
        return _with_logic_flags(updated, value, _operation_bits(mnemonic))
    if mnemonic.startswith("CLR.") and len(operands) == 1:
        value = AbstractValue.constant(0)
        updated = state
        destination = _register_name(operands[0])
        if destination is not None:
            updated = updated.with_register(destination, value)
        return _with_logic_flags(updated, value, _operation_bits(mnemonic))
    if (
        mnemonic.startswith(("ADD", "ADDA", "ADDQ"))
        and len(operands) == 2
    ):
        destination = _register_name(operands[1])
        if destination is not None:
            left = state.register(destination)
            right = _source_value(operands[0], state)
            updated = state.with_register(destination, left.add(right))
            if mnemonic.startswith("ADDA"):
                return updated
            flags = _arithmetic_flags(
                left, right, _operation_bits(mnemonic), subtract=False
            )
            return updated.with_flags(**flags, x=flags["c"])
    if (
        mnemonic.startswith(("SUB", "SUBA", "SUBQ"))
        and len(operands) == 2
    ):
        destination = _register_name(operands[1])
        if destination is not None:
            left = state.register(destination)
            right = _source_value(operands[0], state)
            updated = state.with_register(destination, left.subtract(right))
            if mnemonic.startswith("SUBA"):
                return updated
            flags = _arithmetic_flags(
                left, right, _operation_bits(mnemonic), subtract=True
            )
            return updated.with_flags(**flags, x=flags["c"])
    if mnemonic.startswith("ANDI.") and len(operands) == 2:
        destination = _register_name(operands[1])
        immediate = _IMMEDIATE.fullmatch(operands[0].strip())
        if destination is not None and immediate is not None:
            value = state.register(destination).bitwise_and(
                int(immediate.group(1), 0)
            )
            updated = state.with_register(destination, value)
            return _with_logic_flags(
                updated, value, _operation_bits(mnemonic)
            )
    if mnemonic.startswith("AND.") and len(operands) == 2:
        destination = _register_name(operands[1])
        if destination is not None:
            left = state.register(destination)
            right = _source_value(operands[0], state)
            left_values = left.concrete_values(1)
            right_values = right.concrete_values(1)
            if left_values is not None:
                value = right.bitwise_and(left_values[0])
            elif right_values is not None:
                value = left.bitwise_and(right_values[0])
            else:
                value = AbstractValue.unknown()
            updated = state.with_register(destination, value)
            return _with_logic_flags(
                updated, value, _operation_bits(mnemonic)
            )
    if mnemonic.startswith("TST.") and len(operands) == 1:
        return _with_logic_flags(
            state,
            _source_value(operands[0], state),
            _operation_bits(mnemonic),
        )
    if mnemonic.startswith("CMP") and len(operands) == 2:
        right = _source_value(operands[0], state)
        left = _source_value(operands[1], state)
        return state.with_flags(**_arithmetic_flags(
            left, right, _operation_bits(mnemonic), subtract=True
        ))
    if mnemonic.startswith("BTST") and len(operands) == 2:
        bit_value = _source_value(operands[0], state).concrete_values(1)
        tested = _source_value(operands[1], state).concrete_values()
        zero = TruthValue.UNKNOWN
        if bit_value is not None and tested is not None:
            bit = bit_value[0] % (
                32 if _register_name(operands[1]) is not None else 8
            )
            zero = _uniform_truth({not bool(value & (1 << bit)) for value in tested})
        return state.with_flags(z=zero)
    # Do not let a value survive across an unmodelled instruction that writes
    # the same register. A stale constant is unsafe when it later controls an
    # indirect branch.
    if operands:
        destination = _register_name(operands[-1])
        if destination is not None and mnemonic.startswith((
            "OR.", "EOR.", "LSL.", "LSR.", "ASL.", "ASR.",
            "ROL.", "ROR.", "ROXL.", "ROXR.", "MUL", "DIV",
            "NEG.", "NEGX.", "NOT.", "EXT.", "SWAP",
        )):
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
        values = state.register(register_name).concrete_values(32)
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
            values = state.register(register_name).concrete_values(32)
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
) -> InterpretationResult:
    """Propagate abstract states over backend-decoded instructions."""
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    entrypoints = {image.reset_address}
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
        for successor in successors:
            if successor in by_address:
                queue.append((successor, outgoing))
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
