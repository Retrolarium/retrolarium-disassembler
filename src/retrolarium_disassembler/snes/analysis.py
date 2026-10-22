"""Independent bank-aware W65C816 decoding and abstract state propagation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from collections import deque
from typing import Iterable, TYPE_CHECKING

from retrolarium_core.snes import SnesError, SnesImage, snes_to_rom_offset

if TYPE_CHECKING:
    from retrolarium_disassembler.facts import InstructionFact


class SnesAnalysisError(RuntimeError):
    """The W65C816 analysis could not preserve a sound instruction model."""


@dataclass(frozen=True)
class CpuState:
    e: int | None
    m: int | None
    x: int | None
    carry: int | None
    pbr: int
    dbr: int | None
    direct_page: int | None
    accumulator: int | None = None
    pending_bank_push: int | None = None


@dataclass(frozen=True)
class Flow:
    kind: str
    target: int | None


@dataclass(frozen=True)
class Instruction:
    logical_address: int
    physical_offset: int
    raw: bytes
    opcode: int
    mnemonic: str
    addressing_mode: str
    state_before: CpuState
    state_after: CpuState
    flows: tuple[Flow, ...]

    @property
    def length(self) -> int:
        return len(self.raw)


@dataclass(frozen=True)
class AnalysisDiagnostic:
    kind: str
    logical_address: int
    message: str


@dataclass(frozen=True)
class AnalysisResult:
    input_sha256: str
    mapping: str
    entries: tuple[int, ...]
    instructions: tuple[Instruction, ...]
    diagnostics: tuple[AnalysisDiagnostic, ...]


_ROWS = (
    "BRK:imm8 ORA:dpix COP:imm8 ORA:sr TSB:dp ORA:dp ASL:dp ORA:dpil PHP:imp ORA:immM ASL:acc PHD:imp TSB:abs ORA:abs ASL:abs ORA:long",
    "BPL:rel8 ORA:dpiy ORA:dpi ORA:sriy TRB:dp ORA:dpx ASL:dpx ORA:dpily CLC:imp ORA:absy INC:acc TCS:imp TRB:abs ORA:absx ASL:absx ORA:longx",
    "JSR:abs AND:dpix JSL:long AND:sr BIT:dp AND:dp ROL:dp AND:dpil PLP:imp AND:immM ROL:acc PLD:imp BIT:abs AND:abs ROL:abs AND:long",
    "BMI:rel8 AND:dpiy AND:dpi AND:sriy BIT:dpx AND:dpx ROL:dpx AND:dpily SEC:imp AND:absy DEC:acc TSC:imp BIT:absx AND:absx ROL:absx AND:longx",
    "RTI:imp EOR:dpix WDM:imm8 EOR:sr MVP:block EOR:dp LSR:dp EOR:dpil PHA:imp EOR:immM LSR:acc PHK:imp JMP:abs EOR:abs LSR:abs EOR:long",
    "BVC:rel8 EOR:dpiy EOR:dpi EOR:sriy MVN:block EOR:dpx LSR:dpx EOR:dpily CLI:imp EOR:absy PHY:imp TCD:imp JML:long EOR:absx LSR:absx EOR:longx",
    "RTS:imp ADC:dpix PER:rel16 ADC:sr STZ:dp ADC:dp ROR:dp ADC:dpil PLA:imp ADC:immM ROR:acc RTL:imp JMP:absi ADC:abs ROR:abs ADC:long",
    "BVS:rel8 ADC:dpiy ADC:dpi ADC:sriy STZ:dpx ADC:dpx ROR:dpx ADC:dpily SEI:imp ADC:absy PLY:imp TDC:imp JMP:absix ADC:absx ROR:absx ADC:longx",
    "BRA:rel8 STA:dpix BRL:rel16 STA:sr STY:dp STA:dp STX:dp STA:dpil DEY:imp BIT:immM TXA:imp PHB:imp STY:abs STA:abs STX:abs STA:long",
    "BCC:rel8 STA:dpiy STA:dpi STA:sriy STY:dpx STA:dpx STX:dpy STA:dpily TYA:imp STA:absy TXS:imp TXY:imp STZ:abs STA:absx STZ:absx STA:longx",
    "LDY:immX LDA:dpix LDX:immX LDA:sr LDY:dp LDA:dp LDX:dp LDA:dpil TAY:imp LDA:immM TAX:imp PLB:imp LDY:abs LDA:abs LDX:abs LDA:long",
    "BCS:rel8 LDA:dpiy LDA:dpi LDA:sriy LDY:dpx LDA:dpx LDX:dpy LDA:dpily CLV:imp LDA:absy TSX:imp TYX:imp LDY:absx LDA:absx LDX:absy LDA:longx",
    "CPY:immX CMP:dpix REP:imm8 CMP:sr CPY:dp CMP:dp DEC:dp CMP:dpil INY:imp CMP:immM DEX:imp WAI:imp CPY:abs CMP:abs DEC:abs CMP:long",
    "BNE:rel8 CMP:dpiy CMP:dpi CMP:sriy PEI:dpi CMP:dpx DEC:dpx CMP:dpily CLD:imp CMP:absy PHX:imp STP:imp JML:absil CMP:absx DEC:absx CMP:longx",
    "CPX:immX SBC:dpix SEP:imm8 SBC:sr CPX:dp SBC:dp INC:dp SBC:dpil INX:imp SBC:immM NOP:imp XBA:imp CPX:abs SBC:abs INC:abs SBC:long",
    "BEQ:rel8 SBC:dpiy SBC:dpi SBC:sriy PEA:abs SBC:dpx INC:dpx SBC:dpily SED:imp SBC:absy PLX:imp XCE:imp JSR:absix SBC:absx INC:absx SBC:longx",
)

OPCODES: tuple[tuple[str, str], ...] = tuple(tuple(token.split(":", 1)) for row in _ROWS for token in row.split())
if len(OPCODES) != 256:
    raise AssertionError("W65C816 opcode table must have 256 entries")

_MODE_LENGTHS = {
    "imp": 1,
    "acc": 1,
    "imm8": 2,
    "dp": 2,
    "dpx": 2,
    "dpy": 2,
    "dpi": 2,
    "dpix": 2,
    "dpiy": 2,
    "dpil": 2,
    "dpily": 2,
    "sr": 2,
    "sriy": 2,
    "rel8": 2,
    "abs": 3,
    "absx": 3,
    "absy": 3,
    "absi": 3,
    "absix": 3,
    "absil": 3,
    "rel16": 3,
    "block": 3,
    "long": 4,
    "longx": 4,
}

_CONDITIONAL_BRANCHES = {"BPL", "BMI", "BVC", "BVS", "BCC", "BCS", "BNE", "BEQ"}
_TERMINATORS = {"RTS", "RTL", "RTI", "STP", "BRK", "COP"}
_ACCUMULATOR_WRITES = {
    "ADC",
    "AND",
    "ASL",
    "DEC",
    "EOR",
    "INC",
    "LDA",
    "LSR",
    "ORA",
    "PLA",
    "ROL",
    "ROR",
    "SBC",
    "TDC",
    "TSC",
    "TXA",
    "TYA",
    "XBA",
}
# Instructions that leave the carry as the data makes it.
_CARRY_WRITES = {"ADC", "SBC", "CMP", "CPX", "CPY", "ASL", "LSR", "ROL", "ROR"}
# What a callee may change in its caller's context, by the instructions that
# change it.
_CALLEE_CHANGES = {
    "e": {"XCE"},
    "m": {"REP", "SEP", "PLP", "RTI", "XCE"},
    "x": {"REP", "SEP", "PLP", "RTI", "XCE"},
    "dbr": {"PLB"},
    "direct_page": {"PLD", "TCD"},
}
_RETURNS = {"RTS", "RTL"}
_STACK_CHANGERS = {
    "BRK",
    "COP",
    "JSL",
    "JSR",
    "PEA",
    "PEI",
    "PER",
    "PHA",
    "PHB",
    "PHD",
    "PHK",
    "PHP",
    "PHX",
    "PHY",
    "PLA",
    "PLB",
    "PLD",
    "PLP",
    "PLX",
    "PLY",
    "RTI",
    "RTL",
    "RTS",
}


def _merge_value(left: int | None, right: int | None) -> int | None:
    return left if left == right else None


def merge_states(left: CpuState, right: CpuState) -> CpuState:
    if left.pbr != right.pbr:
        raise SnesAnalysisError("cannot merge states from different program banks")
    merged = CpuState(
        e=_merge_value(left.e, right.e),
        m=_merge_value(left.m, right.m),
        x=_merge_value(left.x, right.x),
        carry=_merge_value(left.carry, right.carry),
        pbr=left.pbr,
        dbr=_merge_value(left.dbr, right.dbr),
        direct_page=_merge_value(left.direct_page, right.direct_page),
        accumulator=_merge_value(left.accumulator, right.accumulator),
        pending_bank_push=_merge_value(left.pending_bank_push, right.pending_bank_push),
    )
    if merged.e == 1:
        merged = replace(merged, m=1, x=1)
    return merged


def _instruction_length(mode: str, state: CpuState) -> int | None:
    if mode == "immM":
        return None if state.m is None else 2 if state.m else 3
    if mode == "immX":
        return None if state.x is None else 2 if state.x else 3
    return _MODE_LENGTHS[mode]


def _u16(raw: bytes) -> int:
    return int.from_bytes(raw[1:3], "little")


def _u24(raw: bytes) -> int:
    return int.from_bytes(raw[1:4], "little")


def _relative_target(address: int, raw: bytes, width: int) -> int:
    displacement = int.from_bytes(raw[1 : 1 + width], "little", signed=True)
    low = ((address & 0xFFFF) + len(raw) + displacement) & 0xFFFF
    return (address & 0xFF0000) | low


def _apply_state(mnemonic: str, mode: str, raw: bytes, state: CpuState) -> CpuState:
    result = replace(state, pbr=state.pbr)
    if mnemonic not in {"PHK", "PHB", "PLB"} and mnemonic in _STACK_CHANGERS:
        result = replace(result, pending_bank_push=None)
    if mnemonic == "CLC":
        result = replace(result, carry=0)
    elif mnemonic == "SEC":
        result = replace(result, carry=1)
    elif mnemonic in {"REP", "SEP"}:
        mask = raw[1]
        setting = mnemonic == "SEP"
        carry = result.carry
        if mask & 0x01:
            carry = 1 if setting else 0
        m = result.m
        x = result.x
        if result.e == 1:
            m = x = 1
        elif result.e == 0:
            if mask & 0x20:
                m = 1 if setting else 0
            if mask & 0x10:
                x = 1 if setting else 0
        else:
            if mask & 0x20:
                m = None
            if mask & 0x10:
                x = None
        result = replace(result, carry=carry, m=m, x=x)
    elif mnemonic == "XCE":
        new_e = result.carry
        new_carry = result.e
        result = replace(result, e=new_e, carry=new_carry)
        if new_e == 1:
            result = replace(result, m=1, x=1)
        elif new_e is None:
            # Emulation forces 8-bit widths; native keeps them: a width is
            # known only where both agree.
            result = replace(result, m=1 if result.m == 1 else None, x=1 if result.x == 1 else None)
    elif mnemonic in _CARRY_WRITES:
        result = replace(result, carry=None)
    elif mnemonic in {"PLP", "RTI"}:
        result = replace(result, carry=None)
        result = replace(
            result,
            m=1 if result.e == 1 else None,
            x=1 if result.e == 1 else None,
        )
    elif mnemonic == "PHK":
        result = replace(result, pending_bank_push=result.pbr)
    elif mnemonic == "PHB":
        result = replace(result, pending_bank_push=result.dbr)
    elif mnemonic == "PLB":
        result = replace(
            result,
            dbr=result.pending_bank_push,
            pending_bank_push=None,
        )
    elif mnemonic == "PLD":
        result = replace(result, direct_page=None)
    elif mnemonic == "TCD":
        result = replace(result, direct_page=result.accumulator)
    elif mnemonic == "TDC":
        result = replace(result, accumulator=result.direct_page)

    if mnemonic == "LDA" and mode == "immM":
        value = int.from_bytes(raw[1:], "little")
        if result.m == 0:
            result = replace(result, accumulator=value)
        else:
            previous = result.accumulator
            accumulator = None if previous is None else (previous & 0xFF00) | value
            result = replace(result, accumulator=accumulator)
    elif mnemonic in _ACCUMULATOR_WRITES and mnemonic not in {"TCD", "TDC"}:
        result = replace(result, accumulator=None)
    return result


def _flows(address: int, mnemonic: str, mode: str, raw: bytes) -> tuple[Flow, ...]:
    fallthrough = (address & 0xFF0000) | (((address & 0xFFFF) + len(raw)) & 0xFFFF)
    if mnemonic in _TERMINATORS:
        return (Flow("terminate", None),)
    if mnemonic in _CONDITIONAL_BRANCHES:
        return (
            Flow("branch", _relative_target(address, raw, 1)),
            Flow("fallthrough", fallthrough),
        )
    if mnemonic in {"BRA", "BRL"}:
        width = 1 if mnemonic == "BRA" else 2
        return (Flow("branch", _relative_target(address, raw, width)),)
    if mnemonic in {"JSR", "JSL"}:
        if mode == "abs":
            target = (address & 0xFF0000) | _u16(raw)
        elif mode == "long":
            target = _u24(raw)
        else:
            target = None
        return (Flow("call", target), Flow("fallthrough", fallthrough))
    if mnemonic in {"JMP", "JML"}:
        if mode == "abs":
            target = (address & 0xFF0000) | _u16(raw)
        elif mode == "long":
            target = _u24(raw)
        else:
            target = None
        return (Flow("jump", target),)
    return (Flow("fallthrough", fallthrough),)


def _read_instruction(image: SnesImage, address: int, state: CpuState) -> tuple[bytes, str, str] | None:
    try:
        physical = snes_to_rom_offset(image, address)
    except SnesError:
        return None
    opcode = image.data[physical]
    mnemonic, mode = OPCODES[opcode]
    length = _instruction_length(mode, state)
    if length is None:
        return b"", mnemonic, mode
    raw = bytearray()
    for delta in range(length):
        operand_address = (address & 0xFF0000) | ((address + delta) & 0xFFFF)
        try:
            offset = snes_to_rom_offset(image, operand_address)
        except SnesError:
            return None
        raw.append(image.data[offset])
    return bytes(raw), mnemonic, mode


def _entry_seeds(image: SnesImage) -> list[tuple[int, CpuState]]:
    seeds: list[tuple[int, CpuState]] = []
    seen: set[tuple[int, str]] = set()
    for vector in image.vector_table:
        address = vector.cpu_address
        if address is None or vector.rom_offset is None:
            continue
        key = (address, vector.mode)
        if key in seen:
            continue
        seen.add(key)
        if vector.mode == "emulation":
            state = CpuState(1, 1, 1, None, 0, None, None)
        else:
            state = CpuState(0, None, None, None, 0, None, None)
        if vector.name == "reset":
            state = CpuState(1, 1, 1, None, 0, 0, 0)
        seeds.append((address, state))
    return seeds


def _call_summaries(instructions: dict[int, Instruction]) -> dict[int, dict[str, int | None]]:
    """For each called routine, the context values it may change and the
    value it returns with (None: unknown or differing between its returns).
    A routine's body is what its entry reaches without following calls; what
    the routines it calls change counts as its own change."""

    def body(entry: int) -> set[int]:
        seen: set[int] = set()
        stack = [entry]
        while stack:
            address = stack.pop()
            if address in seen or address not in instructions:
                continue
            seen.add(address)
            instruction = instructions[address]
            if instruction.mnemonic in _RETURNS or instruction.mnemonic == "RTI":
                continue
            stack.extend(
                flow.target
                for flow in instruction.flows
                if flow.kind in {"branch", "fallthrough", "jump"} and flow.target is not None
            )
        return seen

    bodies: dict[int, set[int]] = {}
    changed: dict[int, set[str]] = {}

    def changes(entry: int, visiting: set[int]) -> set[str]:
        if entry in changed:
            return changed[entry]
        if entry in visiting:
            return set()
        visiting.add(entry)
        bodies.setdefault(entry, body(entry))
        fields: set[str] = set()
        for address in bodies[entry]:
            instruction = instructions[address]
            fields |= {field for field, mnemonics in _CALLEE_CHANGES.items() if instruction.mnemonic in mnemonics}
            if instruction.mnemonic in {"JSR", "JSL"}:
                for flow in instruction.flows:
                    if flow.kind == "call" and flow.target is not None:
                        fields |= changes(flow.target, visiting)
        changed[entry] = fields
        return fields

    callees = {
        flow.target
        for instruction in instructions.values()
        if instruction.mnemonic in {"JSR", "JSL"}
        for flow in instruction.flows
        if flow.kind == "call" and flow.target is not None
    }
    summaries: dict[int, dict[str, int | None]] = {}
    for entry in sorted(callees):
        fields = changes(entry, set())
        exits = [
            instructions[address].state_after
            for address in bodies.get(entry, body(entry))
            if instructions[address].mnemonic in _RETURNS
        ]
        summary: dict[str, int | None] = {}
        for field in sorted(fields):
            values = {getattr(state, field) for state in exits}
            summary[field] = values.pop() if len(values) == 1 else None
        summaries[entry] = summary
    return summaries


def _after_call(state: CpuState, summary: dict[str, int | None] | None) -> CpuState:
    """The caller's context back from a call: what the callee changes as it
    returns it, the rest as it was; the carry and accumulator are the
    callee's to leave."""
    state = replace(state, carry=None, accumulator=None)
    if summary:
        state = replace(state, **summary)
        if state.e == 1:
            state = replace(state, m=1, x=1)
    return state


def analyze_snes(
    image: SnesImage,
    seeds: Iterable[tuple[int, CpuState]] | None = None,
) -> AnalysisResult:
    initial = list(_entry_seeds(image) if seeds is None else seeds)
    if not initial:
        raise SnesAnalysisError("SNES analysis has no backed entry points")
    diagnostics: list[AnalysisDiagnostic] = []
    diagnostic_keys: set[tuple[str, int, str]] = set()

    def diagnose(kind: str, address: int, message: str) -> None:
        key = (kind, address, message)
        if key not in diagnostic_keys:
            diagnostic_keys.add(key)
            diagnostics.append(AnalysisDiagnostic(kind, address, message))

    forced_states: dict[int, CpuState] = {}
    # What each called routine returns with, from the last pass; a pass that
    # changes them runs again.
    summaries: dict[int, dict[str, int | None]] = {}
    for _iteration in range(1024):
        states: dict[int, CpuState] = {}
        instructions: dict[int, Instruction] = {}
        queue: deque[tuple[int, CpuState]] = deque(initial)
        restart = False
        while queue:
            address, incoming = queue.popleft()
            incoming = replace(incoming, pbr=address >> 16)
            forced = forced_states.get(address)
            if forced is not None:
                incoming = merge_states(forced, incoming)
            previous = states.get(address)
            if previous is not None:
                merged = merge_states(previous, incoming)
                if merged == previous:
                    continue
                widened = merged if forced is None else merge_states(forced, merged)
                if forced != widened:
                    forced_states[address] = widened
                    diagnose(
                        "state-conflict",
                        address,
                        "control-flow join widened one or more W65C816 context values",
                    )
                    restart = True
                    break
                incoming = widened
            states[address] = incoming

            decoded = _read_instruction(image, address, incoming)
            if decoded is None:
                diagnose(
                    "unmapped-fetch",
                    address,
                    "instruction crosses or starts outside ROM",
                )
                continue
            raw, mnemonic, mode = decoded
            if not raw:
                flag = "M" if mode == "immM" else "X"
                diagnose(
                    "ambiguous-width",
                    address,
                    f"{mnemonic} immediate length requires a known {flag} flag",
                )
                continue
            physical = snes_to_rom_offset(image, address)
            after = _apply_state(mnemonic, mode, raw, incoming)
            flows = _flows(address, mnemonic, mode, raw)
            instructions[address] = Instruction(
                address,
                physical,
                raw,
                raw[0],
                mnemonic,
                mode,
                incoming,
                after,
                flows,
            )
            for flow in flows:
                if flow.target is None or flow.kind == "terminate":
                    if flow.target is None and flow.kind in {"call", "jump"}:
                        diagnose(
                            "indirect-flow",
                            address,
                            f"{mnemonic} target requires runtime pointer evidence",
                        )
                    continue
                target_state = replace(after, pbr=flow.target >> 16)
                if flow.kind == "fallthrough" and mnemonic in {"JSR", "JSL"}:
                    callee = next((item.target for item in flows if item.kind == "call"), None)
                    target_state = _after_call(target_state, summaries.get(callee) if callee is not None else None)
                queue.append((flow.target, target_state))
        if not restart:
            found = _call_summaries(instructions)
            # Widened, never narrowed again: the passes settle.
            merged = {
                entry: {
                    field: (
                        value if field not in summaries.get(entry, {}) else _merge_value(summaries[entry][field], value)
                    )
                    for field, value in summary.items()
                }
                for entry, summary in found.items()
            }
            if merged == summaries:
                break
            summaries = merged
    else:
        raise SnesAnalysisError("W65C816 state propagation did not converge")

    return AnalysisResult(
        input_sha256=image.rom_sha256,
        mapping=image.header.map_mode,
        entries=tuple(sorted({address for address, _ in initial})),
        instructions=tuple(instructions[key] for key in sorted(instructions)),
        diagnostics=tuple(sorted(diagnostics, key=lambda item: (item.logical_address, item.kind))),
    )


def _state_manifest(state: CpuState) -> dict[str, int | None]:
    return {
        "e": state.e,
        "m": state.m,
        "x": state.x,
        "carry": state.carry,
        "pbr": state.pbr,
        "dbr": state.dbr,
        "direct_page": state.direct_page,
    }


def analysis_manifest(result: AnalysisResult) -> dict[str, object]:
    return {
        "schema": "retrolarium.snes.state-analysis",
        "schema_version": 1,
        "input_sha256": result.input_sha256,
        "mapping": result.mapping,
        "cpu": "w65c816",
        "entries": list(result.entries),
        "instructions": [
            {
                "logical_address": item.logical_address,
                "physical_offset": item.physical_offset,
                "opcode": item.opcode,
                "length": item.length,
                "bytes": item.raw.hex(),
                "mnemonic": item.mnemonic,
                "addressing_mode": item.addressing_mode,
                "state_before": _state_manifest(item.state_before),
                "state_after": _state_manifest(item.state_after),
                "flows": [{"kind": flow.kind, "target": flow.target} for flow in item.flows],
            }
            for item in result.instructions
        ],
        "diagnostics": [
            {
                "kind": item.kind,
                "logical_address": item.logical_address,
                "message": item.message,
            }
            for item in result.diagnostics
        ],
    }


def validate_backend_facts(
    result: AnalysisResult,
    facts: dict[int, "InstructionFact"],
) -> dict[int, "InstructionFact"]:
    """Accept backend facts only where independent state-aware decoding agrees."""
    from retrolarium_disassembler.facts import FactError

    independent = {instruction.logical_address: instruction for instruction in result.instructions}
    accepted: dict[int, InstructionFact] = {}
    for physical, fact in facts.items():
        expected = independent.get(fact.cpu_address)
        if expected is None:
            continue
        if fact.raw != expected.raw or fact.length != expected.length:
            raise FactError(
                f"backend instruction boundary disagrees with independent W65C816 state at ${fact.cpu_address:06X}"
            )
        if fact.mnemonic != expected.mnemonic:
            raise FactError(
                f"backend mnemonic {fact.mnemonic} disagrees with {expected.mnemonic} at ${fact.cpu_address:06X}"
            )
        accepted[physical] = fact
    return accepted
