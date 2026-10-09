"""Validate speculative unused-function candidates without promoting raw bytes.

An absent known caller is evidence of an orphan, not proof of runtime dead code.
The search deliberately starts only after known terminal instructions.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import asdict, dataclass
from typing import Callable

from retrolarium_kit.facts import InstructionFact
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_kit.megadrive_pointers import _absolute_referenced_addresses


MAX_UNUSED_GAP = 2048
_TERMINALS = {"TERMINATOR", "CALL_TERMINATOR", "UNCONDITIONAL_JUMP", "COMPUTED_JUMP"}
_JUMPS = {"CONDITIONAL_JUMP", "UNCONDITIONAL_JUMP"}
_CALLS = {"UNCONDITIONAL_CALL", "CONDITIONAL_CALL"}


@dataclass(frozen=True)
class UnusedCodeCandidate:
    address: int
    end: int
    preceding_address: int
    instruction_count: int
    instruction_addresses: tuple[int, ...]
    signatures: tuple[str, ...]
    evidence: str
    confidence: str = "high"
    runtime_status: str = "unknown"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_unused_fragment(
    image: MegaDriveImage,
    fragment: tuple[InstructionFact, ...],
    known: dict[int, InstructionFact],
    *,
    data_addresses: set[int],
    protected_ranges: tuple[tuple[int, int], ...] = (),
    render_instruction: Callable[[InstructionFact], str | None],
) -> tuple[str | None, tuple[str, ...]]:
    """Return the rejection reason (None on success) and boundary signatures."""
    if not fragment:
        return "empty_fragment", ()
    start = fragment[0].cpu_address
    end = fragment[-1].cpu_address + fragment[-1].length
    if start & 1 or start < 0x200 or end > len(image.data):
        return "invalid_rom_bounds", ()
    if any(left < end and start < right for left, right in protected_ranges):
        return "known_data_range", ()
    if any(start <= address < end for address in data_addresses):
        return "known_data_reference", ()
    if fragment[-1].mnemonic.upper() != "RTS" or fragment[-1].raw != b"\x4e\x75":
        return "no_final_rts", ()
    if fragment[0].mnemonic.upper().startswith("ORI."):
        # Small word tables/record headers commonly decode as ORI.B #n,Dn,
        # followed by genuine code. A valid tail does not validate that header.
        return "ambiguous_ori_entry", ()
    starts = {fact.cpu_address for fact in fragment}
    if any(start <= address < end for address in known):
        return "overlaps_known_code", ()
    cursor = start
    signatures = {"rts"}
    memory_operations = 0
    local_branches = 0
    successors: dict[int, set[int]] = {}
    returns = set()
    bases = set()
    for fact in fragment:
        if (fact.cpu_address != cursor or fact.length < 2 or fact.length & 1
                or len(fact.raw) != fact.length
                or image.data[cursor:cursor + fact.length] != fact.raw):
            return "incomplete_or_conflicting_decode", ()
        cursor += fact.length
        base = fact.mnemonic.upper().split(".", 1)[0]
        bases.add(base)
        if base in {"ILLEGAL", "TRAP", "TRAPV", "RESET", "STOP", "RTE", "RTR"}:
            return "exception_or_non_rts_exit", ()
        if int.from_bytes(fact.raw[:2], "big") >> 12 in {0xA, 0xF}:
            return "unsupported_cpu_opcode", ()
        if render_instruction(fact) is None:
            return "requires_data_directive", ()
        if "(" in fact.operands and base not in {"JMP", "JSR", "LEA", "PEA"}:
            memory_operations += 1
        if base == "NOP" and fact.raw == b"\x4e\x71":
            signatures.add("nop")
        if base in {"MOVEM", "LINK", "UNLK"} and (
                "SP" in fact.operands.upper() or "A7" in fact.operands.upper()):
            signatures.add("stack_frame")
        if any(start <= address < end for address in _absolute_referenced_addresses({0: fact})):
            return "fragment_read_as_data", ()
        flow = fact.flow_type.upper()
        targets = {target & 0xFFFFFF for target in fact.flows}
        edges = set()
        if base == "RTS":
            returns.add(fact.cpu_address)
        elif flow in _JUMPS:
            if not targets or not targets <= starts:
                return "branch_outside_fragment_or_into_operand", ()
            local_branches += 1
            edges.update(targets)
            if flow == "CONDITIONAL_JUMP":
                edges.add(cursor)
        elif flow in _CALLS:
            if not targets or not targets <= starts | known.keys():
                return "unproven_call_target", ()
            if not targets <= starts:
                signatures.add("call_known_code")
            edges.update(targets & starts)
            edges.add(cursor)
        elif flow == "FALL_THROUGH":
            edges.add(cursor)
        else:
            return "unresolved_or_exceptional_flow", ()
        if not edges <= starts:
            return "fallthrough_outside_fragment", ()
        successors[fact.cpu_address] = edges
    # NOP/RTS fill and accidental short decodes are insufficient evidence.
    if len(fragment) < 4 or len(bases) < 3:
        return "insufficient_instruction_variety", ()
    if local_branches and memory_operations >= 2:
        signatures.add("local_control_flow_and_memory")
    if len(signatures) < 2:
        return "insufficient_boundary_signatures", ()
    reached = set()
    pending = [start]
    while pending:
        address = pending.pop()
        if address not in reached:
            reached.add(address)
            pending.extend(successors[address] - reached)
    if reached != starts:
        return "unreachable_bytes_in_fragment", ()
    # Loops may repeat, but every instruction must have a path to an RTS.
    reverse = {address: set() for address in starts}
    for address, edges in successors.items():
        for target in edges:
            reverse[target].add(address)
    can_return = set(returns)
    pending = list(returns)
    while pending:
        address = pending.pop()
        for predecessor in reverse[address] - can_return:
            can_return.add(predecessor)
            pending.append(predecessor)
    if can_return != starts:
        return "closed_loop_without_return_path", ()
    return None, tuple(sorted(signatures))


def discover_validated_unused_candidates(
    image: MegaDriveImage,
    known: dict[int, InstructionFact],
    decoded: dict[int, InstructionFact],
    *,
    protected_ranges: tuple[tuple[int, int], ...] = (),
    render_instruction: Callable[[InstructionFact], str | None],
) -> tuple[tuple[UnusedCodeCandidate, ...], tuple[dict[str, object], ...]]:
    """Search bounded gaps; never resynchronize through bytes rejected as data."""
    known = {fact.cpu_address: fact for fact in known.values()}
    decoded = {fact.cpu_address: fact for fact in decoded.values()}
    addresses = sorted(known)
    data_addresses = _absolute_referenced_addresses(known)
    accepted = []
    rejected = []
    data_sorted = sorted(data_addresses)
    for index, address in enumerate(addresses):
        previous = known[address]
        start = address + previous.length
        end = addresses[index + 1] if index + 1 < len(addresses) else len(image.data)
        if (previous.flow_type.upper() not in _TERMINALS or start in known
                or start & 1 or not 2 <= end - start <= MAX_UNUSED_GAP):
            continue
        # Stop at the first explicit data base instead of decoding beyond it.
        data_index = bisect_left(data_sorted, start)
        limit = min(end, data_sorted[data_index]) if data_index < len(data_sorted) else end
        cursor = start
        fragment = []
        reason = "incomplete_decode"
        while cursor < limit:
            fact = decoded.get(cursor)
            if fact is None or fact.length < 2 or cursor + fact.length > limit:
                break
            fragment.append(fact)
            cursor += fact.length
            if fact.mnemonic.upper() != "RTS":
                continue
            reason, signatures = validate_unused_fragment(
                image, tuple(fragment), known, data_addresses=data_addresses,
                protected_ranges=protected_ranges, render_instruction=render_instruction,
            )
            if reason is not None:
                # A forward branch can bypass an early return to a later RTS.
                # Keep decoding that same entry, never skip the rejected prefix.
                continue
            accepted.append(UnusedCodeCandidate(
                address=start, end=cursor, preceding_address=previous.cpu_address,
                instruction_count=len(fragment), signatures=signatures,
                instruction_addresses=tuple(fact.cpu_address for fact in fragment),
                evidence="complete renderable CFG ending in RTS; no known data use or caller",
            ))
            previous = fragment[-1]
            start = cursor
            fragment = []
            reason = "incomplete_decode"
        if start < end:
            rejected.append({"address": start, "end": end, "reason":
                             "known_data_reference" if limit == start else reason or "incomplete_decode"})
    return tuple(accepted), tuple(rejected)
