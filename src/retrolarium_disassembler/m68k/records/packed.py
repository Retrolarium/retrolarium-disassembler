"""Batch adjacent orphan roots using speculative facts, never an oracle.

Pseudo-decoded instructions do not become emitted code here. They can justify
the next adjacent root only after a complete, renderable CFG from an already
qualified packed-gap root has been checked. The backend decodes all resulting
roots on the next pass, avoiding one full analysis per adjacent function.
"""
from __future__ import annotations

from collections import deque
from bisect import bisect_left, bisect_right
import re
from typing import Callable

from .facts import InstructionFact
from .m68k_abstract import (
    OrphanCandidate, discover_packed_orphan_candidates, immediate_rom_addresses,
)
from .megadrive import MegaDriveImage
from .m68k_ram_dispatch import discover_inline_trap_calls


def _call_continuations(known: dict[int, InstructionFact], image: MegaDriveImage):
    """Inspect suppressed call fall-through, never a JMP/thunk fall-through.

    Backend no-return inference is unreliable for nonlocal stack unwinding and
    coroutine bookmarks. A continuation is only accepted after the same full
    CFG validation as a packed orphan; a call opcode alone is insufficient.
    """
    starts = sorted(known)
    for fact in known.values():
        if fact.flow_type.upper() != "CALL_TERMINATOR" or len(fact.raw) < 2:
            continue
        opcode = int.from_bytes(fact.raw[:2], "big")
        if not (opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100):
            continue
        start = fact.cpu_address + fact.length
        if start in known or not fact.flows or not all(
                (target & 0xFFFFFF) in known for target in fact.flows):
            continue
        index = bisect_left(starts, start)
        end = min(starts[index] if index < len(starts) else len(image.data),
                  start + 2048)
        if end - start >= 4:
            yield OrphanCandidate(start, fact.cpu_address, end, end - start,
                                  "high", "complete CFG after suppressed call fall-through")


def _long_gap_prefixes(known, image):
    """Validate an immediate gap prefix, including a split function's head."""
    starts = sorted(known)
    for index, address in enumerate(starts[:-1]):
        fact = known[address]
        start = address + fact.length
        if (fact.flow_type.upper() not in {"TERMINATOR", "UNCONDITIONAL_JUMP", "COMPUTED_JUMP"}
                or starts[index + 1] - start < 4 or start & 1):
            continue
        end = min(start + 2048, starts[index + 1], len(image.data))
        yield OrphanCandidate(start, address, end, end - start, "high",
                              "complete bounded CFG at prefix of packed gap")


def _signature_entries(known, decoded, image):
    starts = sorted(known)
    for address, fact in decoded.items():
        if address in known or len(fact.raw) < 2:
            continue
        opcode = int.from_bytes(fact.raw[:2], "big")
        signature = (opcode & 0xF1C0 == 0x41C0 or opcode in {0x48E7, 0x48A7}
                     or opcode & 0xFFF8 == 0x4E50 or opcode & 0xF1FF == 0x303C
                     or opcode & 0xFF00 == 0x0C00 and opcode & 0xC0 != 0xC0)
        index = bisect_right(starts, address) - 1
        if not signature or index < 0:
            continue
        previous = known[starts[index]]
        left = previous.cpu_address + previous.length
        end = min(starts[index + 1] if index + 1 < len(starts) else len(image.data), left + 2048)
        if (previous.flow_type.upper() not in {"TERMINATOR", "CALL_TERMINATOR", "UNCONDITIONAL_JUMP", "COMPUTED_JUMP"}
                or not left < address < end or address & 1):
            continue
        yield OrphanCandidate(address, previous.cpu_address, end, end - address,
                              "high", "bounded function signature; complete CFG, RTS and known callee")


def _complete_cfg(
    image: MegaDriveImage, candidate: OrphanCandidate,
    known: dict[int, InstructionFact], decoded: dict[int, InstructionFact],
    protected_ranges: tuple[tuple[int, int], ...],
    render: Callable[[InstructionFact], str | None],
    data: tuple[int, ...],
    inline_traps: dict | None = None,
    decode_request: Callable[[int, int, str], None] | None = None,
) -> dict[int, InstructionFact]:
    start, end = candidate.address, candidate.following_address
    pending = deque([start])
    body: dict[int, InstructionFact] = {}
    occupied = set()
    successors: dict[int, set[int]] = {}
    exits = set()
    while pending:
        address = pending.popleft()
        if address in body:
            continue
        fact = decoded.get(address)
        if fact is None and start <= address < end and decode_request is not None:
            decode_request(address, start, "missing dispatch CFG instruction")
        data_index = bisect_left(data, address)
        if (fact is None or not start <= address < end or fact.length < 2
                or fact.length & 1 or address + fact.length > end
                or image.data[address:address + fact.length] != fact.raw
                or render(fact) is None
                or data_index < len(data) and data[data_index] < address + fact.length
                or any(left < address + fact.length and address < right
                       for left, right in protected_ranges)):
            return {}
        span = set(range(address, address + fact.length))
        if span & occupied:
            return {}  # Branch into an operand or conflicting pseudo decode.
        occupied.update(span)
        body[address] = fact
        flow = fact.flow_type.upper()
        if flow == "CALL_TERMINATOR":
            opcode = int.from_bytes(fact.raw[:2], "big")
            if opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100:
                flow = "UNCONDITIONAL_CALL"
            elif opcode & 0xFF00 == 0x6000:
                # Ghidra may inherit a callee's no-return annotation for a
                # tail BRA. Its encoded displacement still defines a jump;
                # inconsistent speculative metadata must not qualify a CFG.
                short = bool(opcode & 0xFF)
                length = 2 if short else 4
                if fact.length != length or len(fact.raw) != length:
                    return {}
                displacement = int.from_bytes(fact.raw[1:] if short else fact.raw[2:],
                                              "big", signed=True)
                target = (address + 2 + displacement) & 0xFFFFFF
                operand = re.fullmatch(r"0x[0-9a-f]+", fact.operands.strip(), re.I)
                if (target & 1 or operand is None or int(operand[0], 16) & 0xFFFFFF != target
                        or {point & 0xFFFFFF for point in fact.flows} != {target}):
                    return {}
                flow = "UNCONDITIONAL_JUMP"
            elif opcode & 0xFFC0 == 0x4EC0:
                flow = "UNCONDITIONAL_JUMP"
        following = address + fact.length
        targets = {target & 0xFFFFFF for target in fact.flows}
        edges = set()
        inline = (inline_traps or {}).get(address)
        if inline is not None and fact.mnemonic.upper() == "TRAP":
            # The already rooted vector handler proves how many argument
            # bytes this instruction consumes. They remain data, even in a
            # speculative CFG; a branch into them invalidates the hypothesis.
            if inline.data_address != following or inline.continuation > end:
                return {}
            argument_bytes = set(range(following, inline.continuation))
            if argument_bytes & occupied:
                return {}
            occupied.update(argument_bytes)
            if inline.continuation in known:
                exits.add(address)
            else:
                edges.add(inline.continuation)
        elif fact.mnemonic.upper() in {"RTS", "RTE", "RTR"}:
            exits.add(address)
        elif flow in {"UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP"}:
            if not targets:
                return {}
            for target in targets:
                if target in known:
                    exits.add(address)
                elif start <= target < end:
                    edges.add(target)
                else:
                    return {}
            if flow == "CONDITIONAL_JUMP":
                edges.add(following)
        elif flow in {"UNCONDITIONAL_CALL", "CONDITIONAL_CALL"}:
            if not targets or not targets <= known.keys():
                return {}
            edges.add(following)
        elif flow == "COMPUTED_CALL" and int.from_bytes(fact.raw[:2], "big") & 0xFFC0 == 0x4E80:
            edges.add(following)  # JSR still has an architectural return PC.
        elif flow == "FALL_THROUGH":
            edges.add(following)
        else:
            return {}
        if following in edges and following in known:
            edges.remove(following)
            exits.add(address)
        successors[address] = edges
        pending.extend(edges - body.keys())
    reverse = {address: set() for address in body}
    for address, edges in successors.items():
        for target in edges:
            reverse[target].add(address)
    can_exit = set(exits)
    pending.extend(exits)
    while pending:
        for predecessor in reverse[pending.popleft()] - can_exit:
            can_exit.add(predecessor)
            pending.append(predecessor)
    return body if can_exit == body.keys() else {}


def discover_packed_orphan_closure(
    image: MegaDriveImage, known: dict[int, InstructionFact],
    decoded: dict[int, InstructionFact], *,
    protected_ranges: tuple[tuple[int, int], ...] = (),
    render_instruction: Callable[[InstructionFact], str | None],
) -> tuple[OrphanCandidate, ...]:
    virtual = {fact.cpu_address: fact for fact in known.values()}
    decoded = {fact.cpu_address: fact for fact in decoded.values()}
    # Only candidate TRAP sites are speculative. Handler instructions come
    # from rooted code; a pseudo-decoded handler never proves an exception ABI.
    trap_sites = {a: f for a, f in decoded.items() if f.mnemonic.upper() == "TRAP"}
    inline_traps = {call.call_address: call for call in discover_inline_trap_calls(
        image, {**trap_sites, **virtual}) if call.handler in virtual}
    candidates = {}
    attempted = set()
    # Every successful round consumes bytes in a gap capped at 2048; this
    # additional bound limits work on pathological ROMs without dropping the
    # original candidates (which the ordinary decoder still receives).
    for _ in range(128):
        additions = {}
        byte_owners = {}
        inline_protected = tuple(
            (inline_traps[a].data_address, inline_traps[a].continuation)
            for a in virtual.keys() & inline_traps.keys())
        round_protected = protected_ranges + inline_protected

        def accept_body(body):
            # Independently valid hypotheses must agree on instruction
            # boundaries before they share a batch of backend roots.
            owners = {}
            for address, fact in body.items():
                for byte in range(address, address + fact.length):
                    owners[byte] = address
            for address in body.keys() & inline_traps.keys():
                inline = inline_traps[address]
                for byte in range(inline.data_address, inline.continuation):
                    if byte in owners:
                        return False
                    owners[byte] = ("inline_data", address)
            if any(byte in byte_owners and byte_owners[byte] != owner for byte, owner in owners.items()):
                return False
            byte_owners.update(owners)
            additions.update(body)
            return True

        data = tuple(sorted({ref.address & 0xFFFFFF
                             for fact in virtual.values() for ref in fact.references
                             if ref.reference_type.upper() in {"READ", "DATA"}}
                            | immediate_rom_addresses(virtual, image)))
        for candidate in _long_gap_prefixes(virtual, image):
            if candidate.address in attempted:
                continue
            body = _complete_cfg(image, candidate, virtual, decoded,
                                 round_protected, render_instruction, data, inline_traps)
            joins_known = any(f.cpu_address + f.length in virtual
                              and f.flow_type.upper() in {"FALL_THROUGH", "UNCONDITIONAL_CALL", "COMPUTED_CALL"}
                              for f in body.values())
            first = body.get(candidate.address)
            if (len(body) >= 4 and first and not first.mnemonic.upper().startswith("ORI.")
                    and (joins_known or any(set(f.flows) & virtual.keys() for f in body.values()))
                    and accept_body(body)):
                attempted.add(candidate.address)
                candidates[candidate.address] = candidate
        for candidate in _call_continuations(virtual, image):
            if candidate.address in attempted:
                continue
            body = _complete_cfg(image, candidate, virtual, decoded,
                                 round_protected, render_instruction, data, inline_traps)
            if len(body) >= 2 and accept_body(body):
                attempted.add(candidate.address)
                candidates[candidate.address] = candidate
        for candidate in discover_packed_orphan_candidates(image, virtual):
            if candidate.address in attempted or any(
                    left <= candidate.address < right for left, right in inline_protected):
                continue
            attempted.add(candidate.address)
            body = _complete_cfg(image, candidate, virtual, decoded,
                                 round_protected, render_instruction, data, inline_traps)
            if accept_body(body):
                candidates[candidate.address] = candidate
        # Exhaust adjacent roots before resynchronizing inside data gaps.
        # Otherwise an interior signature can cut a valid earlier function.
        if not additions:
            for candidate in _signature_entries(virtual, decoded, image):
                if candidate.address in attempted:
                    continue
                attempted.add(candidate.address)
                body = _complete_cfg(image, candidate, virtual, decoded,
                                     round_protected, render_instruction, data, inline_traps)
                calls_known = any((int.from_bytes(f.raw[:2], "big") & 0xFFC0 == 0x4E80
                                   or int.from_bytes(f.raw[:2], "big") & 0xFF00 == 0x6100)
                                  and set(f.flows) & virtual.keys() for f in body.values())
                if (len(body) >= 4 and calls_known and any(f.raw == b"\x4e\x75" for f in body.values())
                        and accept_body(body)):
                    candidates[candidate.address] = candidate
        if not additions:
            break
        virtual.update(additions)
    return tuple(candidates[address] for address in sorted(candidates))
