"""Validate a speculative handler before using it to bound a dispatch table."""
from __future__ import annotations

from bisect import bisect_right
from typing import Callable

from retrolarium_disasm.facts import InstructionFact
from retrolarium_disasm.m68k.abstract import OrphanCandidate
from retrolarium_disasm.m68k.records.packed import _complete_cfg
from retrolarium_disasm.m68k.dispatch.ram import discover_inline_trap_calls
from retrolarium_disasm.m68k.frames.call_frame import make_trap_call_frame_validator
from retrolarium_disasm.m68k.dispatch.closure import logical_image, make_dispatch_closure_validator
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disasm.m68k.instructions import absolute_referenced_addresses


def make_dispatch_handler_validator(
    image: MegaDriveImage,
    known: dict[int, InstructionFact],
    decoded: dict[int, InstructionFact],
    *,
    protected_ranges: tuple[tuple[int, int], ...] = (),
    render_instruction: Callable[[InstructionFact], str | None],
    decode_request: Callable[[int, int, str], None] | None = None,
) -> Callable[[int], bool]:
    """Return a cached predicate; this never promotes probe facts to code.

    A witness needs a complete bounded CFG and a connection to rooted code,
    or a substantial closed leaf with multiple RTS exits and a genuine branch.
    The latter is a high-confidence code heuristic for structural dispatch
    consumers, not proof of reachable table indices. Data reads, overlaps,
    missing decodes and unresolved transfers invalidate either hypothesis.
    """
    known = {f.cpu_address: f for f in known.values()}
    decoded = {f.cpu_address: f for f in decoded.values()}
    starts = sorted(known)
    origin, rom_end = image.header.rom_start, image.header.rom_start + len(image.data)
    byte_image = logical_image(image)
    data = tuple(sorted(absolute_referenced_addresses(known)))
    # Only trap sites may come from speculative decoding. Every instruction
    # proving the exception handler's inline-argument ABI must be rooted.
    trap_sites = {a: f for a, f in decoded.items() if f.mnemonic.upper() == "TRAP"}
    preserves_frame = make_trap_call_frame_validator(known)
    inline_traps = {call.call_address: call for call in discover_inline_trap_calls(
        image, {**trap_sites, **known}) if call.handler in known and preserves_frame(call.handler)}
    protected_ranges = tuple((origin + start, origin + end) for start, end in protected_ranges) + tuple(
        (call.data_address, call.continuation)
        for address, call in inline_traps.items() if address in known)
    checked: dict[int, bool] = {}
    closure_validator = None
    closed_leaf_validator = None

    def validate(address: int) -> bool:
        nonlocal closure_validator, closed_leaf_validator
        if address in checked:
            return checked[address]
        index = bisect_right(starts, address)
        previous = known[starts[index - 1]] if index else None
        if (address & 1 or not origin + 0x200 <= address < rom_end or address in known
                or previous is not None and address < previous.cpu_address + previous.length):
            checked[address] = False
            return False
        end = min(address + 2048, rom_end,
                  starts[index] if index < len(starts) else rom_end)
        candidate = OrphanCandidate(address, address, end, end - address,
                                    "high", "complete bounded dispatch handler CFG")
        body = _complete_cfg(byte_image, candidate, known, decoded, protected_ranges,
                             render_instruction, data, inline_traps, decode_request=decode_request)
        first = body.get(address)
        checked[address] = bool(
            len(body) >= 4 and first and not first.mnemonic.upper().startswith("ORI.")
            and len({f.mnemonic.upper().split(".", 1)[0] for f in body.values()}) >= 3
            and any(set(f.flows) & known.keys() for f in body.values())
            and not any(f.flow_type.upper() in {"COMPUTED_CALL", "COMPUTED_JUMP"}
                        or f.mnemonic.upper() in {"RTE", "RTR", "ILLEGAL", "STOP", "RESET"}
                        or f.mnemonic.upper() == "TRAP" and f.cpu_address not in inline_traps
                        for f in body.values()))
        if closure_validator is None:
            closure_validator = make_dispatch_closure_validator(
                image, known, decoded, protected_ranges=protected_ranges,
                render_instruction=render_instruction, decode_request=decode_request,
                inline_traps=inline_traps)
        if checked[address]:
            checked[address] = not closure_validator.has_conflict(body)
        else:
            checked[address] = closure_validator(address)
        # Keep the existing witness and its conflict rules first. The optional
        # leaf criterion must not affect other closure users or reject handlers
        # that already passed the established rooted-code witness.
        if not checked[address]:
            if closed_leaf_validator is None:
                closed_leaf_validator = make_dispatch_closure_validator(
                    image, known, decoded, protected_ranges=protected_ranges,
                    render_instruction=render_instruction, decode_request=decode_request,
                    inline_traps=inline_traps, allow_closed_leaves=True)
            checked[address] = closed_leaf_validator(address)
        return checked[address]

    return validate
