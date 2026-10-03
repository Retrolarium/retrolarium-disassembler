"""Validate a speculative handler before using it to bound a dispatch table."""
from __future__ import annotations

from bisect import bisect_right
from typing import Callable

from .facts import InstructionFact
from .m68k_abstract import OrphanCandidate
from .m68k_packed import _complete_cfg
from .m68k_ram_dispatch import discover_inline_trap_calls
from .m68k_call_frame import make_trap_call_frame_validator
from .megadrive import MegaDriveImage
from .megadrive_pointers import _absolute_referenced_addresses


def make_dispatch_handler_validator(
    image: MegaDriveImage,
    known: dict[int, InstructionFact],
    decoded: dict[int, InstructionFact],
    *,
    protected_ranges: tuple[tuple[int, int], ...] = (),
    render_instruction: Callable[[InstructionFact], str | None],
) -> Callable[[int], bool]:
    """Return a cached predicate; this never promotes probe facts to code.

    A witness must have a complete bounded CFG, a return or known tail exit,
    and a direct connection to rooted code. Data reads, operand overlaps,
    missing decodes and unresolved transfers invalidate the hypothesis.
    """
    known = {f.cpu_address: f for f in known.values()}
    decoded = {f.cpu_address: f for f in decoded.values()}
    starts = sorted(known)
    data = tuple(sorted(_absolute_referenced_addresses(known)))
    # Only trap sites may come from speculative decoding. Every instruction
    # proving the exception handler's inline-argument ABI must be rooted.
    trap_sites = {a: f for a, f in decoded.items() if f.mnemonic.upper() == "TRAP"}
    preserves_frame = make_trap_call_frame_validator(known)
    inline_traps = {call.call_address: call for call in discover_inline_trap_calls(
        image, {**trap_sites, **known}) if call.handler in known and preserves_frame(call.handler)}
    protected_ranges = protected_ranges + tuple(
        (call.data_address, call.continuation)
        for address, call in inline_traps.items() if address in known)
    checked: dict[int, bool] = {}

    def validate(address: int) -> bool:
        if address in checked:
            return checked[address]
        index = bisect_right(starts, address)
        previous = known[starts[index - 1]] if index else None
        if (address & 1 or address < 0x200 or address in known
                or previous is not None and address < previous.cpu_address + previous.length):
            checked[address] = False
            return False
        end = min(address + 2048, len(image.data),
                  starts[index] if index < len(starts) else len(image.data))
        candidate = OrphanCandidate(address, address, end, end - address,
                                    "high", "complete bounded dispatch handler CFG")
        body = _complete_cfg(image, candidate, known, decoded, protected_ranges,
                             render_instruction, data, inline_traps)
        first = body.get(address)
        checked[address] = bool(
            len(body) >= 4 and first and not first.mnemonic.upper().startswith("ORI.")
            and len({f.mnemonic.upper().split(".", 1)[0] for f in body.values()}) >= 3
            and any(set(f.flows) & known.keys() for f in body.values())
            and not any(f.flow_type.upper() in {"COMPUTED_CALL", "COMPUTED_JUMP"}
                        or f.mnemonic.upper() in {"RTE", "RTR", "ILLEGAL", "STOP", "RESET"}
                        or f.mnemonic.upper() == "TRAP" and f.cpu_address not in inline_traps
                        for f in body.values()))
        return checked[address]

    return validate
