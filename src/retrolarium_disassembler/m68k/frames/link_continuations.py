"""Continuations passed as a hand-made return address before a branch.

Runtime libraries without JSR save a link in a register or on the stack:
``LEA d16(PC),An`` or ``PEA d16(PC)`` immediately followed by an
unconditional ``BRA``/``JMP``. The callee resumes with ``JMP (An)`` or
``RTS``. When the PC-relative address is exactly the instruction after that
branch, it is the architectural continuation of a call and therefore code.
A non-adjacent address is commonly a data argument and is not accepted.
"""
from __future__ import annotations

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .megadrive_symbols import pc_displacement_target
from .m68k_seeds import DecoderSeed


def discover_link_continuation_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[DecoderSeed, ...]:
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    seeds = []
    for link in by_address.values():
        opcode = int.from_bytes(link.raw[:2], "big")
        # LEA d16(PC),An = 0100 rrr1 1111 1010; PEA d16(PC) = 0x487A.
        if not (opcode & 0xF1FF == 0x41FA or opcode == 0x487A) or len(link.raw) != 4:
            continue
        branch = by_address.get(link.cpu_address + link.length)
        if branch is None or branch.flow_type.upper() != "UNCONDITIONAL_JUMP":
            continue
        branch_opcode = int.from_bytes(branch.raw[:2], "big")
        if not (branch_opcode & 0xFF00 == 0x6000 or branch_opcode & 0xFFC0 == 0x4EC0):
            continue
        continuation = branch.cpu_address + branch.length
        if pc_displacement_target(link) != continuation:
            continue
        seeds.append(DecoderSeed(
            continuation, "link_continuation", "proven",
            f"{'LEA' if opcode != 0x487A else 'PEA'} d16(PC) at {link.cpu_address:06X} "
            f"names the instruction after the branch at {branch.cpu_address:06X}",
            link.cpu_address,
        ))
    return tuple(seeds)
