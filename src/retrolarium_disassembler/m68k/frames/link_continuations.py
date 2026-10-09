"""Continuations passed as a hand-made return address before a branch.

Runtime libraries without JSR save a link in a register: ``LEA d16(PC),An``
immediately followed by an unconditional ``BRA``/``JMP`` whose callee
resumes with ``JMP (An)``. When the PC-relative address is exactly the
instruction after that branch, it is the architectural continuation of a
call and therefore code. Without the callee's JMP through the same register
an adjacent address is commonly a data argument and is not accepted.
"""
from __future__ import annotations

from retrolarium_disasm.facts import InstructionFact
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disasm.m68k.instructions import pc_displacement_target
from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_disasm.m68k.abstract import _register_use


def discover_link_continuation_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[DecoderSeed, ...]:
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    seeds = []
    for link in by_address.values():
        opcode = int.from_bytes(link.raw[:2], "big")
        # LEA d16(PC),An = 0100 rrr1 1111 1010.
        if opcode & 0xF1FF != 0x41FA or len(link.raw) != 4:
            continue
        branch = by_address.get(link.cpu_address + link.length)
        if branch is None or branch.flow_type.upper() != "UNCONDITIONAL_JUMP":
            continue
        branch_opcode = int.from_bytes(branch.raw[:2], "big")
        if not (branch_opcode & 0xFF00 == 0x6000 or branch_opcode & 0xFFC0 == 0x4EC0):
            continue
        continuation = branch.cpu_address + branch.length
        if pc_displacement_target(link) != continuation or not branch.flows:
            continue
        # The callee must resume through the same register; an adjacent
        # literal passed to an ordinary routine is data.
        register = link.operands.upper().rsplit("|", 1)[-1]
        if _register_use(by_address, branch.flows[0] & 0xFFFFFF, register) != "code":
            continue
        seeds.append(DecoderSeed(
            continuation, "link_continuation", "proven",
            f"LEA d16(PC) at {link.cpu_address:06X} names the instruction after the "
            f"branch at {branch.cpu_address:06X}; the callee jumps through {register}",
            link.cpu_address,
        ))
    return tuple(seeds)
