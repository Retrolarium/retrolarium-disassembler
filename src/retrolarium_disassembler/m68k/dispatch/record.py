"""Recover strided ROM records whose pointer field is executed via RTS.

Some engines schedule objects with MOVE.L field(An),-(SP); RTS rather than
JMP. A table is code evidence only when decoded code copies that same field,
with a proven unsigned byte index and record stride. No game addresses or
reference symbols participate in discovery.
"""
from __future__ import annotations

import re

from retrolarium_disassembler.facts import InstructionFact
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disassembler.m68k.instructions import absolute_referenced_addresses, instruction_sets
from retrolarium_disassembler.m68k.instructions import pc_displacement_target


_FIELD = r"\((-?0x[0-9a-f]+),(A[0-6])\)"
_PUSH = re.compile(_FIELD + r"\|-\(SP\)", re.I)
_COPY = re.compile(
    r"\((-?0x[0-9a-f]+),(A[0-6]),(D[0-7])w\*0x1\)\|" + _FIELD, re.I)


def executed_stack_fields(facts: dict[int, InstructionFact]) -> dict[int, int]:
    """Field displacement -> instruction that pushes its value before RTS."""
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    fields = {}
    for push in facts.values():
        match = _PUSH.fullmatch(push.operands)
        following = by_address.get(push.cpu_address + push.length)
        if (push.mnemonic.upper() == "MOVE.L" and match is not None
                and following is not None and following.mnemonic.upper() == "RTS"
                and following.raw == b"\x4e\x75"):
            fields[int(match[1], 0)] = push.cpu_address
    return fields


def discover_record_callback_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
) -> tuple[DecoderSeed, ...]:
    fields = executed_stack_fields(facts)
    if not fields:
        return ()
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    occupied, interiors, starts = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    data, origin = image.data, image.header.rom_start
    seeds = {}
    for read in facts.values():
        match = _COPY.fullmatch(read.operands)
        if read.mnemonic.upper() != "MOVE.L" or match is None:
            continue
        displacement, base, index, field, destination = match.groups()
        base, index = base.upper(), index.upper()
        if int(field, 0) not in fields:
            continue
        scale = ends.get(read.cpu_address)
        # LEA base; CLR.W Dn; MOVE.B ...,Dn; LSL.W #k,Dn; field copy.
        count = re.fullmatch(r"#0x([1-4])\|" + index + "w", scale.operands, re.I) if scale else None
        if scale is None or scale.mnemonic.upper() != "LSL.W" or count is None:
            continue
        stride = 1 << int(count[1], 16)
        byte = ends.get(scale.cpu_address)
        zero = ends.get(byte.cpu_address) if byte else None
        lea = ends.get(zero.cpu_address) if zero else None
        if (byte is None or byte.mnemonic.upper() != "MOVE.B"
                or not byte.operands.upper().endswith(f"|{index}B")
                or zero is None or zero.mnemonic.upper() != "CLR.W"
                or zero.operands.upper() != f"{index}W"
                or lea is None or lea.mnemonic.upper() != "LEA"
                or lea.operands.rsplit("|", 1)[-1].upper() != base
                or any(f.flow_type.upper() != "FALL_THROUGH" for f in (lea, zero, byte, scale, read))):
            continue
        table = pc_displacement_target(lea)
        absolute = re.fullmatch(r"\((0x[0-9a-f]+)\)\.l\|" + base, lea.operands, re.I)
        if table is None and absolute:
            table = int(absolute[1], 0)
        offset = int(displacement, 0)
        if table is None or not 0 <= offset <= stride - 4:
            continue
        start = table - origin
        targets = []
        for entry in range(256):
            at = start + entry * stride
            if (at < 0x200 or at & 1 or at + stride > len(data)
                    or any(at + b in occupied for b in range(stride))
                    or entry and any(origin + at + b in boundaries for b in range(stride))):
                break
            record = data[at:at + stride]
            target = int.from_bytes(record[offset:offset + 4], "big")
            if target == 0 and not any(record):
                continue  # Explicit empty records preserve the index/stride.
            physical = target - origin
            if (target & 1 or not 0x200 <= physical <= len(data) - 2
                    or physical in interiors or start <= physical < at + stride
                    or data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                break
            targets.append(target)
        # Require corroboration from an existing instruction boundary. This
        # avoids inventing a code table from a coincidental record-shaped asset.
        if len(set(targets)) < 3 or not (set(targets) & starts):
            continue
        evidence = (f"unsigned byte index times {stride}; record table {table:06X}, "
                    f"pointer field +{offset}; object field +{int(field, 0)} "
                    f"executed by stack push/RTS at {fields[int(field, 0)]:06X}")
        for target in targets:
            seeds[target] = DecoderSeed(target, "record_stack_callback", "high", evidence, read.cpu_address)
    return tuple(seeds[address] for address in sorted(seeds))
