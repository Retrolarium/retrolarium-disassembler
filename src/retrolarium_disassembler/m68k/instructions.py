"""What a decoded 68000 instruction says about the bytes around it.

The address sets a pass needs to avoid splitting instructions, the absolute
addresses an instruction's operands name, and PC-relative operands decoded
from the instruction bytes and checked against Ghidra's text. The Mega Drive
pipeline and every 68000 pass share these; nothing here knows the console.
"""

from __future__ import annotations

import re

from retrolarium_disassembler.facts import InstructionFact


def instruction_sets(
    facts: dict[int, InstructionFact],
) -> tuple[set[int], set[int], set[int]]:
    occupied: set[int] = set()
    interiors: set[int] = set()
    starts: set[int] = set()
    for fact in facts.values():
        starts.add(fact.cpu_address)
        occupied.update(range(fact.physical_offset, fact.physical_offset + fact.length))
        interiors.update(range(fact.physical_offset + 1, fact.physical_offset + fact.length))
    return occupied, interiors, starts


_PC_INDEXED_OPERAND = re.compile(r"\((-?0x[0-9a-f]+|-?\d+),PC,[DA][0-7][wl]?\*0x[1248]\)$", re.I)


_ADDRESS_REGISTER = re.compile(r"\b(?:A[0-7]|SP)\b", re.I)


def absolute_referenced_addresses(
    facts: dict[int, InstructionFact],
) -> set[int]:
    """Return data references that name an absolute address.

    Struct displacements, literal immediates, and backend-inferred effective
    addresses of ``(An)`` accesses do not identify a separate ROM object.
    Inspect each referenced operand, so an absolute destination still
    qualifies when the source is indirect or an immediate scalar.
    """
    addresses: set[int] = set()
    for fact in facts.values():
        operands = fact.operands.split("|")
        for reference in fact.references:
            if not ("DATA" in reference.reference_type or "READ" in reference.reference_type):
                continue
            operand = (
                operands[reference.operand_index] if 0 <= reference.operand_index < len(operands) else fact.operands
            )
            if operand.startswith("#"):
                # A DATA annotation on #size/#flags does not mean the value
                # addresses ROM. Dispatch bases are proven separately from
                # the indexed reader; literal constants alone cannot cut it.
                continue
            indexed = _PC_INDEXED_OPERAND.fullmatch(operand)
            if indexed is not None and int(indexed[1], 0) != reference.address:
                # Only the base of (d8,PC,Xn) is explicit. Ghidra adds element
                # addresses from inferred index values; they are not objects.
                continue
            if re.fullmatch(r"(?:[DA][0-7][bwl]?|SP|SR|CCR|USP)", operand, re.I):
                # Ghidra can attach a DATA reference to a register's inferred
                # scalar value. It is not an explicit address and must not
                # split a table which happens to contain the same number.
                continue
            if "(" in operand and _ADDRESS_REGISTER.search(operand) and "PC" not in operand.upper():
                continue
            addresses.add(reference.address)
    return addresses


def pc_indexed_target(fact: InstructionFact) -> tuple[int, int, str, str] | None:
    """Decode and validate a 68000 brief indexed PC-relative operand."""
    if len(fact.raw) < 4:
        return None
    source = fact.operands.split("|", 1)[0]
    operand = re.fullmatch(r"\(0x([0-9a-f]+),PC,([DA])([0-7])([wl]?)\*0x1\)", source, re.I)
    if operand is None:
        return None
    extension = int.from_bytes(fact.raw[2:4], "big")
    if extension & 0x0700:  # Scale/full-extension bits require a 68020+.
        return None
    kind = "A" if extension & 0x8000 else "D"
    register = (extension >> 12) & 7
    size = "l" if extension & 0x0800 else "w"
    displacement = int.from_bytes(fact.raw[3:4], "big", signed=True)
    target = (fact.cpu_address + 2 + displacement) & 0xFFFFFF
    if (
        int(operand.group(1), 16) != target
        or operand.group(2).upper() != kind
        or int(operand.group(3)) != register
        or (operand.group(4).lower() or "l") != size
    ):
        return None
    return target, register, kind.lower(), size


def pc_displacement_target(fact: InstructionFact) -> int | None:
    """Decode and validate a 68000 d16(PC) source operand."""
    extension_offset = 4 if fact.mnemonic.upper().startswith("MOVEM.") else 2
    if len(fact.raw) < extension_offset + 2:
        return None
    source = fact.operands.split("|", 1)[0]
    operand = re.fullmatch(r"\((-?0x[0-9a-f]+),PC\)", source, re.I)
    if operand is None:
        return None
    displacement = int.from_bytes(fact.raw[extension_offset : extension_offset + 2], "big", signed=True)
    if displacement != int(operand.group(1), 0):
        return None
    return (fact.cpu_address + extension_offset + displacement) & 0xFFFFFF


def pc_indexed_jsr_target(fact: InstructionFact) -> tuple[int, int] | None:
    """Decode a 68000 JSR (d8,PC,Dn.W) and validate Ghidra's target."""
    indexed = pc_indexed_target(fact)
    if (
        fact.mnemonic.upper() != "JSR"
        or fact.flow_type != "COMPUTED_CALL"
        or fact.raw[:2] != b"\x4e\xbb"
        or indexed is None
    ):
        return None
    target, register, kind, size = indexed
    if kind != "d" or size != "w":
        return None
    return target, register
