"""Conservative recovery of Mega Drive 68000-to-Z80 program copies."""

from __future__ import annotations

from retrolarium_disassembler import AnalysisError

from dataclasses import dataclass, replace
import hashlib
import re

from retrolarium_disassembler.facts import InstructionFact
from retrolarium_core.megadrive import MegaDriveImage, m68k_to_rom_offset


Z80_WINDOW_START = 0xA00000
Z80_WINDOW_END = 0xA01FFF


@dataclass(frozen=True)
class CrossCpuCopy:
    edge_id: str
    schema_id: str
    source_cpu_id: str
    source_space: str
    source_start: int
    source_end: int
    target_cpu_id: str
    target_space: str
    target_start: int
    target_end: int
    size: int
    payload_sha256: str
    evidence_addresses: tuple[int, ...]
    confidence: str


def _destination_register(fact: InstructionFact) -> str | None:
    operands = fact.operands.split("|")
    if len(operands) != 2:
        return None
    register = operands[1].strip().upper()
    return register if re.fullmatch(r"[AD][0-7](?:[BWL])?", register) else None


def _absolute_address(operand: str) -> int | None:
    match = re.search(r"\(0x([0-9a-f]+)\)(?:\.l)?", operand, re.I)
    return int(match.group(1), 16) if match else None


def _register_constant(fact: InstructionFact, register: str) -> int | None:
    operands = fact.operands.split("|")
    if len(operands) != 2 or operands[1].upper().rstrip("BWL") != register:
        return None
    if fact.mnemonic not in {"MOVE.W", "MOVE.L", "MOVEQ"}:
        return None
    value = operands[0].removeprefix("#")
    return int(value, 0) if re.fullmatch(r"-?(?:0x[0-9a-f]+|\d+)", value, re.I) else None


def _source_address(image: MegaDriveImage, fact: InstructionFact) -> int | None:
    for reference in fact.references:
        if reference.operand_index != 0 or "DATA" not in reference.reference_type:
            continue
        if image.header.rom_start <= reference.address <= image.actual_rom_end:
            return reference.address
    operands = fact.operands.split("|")
    if not operands:
        return None
    address = _absolute_address(operands[0])
    if address is None or not image.header.rom_start <= address <= image.actual_rom_end:
        return None
    return address


def _writes_register(fact: InstructionFact, register: str) -> bool:
    destination = _destination_register(fact)
    return destination is not None and destination.rstrip("BWL") == register


def _changes_address_register(fact: InstructionFact, register: str) -> bool:
    """Whether the instruction may leave another address in `register`: a
    write, an auto-increment or decrement, or a call (which may do either)."""
    if _writes_register(fact, register):
        return True
    if fact.mnemonic in {"JSR", "BSR", "BSR.S", "BSR.W", "TRAP"} or fact.mnemonic.startswith("BSR"):
        return True
    operands = fact.operands.upper()
    return f"({register})+" in operands or f"-({register})" in operands


def _nearest_write(prior: list[InstructionFact], register: str) -> InstructionFact | None:
    return next((fact for fact in reversed(prior) if _writes_register(fact, register)), None)


Z80_IM1_VECTOR = 0x38


def z80_im1_handler_seed(facts: dict[int, InstructionFact], base_address: int, size: int) -> int | None:
    """Return the IM1 vector when decoded code executes both IM 1 and EI."""
    raws = {fact.raw for fact in facts.values()}
    if b"\xed\x56" not in raws or b"\xfb" not in raws:
        return None
    if not base_address <= Z80_IM1_VECTOR < base_address + size:
        return None
    return Z80_IM1_VECTOR


def _subroutine_copy_routines(ordered: list[InstructionFact]) -> set[int]:
    """Find calls that copy A0 bytes into Z80 RAM using D0/D1 parameters."""
    routines: set[int] = set()
    for entry in ordered:
        if not (entry.mnemonic.startswith("MOVEM") and entry.operands.endswith("|-(SP)")):
            continue
        window = [fact for fact in ordered if entry.cpu_address < fact.cpu_address < entry.cpu_address + 0x40]
        bus = next(
            (fact for fact in window if fact.mnemonic == "LEA" and fact.operands.upper() == "(0XA00000).L|A1"), None
        )
        if bus is None:
            continue
        if not any(fact.mnemonic == "ADDA.W" and fact.operands.upper() == "D1W|A1" for fact in window):
            continue
        source = next(
            (fact for fact in window if fact.mnemonic == "MOVE.B" and fact.operands.upper() == "(A0)+|D1B"), None
        )
        if source is None:
            continue
        if not any(fact.mnemonic == "MOVE.B" and fact.operands.upper() == "D1B|(A1)" for fact in window):
            continue
        if not any(fact.mnemonic == "ADDQ.W" and fact.operands.upper() == "0X1|A1" for fact in window):
            continue
        if not any(
            fact.mnemonic == "DBF" and fact.operands.upper().startswith("D0W|") and source.cpu_address in fact.flows
            for fact in window
        ):
            continue
        routines.add(entry.cpu_address)
    return routines


def _detect_subroutine_copies(
    image: MegaDriveImage, ordered: list[InstructionFact], seen: set[tuple[int, int, int]]
) -> list[CrossCpuCopy]:
    routines = _subroutine_copy_routines(ordered)
    copies: list[CrossCpuCopy] = []
    for index, call in enumerate(ordered):
        if not call.mnemonic.startswith("BSR") or not routines.intersection(call.flows):
            continue
        prior = [fact for fact in ordered[max(0, index - 8) : index] if call.cpu_address - 0x20 <= fact.cpu_address]
        # The nearest write to each parameter register reaches the call; the
        # order in which the caller sets them up is irrelevant.
        count = _nearest_write(prior, "D0")
        destination = _nearest_write(prior, "D1")
        source = _nearest_write(prior, "A0")
        if count is None or destination is None or source is None:
            continue
        if source.mnemonic != "LEA":
            continue
        count_value = _register_constant(count, "D0")
        destination_value = _register_constant(destination, "D1")
        source_start = _source_address(image, source)
        if count_value is None or destination_value is None or source_start is None:
            continue
        size = (count_value & 0xFFFF) + 1
        destination_value &= 0xFFFF
        # Short copies to the sound command area are data transfers; only
        # program-sized images that fit Z80 RAM are extracted.
        if not 0x20 <= size <= 0x2000 or destination_value + size > 0x2000:
            continue
        source_end = source_start + size - 1
        if source_end > image.actual_rom_end:
            continue
        key = (source_start, Z80_WINDOW_START + destination_value, size)
        if key in seen:
            continue
        seen.add(key)
        payload_offset = m68k_to_rom_offset(image, source_start)
        payload = image.data[payload_offset : payload_offset + size]
        copies.append(
            CrossCpuCopy(
                edge_id=f"megadrive.cross.m68k-z80.{source_start:06X}.{destination_value:04X}",
                schema_id="megadrive.m68k-z80.subroutine-copy",
                source_cpu_id="m68k",
                source_space="m68k",
                source_start=source_start,
                source_end=source_end,
                target_cpu_id="z80",
                target_space="z80",
                target_start=destination_value,
                target_end=destination_value + size - 1,
                size=size,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                evidence_addresses=(
                    count.cpu_address,
                    destination.cpu_address,
                    source.cpu_address,
                    call.cpu_address,
                    *call.flows,
                ),
                confidence="proven-static-copy",
            )
        )
    return copies


def _end_minus_source_count(
    image: MegaDriveImage,
    ordered: list[InstructionFact],
    index: int,
    count_register: str,
    source_register: str,
    source_start: int | None,
) -> int | None:
    """DBF count computed as end - source - 1 from two LEA'd addresses.

    Matches MOVE.L Ay,Dn / SUB.L Ax,Dn / SUBQ #1,Dn, where Ax is the copy
    source and Ay was loaded with the payload's end address, as compiled
    `for (n = end - src; n--; ) *dst++ = *src++;` loops do.
    """
    if source_start is None or index < 2:
        return None
    subq, sub, move = ordered[index], ordered[index - 1], ordered[index - 2]
    register = count_register.upper()
    if not (
        subq.mnemonic.upper() in {"SUBQ.W", "SUBQ.L"}
        and re.fullmatch(r"(?:#)?(?:0x)?1\|" + register + r"W?", subq.operands, re.I)
    ):
        return None
    sub_match = re.fullmatch(r"(A[0-7])\|" + register, sub.operands, re.I)
    if sub.mnemonic.upper() != "SUB.L" or sub_match is None or sub_match.group(1).upper() != source_register.upper():
        return None
    move_match = re.fullmatch(r"(A[0-7])\|" + register, move.operands, re.I)
    if move.mnemonic.upper() != "MOVE.L" or move_match is None:
        return None
    end_register = move_match.group(1).upper()
    for previous in reversed(ordered[max(0, index - 8) : index - 2]):
        if _destination_register(previous) == end_register:
            if previous.mnemonic != "LEA":
                return None
            end = _source_address(image, previous)
            if end is None or end <= source_start:
                return None
            return end - source_start - 1
    return None


def detect_z80_copies(image: MegaDriveImage, facts: dict[int, InstructionFact]) -> tuple[CrossCpuCopy, ...]:
    """Find statically proven LEA/DBF byte-copy loops into the Z80 RAM window."""
    ordered = sorted(facts.values(), key=lambda fact: fact.cpu_address)
    copies: list[CrossCpuCopy] = []
    seen: set[tuple[int, int, int]] = set()
    for index, copy in enumerate(ordered):
        match = re.fullmatch(r"\(A([0-7])\)\+\|\(A([0-7])\)\+", copy.operands, re.I)
        if copy.mnemonic != "MOVE.B" or match is None:
            continue
        source_register = f"A{match.group(1)}"
        target_register = f"A{match.group(2)}"
        if source_register == target_register:
            continue

        loop = None
        for following in ordered[index + 1 : index + 4]:
            operands = following.operands.split("|")
            if (
                following.mnemonic == "DBF"
                and len(operands) == 2
                and re.fullmatch(r"D[0-7]W?", operands[0].strip().upper())
                and copy.cpu_address in following.flows
            ):
                loop = following
                break
        if loop is None:
            continue
        count_register = loop.operands.split("|")[0].strip().upper().rstrip("W")

        source_fact = None
        target_fact = None
        count_fact = None
        # The nearest change of each address register must be its LEA: a
        # later MOVEA, an (An)+ or a call in between leaves another address.
        source_open = target_open = True
        for previous in reversed(ordered[max(0, index - 10) : index]):
            destination = _destination_register(previous)
            if source_open and _changes_address_register(previous, source_register):
                source_open = False
                if (
                    previous.mnemonic == "LEA"
                    and destination == source_register
                    and _source_address(image, previous) is not None
                ):
                    source_fact = previous
            if target_open and _changes_address_register(previous, target_register):
                target_open = False
                if (
                    previous.mnemonic == "LEA"
                    and destination == target_register
                    and _absolute_address(previous.operands.split("|")[0]) is not None
                ):
                    target_fact = previous
            # Only the nearest write to the DBF counter register counts;
            # intervening hardware writes such as bus requests are ignored.
            if count_fact is None and _writes_register(previous, count_register):
                count_fact = previous
            if source_fact and target_fact and count_fact:
                break
        if source_fact is None or target_fact is None or count_fact is None:
            continue

        count_value = _register_constant(count_fact, count_register)
        if count_value is None:
            count_value = _end_minus_source_count(
                image,
                ordered,
                ordered.index(count_fact),
                count_register,
                source_register,
                _source_address(image, source_fact),
            )
        if count_value is None:
            continue
        size = (count_value & 0xFFFF) + 1
        if not 1 <= size <= 0x2000:
            continue

        source_start = _source_address(image, source_fact)
        target_start = _absolute_address(target_fact.operands.split("|")[0])
        assert source_start is not None and target_start is not None
        source_end = source_start + size - 1
        target_end = target_start + size - 1
        if source_end > image.actual_rom_end:
            continue
        if not Z80_WINDOW_START <= target_start <= target_end <= Z80_WINDOW_END:
            continue
        key = (source_start, target_start, size)
        if key in seen:
            continue
        seen.add(key)
        payload_offset = m68k_to_rom_offset(image, source_start)
        payload = image.data[payload_offset : payload_offset + size]
        z80_start = target_start - Z80_WINDOW_START
        copies.append(
            CrossCpuCopy(
                edge_id=(f"megadrive.cross.m68k-z80.{source_start:06X}.{z80_start:04X}"),
                schema_id="megadrive.m68k-z80.dbf-postincrement-copy",
                source_cpu_id="m68k",
                source_space="m68k",
                source_start=source_start,
                source_end=source_end,
                target_cpu_id="z80",
                target_space="z80",
                target_start=z80_start,
                target_end=z80_start + size - 1,
                size=size,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                evidence_addresses=(
                    source_fact.cpu_address,
                    target_fact.cpu_address,
                    count_fact.cpu_address,
                    copy.cpu_address,
                    loop.cpu_address,
                ),
                confidence="proven-static-copy",
            )
        )
    copies.extend(_detect_subroutine_copies(image, ordered, seen))
    return tuple(sorted(copies, key=lambda copy: (copy.source_start, copy.target_start)))


@dataclass(frozen=True)
class Z80LogicalImage:
    """Copies that tile one contiguous Z80 RAM range, analyzed as one program."""

    fragments: tuple[CrossCpuCopy, ...]

    @property
    def target_start(self) -> int:
        return self.fragments[0].target_start

    @property
    def target_end(self) -> int:
        return self.fragments[-1].target_end

    @property
    def size(self) -> int:
        return self.target_end - self.target_start + 1

    def payload(self, image: MegaDriveImage) -> bytes:
        return b"".join(copy_payload(image, fragment) for fragment in self.fragments)


def copy_payload(image: MegaDriveImage, copy: CrossCpuCopy) -> bytes:
    offset = m68k_to_rom_offset(image, copy.source_start)
    payload = image.data[offset : offset + copy.size]
    if hashlib.sha256(payload).hexdigest() != copy.payload_sha256:
        raise AnalysisError(f"Z80 copy payload changed: {copy.edge_id}")
    return payload


def group_z80_copies(copies: tuple[CrossCpuCopy, ...]) -> tuple[Z80LogicalImage, ...]:
    """Join copies whose Z80 destinations are exactly adjacent.

    Only gap-free chains are joined, so no uncovered RAM byte is ever part of
    an analysis input. Any copy whose destination overlaps another copy may
    describe a conflicting upload and stays a standalone program.
    """
    ordered = sorted(copies, key=lambda copy: (copy.target_start, copy.target_end, copy.source_start))
    overlapping: set[int] = set()
    for index, first in enumerate(ordered):
        for other_index in range(index + 1, len(ordered)):
            if ordered[other_index].target_start > first.target_end:
                break
            overlapping.update((index, other_index))
    images: list[Z80LogicalImage] = []
    run: list[CrossCpuCopy] = []
    for index, copy in enumerate(ordered):
        if index in overlapping:
            if run:
                images.append(Z80LogicalImage(tuple(run)))
                run = []
            images.append(Z80LogicalImage((copy,)))
        elif run and copy.target_start == run[-1].target_end + 1:
            run.append(copy)
        else:
            if run:
                images.append(Z80LogicalImage(tuple(run)))
            run = [copy]
    if run:
        images.append(Z80LogicalImage(tuple(run)))
    return tuple(
        sorted(
            images,
            key=lambda item: (item.fragments[0].source_start, item.fragments[0].target_start),
        )
    )


def fragment_z80_facts(
    logical: Z80LogicalImage,
    facts: dict[int, InstructionFact],
    fragment: CrossCpuCopy,
) -> dict[int, InstructionFact]:
    """Rebase logical-image facts onto one fragment's payload offsets.

    Instructions straddling a fragment boundary cannot be emitted inside
    either fragment, so their bytes are left as data.
    """
    start = fragment.target_start - logical.target_start
    end = start + fragment.size
    return {
        offset - start: replace(fact, physical_offset=fact.physical_offset - start)
        for offset, fact in facts.items()
        if start <= offset and offset + fact.length <= end
    }
