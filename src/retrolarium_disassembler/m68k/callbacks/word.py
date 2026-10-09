"""Word callback slots and leaf resolvers returning a ROM function address.

Discovery requires decoded executable readers. ROM values and instructions
provide all evidence; reference symbols, game identities and addresses are
never used.
"""
from __future__ import annotations

import re

from retrolarium_disasm.facts import InstructionFact
from retrolarium_disasm.m68k.seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disasm.m68k.instructions import absolute_referenced_addresses, instruction_sets
from retrolarium_disasm.m68k.instructions import pc_displacement_target


ABS = re.compile(r"\((-?0x[0-9a-f]+)\)\.[wl]", re.I)


def _zero(fact, register):
    return (fact.mnemonic.upper() == "MOVEQ"
            and re.fullmatch(r"#?0x0\|" + register, fact.operands, re.I) is not None)


def _ram_word(operand, image):
    match = ABS.fullmatch(operand)
    if match is None:
        return None
    address = int(match[1], 0) & 0xFFFFFF
    return address if image.header.ram_start <= address <= image.header.ram_end - 1 else None


def _target(image, value, interiors):
    physical = value - image.header.rom_start
    return (not value & 1 and 0x200 <= physical <= len(image.data) - 2
            and physical not in interiors
            and image.data[physical:physical + 2] not in {b"\0\0", b"\xff\xff"})


def discover_word_ram_callback_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact], *,
    execution_facts: dict[int, InstructionFact] | None = None,
) -> tuple[DecoderSeed, ...]:
    """Prove MOVEQ 0 / RAM word / MOVEA.L / indirect call, then its writers.

    A partial access, data read or unverified writer disqualifies the slot.
    As with existing absolute RAM callback proofs, computed RAM aliases are
    outside the static operand model.
    """
    execution = facts if execution_facts is None else execution_facts
    by_address = {f.cpu_address: f for f in execution.values()}
    ends = {f.cpu_address + f.length: f for f in execution.values()}
    slots = {}
    for load in execution.values():
        operands = load.operands.split("|")
        if load.mnemonic.upper() != "MOVE.W" or len(operands) != 2:
            continue
        match = re.fullmatch(r"(D[0-7])w", operands[1], re.I)
        slot = _ram_word(operands[0], image)
        if match is None or slot is None:
            continue
        dr = match[1].upper()
        zero = ends.get(load.cpu_address)
        convert = by_address.get(load.cpu_address + load.length)
        ar = re.fullmatch(dr + r"\|(A[0-6])", convert.operands, re.I) if convert else None
        call = by_address.get(convert.cpu_address + convert.length) if convert else None
        if (zero is None or not _zero(zero, dr)
                or convert is None or convert.mnemonic.upper() != "MOVEA.L" or ar is None
                or call is None or call.mnemonic.upper() not in {"JMP", "JSR"}
                or call.operands.upper() != f"({ar[1].upper()})"):
            continue
        slots.setdefault(slot, {})[load.cpu_address] = call.cpu_address
    if not slots:
        return ()
    _, interiors, _ = instruction_sets(facts)
    writers = {slot: [] for slot in slots}
    rejected = set()
    for fact in facts.values():
        operands = fact.operands.split("|")
        size = {"B": 1, "W": 2, "L": 4}.get(fact.mnemonic.upper().rsplit(".", 1)[-1], 4)
        if fact.mnemonic.upper().startswith("MOVEM"):
            size = 64
        for index, operand in enumerate(operands):
            absolute = ABS.fullmatch(operand)
            if absolute is None:
                continue
            address = int(absolute[1], 0) & 0xFFFFFF
            for slot in slots:
                if address >= slot + 2 or address + size <= slot or slot in rejected:
                    continue
                if address != slot or size != 2:
                    rejected.add(slot)
                elif fact.cpu_address in slots[slot]:
                    continue
                elif fact.mnemonic.upper().startswith(("TST.", "CMP")):
                    continue
                elif fact.mnemonic.upper() == "CLR.W" and index == len(operands) - 1:
                    continue
                elif fact.mnemonic.upper() == "MOVE.W" and index == 1:
                    immediate = re.fullmatch(r"#(-?0x[0-9a-f]+)", operands[0], re.I)
                    target = int(immediate[1], 0) & 0xFFFF if immediate else None
                    if target == 0:
                        continue
                    if target is None or not _target(image, target, interiors):
                        rejected.add(slot)
                    else:
                        writers[slot].append((fact, target))
                else:
                    rejected.add(slot)
    result = {}
    for slot, entries in writers.items():
        if slot in rejected:
            continue
        for writer, target in entries:
            result[target] = DecoderSeed(target, "word_ram_callback", "proven",
                f"RAM word slot {slot:06X} zero-extended by MOVEQ/MOVE.W/MOVEA.L "
                f"and called at {min(slots[slot].values()):06X}; immediate writer {writer.cpu_address:06X}",
                writer.cpu_address)
    return tuple(result[key] for key in sorted(result))


def discover_nested_word_resolver_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
) -> tuple[DecoderSeed, ...]:
    """LEA / JSR leaf resolver / JSR (An), with long outer and word inner tables."""
    by_address = {f.cpu_address: f for f in facts.values()}
    ends = {f.cpu_address + f.length: f for f in facts.values()}
    interiors = starts = boundaries = None
    data, origin = image.data, image.header.rom_start
    result = {}
    for caller in facts.values():
        if caller.mnemonic.upper() not in {"JSR", "BSR", "BSR.W", "BSR.B"} or len(caller.flows) != 1:
            continue
        body, cursor = [], caller.flows[0]
        for _ in range(10):
            item = by_address.get(cursor)
            if item is None:
                break
            body.append(item)
            cursor += item.length
        if len(body) != 10 or body[-1].mnemonic.upper() != "RTS":
            continue
        dr_match = re.fullmatch(r"#?0x0\|(D[0-7])", body[0].operands, re.I)
        if dr_match is None or not _zero(body[0], dr_match[1]):
            continue
        dr = dr_match[1].upper()
        pointer = re.fullmatch(r"\(0x0,(A[0-6])," + dr + r"w\*0x1\)\|(A[0-6])", body[4].operands, re.I)
        if pointer is None or pointer[1].upper() != pointer[2].upper():
            continue
        ar = pointer[1].upper()
        expected = {2: ("ADD.W", f"{dr}W|{dr}W"), 3: ("ADD.W", f"{dr}W|{dr}W"),
                    6: ("ADD.W", f"{dr}W|{dr}W"), 7: ("MOVE.W", f"(0X0,{ar},{dr}W*0X1)|{dr}W"),
                    8: ("MOVEA.L", f"{dr}|{ar}")}
        if (body[4].mnemonic.upper() != "MOVEA.L"
                or any(f.flow_type.upper() != "FALL_THROUGH" for f in body[:-1])
                or any(body[i].mnemonic.upper() != op or body[i].operands.upper() != operands for i, (op, operands) in expected.items())
                or any(body[i].mnemonic.upper() != "MOVE.W" or not body[i].operands.upper().endswith(f"|{dr}W")
                       or _ram_word(body[i].operands.split("|")[0], image) is None for i in (1, 5))):
            continue
        lea, call = ends.get(caller.cpu_address), by_address.get(caller.cpu_address + caller.length)
        if (lea is None or lea.mnemonic.upper() != "LEA" or lea.operands.rsplit("|", 1)[-1].upper() != ar
                or call is None or call.mnemonic.upper() not in {"JMP", "JSR"} or call.operands.upper() != f"({ar})"):
            continue
        table = pc_displacement_target(lea)
        absolute = ABS.fullmatch(lea.operands.split("|")[0])
        if table is None and absolute:
            table = int(absolute[1], 0) & 0xFFFFFF
        if table is None:
            continue
        if interiors is None:
            _, interiors, starts = instruction_sets(facts)
            boundaries = absolute_referenced_addresses(facts)
        secondary = []
        limit = min(len(data), table - origin + 4 * 256)
        for at in range(table - origin, limit, 4):
            if at < 0x200 or at & 1 or at + 4 > limit:
                break
            if at != table - origin and origin + at in boundaries:
                break
            target = int.from_bytes(data[at:at+4], "big")
            physical = target - origin
            if (target & 1 or not 0x200 <= physical <= len(data) - 2
                    or table <= target < origin + at + 4):
                break
            secondary.append(target)
            if physical > at:
                limit = min(limit, physical)
        if len(set(secondary)) < 2:
            continue
        targets = set()
        for table2 in set(secondary):
            start = table2 - origin
            limit = min([len(data), start + 2 * 256,
                         *(other - origin for other in secondary if other > table2)])
            at = start
            while at + 2 <= limit:
                if at != start and origin + at in boundaries:
                    break
                target = int.from_bytes(data[at:at+2], "big")
                if not _target(image, target, set()) or start <= target - origin < at + 2:
                    break
                # The executed resolver proves that these slots are data.
                # A backend decode of a subtable must not truncate the outer
                # array. Conflicting handler interiors are skipped individually.
                if target - origin not in interiors:
                    targets.add(target)
                if target - origin > at:
                    limit = min(limit, target - origin)
                at += 2
        if len(targets) < 4 or not targets & starts:
            continue
        for target in targets:
            result[target] = DecoderSeed(target, "nested_word_resolver", "proven",
                f"LEA outer table {table:06X}; leaf resolver {body[0].cpu_address:06X} "
                f"selects longword subtable, zero-extends an absolute word and returns {ar}; call {call.cpu_address:06X}",
                caller.cpu_address)
    return tuple(result[key] for key in sorted(result))
