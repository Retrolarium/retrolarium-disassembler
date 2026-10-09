"""Recover callback parameters and saved return PCs from decoded engine ABIs.

No function names or game addresses are used. A ROM address passed in an
address register must reach a store into a field that decoded code executes.
The bounded interprocedural walk stops at a register clobber or unknown call.
"""
from __future__ import annotations

from collections import deque
import re

from retrolarium_disassembler.facts import InstructionFact
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disassembler.m68k.instructions import instruction_sets
from retrolarium_disassembler.m68k.instructions import pc_displacement_target
from retrolarium_disassembler.m68k.dispatch.record import executed_stack_fields
from retrolarium_disassembler.m68k.abstract import _register_list
from retrolarium_disassembler.m68k.frames.call_frame import _STACK


_FIELD = r"\((?:(-?0x[0-9a-f]+),)?(A[0-6])\)"
_LOAD = re.compile(_FIELD + r"\|(A[0-6])", re.I)
_STORE = re.compile(r"(A[0-6]|\(SP\)\+)\|" + _FIELD, re.I)
_ABS_LEA = re.compile(r"\((0x[0-9a-f]+)\)\.l\|(A[0-6])", re.I)
_IMMEDIATE_STORE = re.compile(r"#(0x[0-9a-f]+)\|" + _FIELD, re.I)


def _executed_fields(facts):
    fields = executed_stack_fields(facts)
    for fact in facts.values():
        match = _LOAD.fullmatch(fact.operands)
        call = facts.get(fact.cpu_address + fact.length)
        if (fact.mnemonic.upper() == "MOVEA.L" and match and call
                and call.mnemonic.upper() in {"JSR", "JMP"}
                and call.operands.upper() == f"({match[3].upper()})"):
            fields[int(match[1] or "0", 0)] = call.cpu_address
    return fields


def _clobbers(fact, register):
    operands = fact.operands.upper().split("|")
    destination = operands[-1] if operands else ""
    if re.fullmatch(register + r"[BWL]?", destination):
        return not fact.mnemonic.upper().startswith(("CMP", "TST", "BTST"))
    if fact.mnemonic.upper().startswith("MOVEM") and operands[0] == "(SP)+":
        return register.lower() in _register_list(destination)
    return False


def _stores_on_path(facts, start, register, fields, *, bookmark=False):
    pending = deque([(start, 0)])
    visited = set()
    stores = set()
    while pending and len(visited) < 256:
        address, depth = pending.popleft()
        if (address, depth) in visited:
            continue
        visited.add((address, depth))
        fact = facts.get(address)
        if fact is None:
            continue
        match = _STORE.fullmatch(fact.operands)
        if fact.mnemonic.upper() == "MOVE.L" and match:
            field = int(match[2] or "0", 0)
            if field in fields and match[1].upper() == ("(SP)+" if bookmark else register):
                following = facts.get(address + fact.length)
                if not bookmark or following and following.raw == b"\x4e\x75":
                    stores.add(address)
        if bookmark:
            # Only the untouched top of the caller's stack is a return PC.
            if _STACK.search(fact.operands):
                continue
        elif _clobbers(fact, register):
            continue
        opcode = int.from_bytes(fact.raw[:2], "big")
        targets = tuple(target & 0xFFFFFF for target in fact.flows)
        if opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100:
            if depth < 3 and not bookmark:
                pending.extend((target, depth + 1) for target in targets)
            continue  # Do not assume an unknown callee preserves a parameter.
        flow = fact.flow_type.upper()
        if flow in {"UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP"} or opcode & 0xFFC0 == 0x4EC0:
            pending.extend((target, depth) for target in targets)
        if flow in {"FALL_THROUGH", "CONDITIONAL_JUMP"}:
            pending.append((address + fact.length, depth))
    return stores


def discover_callback_abi_seeds(image: MegaDriveImage, facts: dict[int, InstructionFact], *, execution_facts=None):
    facts = {fact.cpu_address: fact for fact in facts.values()}
    executors = facts if execution_facts is None else {
        fact.cpu_address: fact for fact in execution_facts.values()}
    fields = _executed_fields(executors)
    if not fields:
        return ()
    _, interiors, _ = instruction_sets(facts)
    seeds = {}
    summaries = {}
    data = {ref.address & 0xFFFFFF for fact in facts.values()
            if fact.mnemonic.upper() != "LEA" for ref in fact.references
            if ref.reference_type.upper() == "READ"
            or ref.reference_type.upper() == "DATA" and not fact.operands.startswith("#")}

    def accept(target, source, stores, kind):
        physical = target - image.header.rom_start
        if (target & 1 or physical in interiors or target in data
                or not 0x200 <= physical < len(image.data) - 1
                or image.data[physical:physical + 2] in {b"\0\0", b"\xff\xff"}):
            return
        evidence = (f"callback field executed at {','.join(f'{a:06X}' for a in fields.values())}; "
                    f"callee stores {'return PC' if kind == 'callback_bookmark' else 'parameter'} "
                    f"at {','.join(f'{a:06X}' for a in sorted(stores))}")
        seeds[target] = DecoderSeed(target, kind, "high", evidence, source)

    for lea in facts.values():
        if lea.mnemonic.upper() != "LEA":
            continue
        register = lea.operands.rsplit("|", 1)[-1].upper()
        if not re.fullmatch(r"A[0-6]", register):
            continue
        target = pc_displacement_target(lea)
        match = _ABS_LEA.fullmatch(lea.operands)
        if target is None and match:
            target = int(match[1], 0)
        if target is None:
            continue
        current = lea
        for _ in range(6):
            current = facts.get(current.cpu_address + current.length)
            if current is None:
                break
            opcode = int.from_bytes(current.raw[:2], "big")
            if opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100:
                stores = set()
                for callee in current.flows:
                    key = (callee & 0xFFFFFF, register)
                    if key not in summaries:
                        summaries[key] = _stores_on_path(facts, key[0], register, fields)
                    stores.update(summaries[key])
                if stores:
                    accept(target, lea.cpu_address, stores, "callback_parameter")
                break
            if current.flow_type.upper() != "FALL_THROUGH" or _clobbers(current, register):
                break

    for call in facts.values():
        opcode = int.from_bytes(call.raw[:2], "big")
        if not (opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100):
            continue
        stores = set()
        for callee in call.flows:
            key = (callee & 0xFFFFFF, "bookmark")
            if key not in summaries:
                summaries[key] = _stores_on_path(facts, key[0], "", fields, bookmark=True)
            stores.update(summaries[key])
        if stores:
            accept(call.cpu_address + call.length, call.cpu_address, stores, "callback_bookmark")

    # Multiple assignments to the exact field/base register pair executed
    # by an object loop corroborate callback labels inside a function. Such
    # labels need not be immediately after RTS (an old, overstrict boundary).
    # Require existing backend instruction boundaries and reject data uses.
    readers = {}
    for load in executors.values():
        match = _LOAD.fullmatch(load.operands)
        call = executors.get(load.cpu_address + load.length)
        if (load.mnemonic.upper() == "MOVEA.L" and match and call
                and call.mnemonic.upper() in {"JSR", "JMP"}
                and call.operands.upper() == f"({match[3].upper()})"):
            readers[(int(match[1] or "0", 0), match[2].upper())] = call.cpu_address
    assignments = {}
    for store in facts.values():
        match = _IMMEDIATE_STORE.fullmatch(store.operands)
        if store.mnemonic.upper() != "MOVE.L" or match is None:
            continue
        target = int(match[1], 0)
        key = (int(match[2] or "0", 0), match[3].upper())
        entry = facts.get(target)
        if (key in readers and entry and target not in data
                and entry.raw[:2] not in {b"\0\0", b"\xff\xff"}
                and entry.raw[0] >> 4 not in {0xA, 0xF}):
            assignments.setdefault(key, []).append((target, store.cpu_address))
    for key, stores in assignments.items():
        if len({target for target, _ in stores}) < 2:
            continue
        for target, writer in stores:
            accept(target, readers[key], {writer}, "callback_field_assignment")
    return tuple(seeds[address] for address in sorted(seeds))
