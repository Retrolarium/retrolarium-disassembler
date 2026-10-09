"""Recover Z80 word dispatch tables from their executable lookup idiom."""

from __future__ import annotations

from dataclasses import dataclass

from retrolarium_kit.facts import InstructionFact


@dataclass(frozen=True)
class Z80DispatchTable:
    logical_start: int
    logical_end: int
    dispatch_address: int
    lookup_address: int
    targets: tuple[int, ...]
    dispatch_addresses: tuple[int, ...] = ()


def _word_lookup_helper(payload: bytes, address: int, base_address: int) -> bool:
    """Recognize A-indexed little-endian word lookup returning its value in HL."""
    offset = address - base_address
    if not 0 <= offset <= len(payload) - 10:
        return False
    if payload[offset:offset + 5] != b"\x4f\x06\x00\x09\x09":
        return False
    cursor = offset + 5
    while cursor < min(offset + 12, len(payload)) and payload[cursor] == 0:
        cursor += 1
    return payload[cursor:cursor + 5] == b"\x7e\x23\x66\x6f\xc9"


def _direct_code(
    by_address: dict[int, InstructionFact], roots: set[int],
) -> dict[int, InstructionFact]:
    """Follow explicit control flow, excluding inferred register jump targets."""
    reached: dict[int, InstructionFact] = {}
    pending = list(roots)
    while pending:
        address = pending.pop()
        fact = by_address.get(address)
        if fact is None or address in reached:
            continue
        reached[address] = fact
        flow = fact.flow_type.upper()
        if not flow.startswith("COMPUTED"):
            pending.extend(fact.flows)
        if flow in {
            "FALL_THROUGH", "CONDITIONAL_JUMP", "CONDITIONAL_TERMINATOR",
            "UNCONDITIONAL_CALL", "CONDITIONAL_CALL", "COMPUTED_CALL",
        }:
            pending.append(address + fact.length)
    return reached


def discover_z80_dispatch_tables(
    payload: bytes,
    facts: dict[int, InstructionFact],
    *,
    base_address: int = 0,
) -> tuple[Z80DispatchTable, ...]:
    """Require a proven lookup helper and a nearby indirect jump.

    A table stops at the first word outside the extracted Z80 image, at bytes
    already decoded or reached as code, and at targets inside an instruction.
    We do not infer handler addresses from arbitrary pointer-looking data.
    """
    limit = base_address + len(payload)
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    candidates: list[tuple[int, int, int, int]] = []
    inferred_table_jumps: set[int] = set()
    for address, fact in sorted(by_address.items()):
        if len(fact.raw) != 3 or fact.raw[0] != 0x21:  # LD HL,nn
            continue
        table = int.from_bytes(fact.raw[1:], "little")
        cursor = address + 3
        lookup = by_address.get(cursor)
        if lookup is None or len(lookup.raw) != 1:
            continue
        opcode = lookup.raw[0]
        if opcode & 0xC7 != 0xC7:  # RST p
            continue
        lookup_address = opcode & 0x38
        if not _word_lookup_helper(payload, lookup_address, base_address):
            continue
        cursor += 1
        # These instructions do not change HL after the lookup.
        for _ in range(3):
            next_fact = by_address.get(cursor)
            if next_fact is None or next_fact.raw not in (b"\x13", b"\x1a"):
                break
            cursor += 1
        jump = by_address.get(cursor)
        if jump is None or jump.raw != b"\xe9":  # JP (HL)
            continue
        if base_address <= table < limit - 1:
            # SUB n immediately before the load maps n..FF to 0..(FF-n).
            # It bounds the table without relying on pointer-shaped bytes
            # that may belong to the next adjacent table.
            preceding = next(
                (item for item in by_address.values()
                 if item.cpu_address + item.length == address),
                None,
            )
            count_limit = (
                min(64, 0x100 - preceding.raw[1])
                if preceding is not None
                and len(preceding.raw) == 2
                and preceding.raw[0] == 0xD6
                else 64
            )
            candidates.append((table, address, lookup_address, count_limit))
            if jump.flow_type.upper() == "COMPUTED_JUMP" and table in jump.flows:
                inferred_table_jumps.add(table)

    # Several dispatch sites may share one table; the tightest bound wins.
    grouped: dict[int, tuple[list[int], int, int]] = {}
    for table, dispatch, lookup, count_limit in candidates:
        previous = grouped.get(table)
        if previous is None:
            grouped[table] = ([dispatch], lookup, count_limit)
        else:
            previous[0].append(dispatch)
            grouped[table] = (previous[0], previous[1], min(previous[2], count_limit))

    # Bytes already proven to be instructions or reached by control flow can
    # never be table words, and a target inside an instruction is not code.
    instruction_starts = set(by_address)
    covered: set[int] = set()
    flow_targets: set[int] = set()
    for fact in by_address.values():
        covered.update(range(fact.cpu_address, fact.cpu_address + fact.length))
        flow_targets.update(fact.flows)

    tables: list[Z80DispatchTable] = []
    roots = {base_address}
    roots.update(site for group in grouped.values() for site in group[0])
    for table in sorted(grouped):
        dispatches, lookup, count_limit = grouped[table]
        following = min((other for other in grouped if other > table), default=limit)
        # Some backends propagate the initial LD HL,table through the RST
        # helper and report table as the target of JP (HL). The helper replaces
        # HL with a table word: this inferred edge is false. Rebuild coverage
        # from explicit flow and proven dispatch targets before using decoded
        # bytes as a reason to reject this particular table.
        inferred_table_jump = table in inferred_table_jumps
        if inferred_table_jump:
            direct = _direct_code(by_address, roots)
            table_covered = {
                byte for fact in direct.values()
                for byte in range(fact.cpu_address, fact.cpu_address + fact.length)
            }
            table_flows = {
                target for fact in direct.values()
                if not fact.flow_type.upper().startswith("COMPUTED")
                for target in fact.flows
            }
        else:
            table_covered, table_flows = covered, flow_targets
        targets: list[int] = []
        for address in range(
            table, min(following, table + 2 * count_limit, limit - 1), 2
        ):
            if (address in table_covered or address + 1 in table_covered
                    or address in table_flows or address + 1 in table_flows):
                break
            offset = address - base_address
            target = int.from_bytes(payload[offset:offset + 2], "little")
            if not base_address <= target < limit or table <= target < address + 2:
                break
            if target in table_covered and target not in instruction_starts:
                break
            targets.append(target)
            if inferred_table_jump:
                # A table target may prove the first instruction immediately
                # after the table, even when the preceding inferred edge was
                # wrong. Keep that boundary and all explicitly reached code.
                direct = _direct_code(by_address, {target})
                table_covered.update(
                    byte for fact in direct.values()
                    for byte in range(fact.cpu_address, fact.cpu_address + fact.length)
                )
                table_flows.update(
                    destination for fact in direct.values()
                    if not fact.flow_type.upper().startswith("COMPUTED")
                    for destination in fact.flows
                )
        if (len(targets) >= 4
                and not any(table <= target < table + len(targets) * 2
                            for target in targets)):
            tables.append(Z80DispatchTable(
                logical_start=table,
                logical_end=table + len(targets) * 2,
                dispatch_address=min(dispatches),
                lookup_address=lookup,
                targets=tuple(targets),
                dispatch_addresses=tuple(sorted(dispatches)),
            ))
    return tuple(tables)
