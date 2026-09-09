"""Deterministic, full-coverage ca65 emitter for the initial NES/NROM slice."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct

from .facts import InstructionFact
from .ines import InesImage, canonical_prg_start, cpu_to_prg_offset
from .pointers import PointerCandidate, accepted_pointer_tables


OFFICIAL_6502 = {
    "ADC", "AND", "ASL", "BCC", "BCS", "BEQ", "BIT", "BMI", "BNE",
    "BPL", "BRK", "BVC", "BVS", "CLC", "CLD", "CLI", "CLV", "CMP",
    "CPX", "CPY", "DEC", "DEX", "DEY", "EOR", "INC", "INX", "INY",
    "JMP", "JSR", "LDA", "LDX", "LDY", "LSR", "NOP", "ORA", "PHA",
    "PHP", "PLA", "PLP", "ROL", "ROR", "RTI", "RTS", "SBC", "SEC",
    "SED", "SEI", "STA", "STX", "STY", "TAX", "TAY", "TSX", "TXA",
    "TXS", "TYA",
}
BRANCHES = {"BCC", "BCS", "BEQ", "BMI", "BNE", "BPL", "BVC", "BVS"}
DIRECT_CONTROL = BRANCHES | {"JMP", "JSR"}
HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")
SPACE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*::")
DIRECT_ADDRESS_RE = re.compile(r"(?:a:)?\$([0-9A-Fa-f]{2,4})(,[XY])?")


class EmitError(ValueError):
    """Facts cannot be emitted without violating byte ownership."""


@dataclass(frozen=True)
class EmitResult:
    instruction_count: int
    instruction_bytes: int
    pointer_bytes: int
    raw_bytes: int
    labels: int
    diagnostics: tuple[str, ...]


def technical_name(kind: str, address: int) -> str:
    prefixes = {
        "function": "Func",
        "location": "Loc",
        "pointer_table": "PtrTable",
        "pointer_table_high": "PtrTableHi",
        "data": "Data",
    }
    prefix = prefixes[kind]
    return f"{prefix}_B00_{address:04X}"


def internal_address(image: InesImage, address: int) -> bool:
    try:
        cpu_to_prg_offset(image, address)
    except ValueError:
        return False
    return True


def label_plan(
    image: InesImage,
    facts: dict[int, InstructionFact],
    pointer_candidates: tuple[PointerCandidate, ...] = (),
) -> tuple[dict[int, str], tuple[str, ...]]:
    priorities: dict[int, int] = {}
    labels: dict[int, str] = {}
    diagnostics: list[str] = []
    interiors: set[int] = set()
    pointer_interiors: set[int] = set()
    for fact in facts.values():
        interiors.update(range(fact.physical_offset + 1, fact.physical_offset + fact.length))
    for candidate in accepted_pointer_tables(pointer_candidates):
        if candidate.schema_id == "nes.u16le":
            pointer_interiors.update(
                entry.physical_offset + 1 for entry in candidate.entries
            )

    def propose(address: int, kind: str, priority: int) -> None:
        if not internal_address(image, address):
            return
        offset = cpu_to_prg_offset(image, address)
        if offset in interiors:
            diagnostics.append(
                f"control target ${address:04X} falls inside an instruction; kept numeric"
            )
            return
        if offset in pointer_interiors:
            diagnostics.append(
                f"target ${address:04X} falls inside an encoded pointer; kept numeric"
            )
            return
        if priority > priorities.get(address, -1):
            labels[address] = technical_name(kind, address)
            priorities[address] = priority

    for fact in facts.values():
        if fact.backend_function:
            propose(fact.cpu_address, "function", 30)
        if fact.mnemonic not in DIRECT_CONTROL:
            continue
        kind = "function" if fact.mnemonic == "JSR" else "location"
        priority = 20 if kind == "function" else 10
        for target in fact.flows:
            propose(target, kind, priority)

    for candidate in accepted_pointer_tables(pointer_candidates):
        propose(candidate.cpu_start, "pointer_table", 35)
        if candidate.schema_id == "nes.split_lo_hi":
            high_address = candidate.entries[0].high_cpu_address
            if high_address is None:
                raise EmitError(f"split pointer table {candidate.candidate_id} has no high array")
            propose(high_address, "pointer_table_high", 35)
        for entry in candidate.entries:
            if not internal_address(image, entry.target):
                continue
            target_offset = cpu_to_prg_offset(image, entry.target)
            kind = "location" if target_offset in facts else "data"
            propose(entry.target, kind, 15)

    if len(image.prg) >= 6:
        nmi, reset, irq = struct.unpack_from("<HHH", image.prg, len(image.prg) - 6)
        for target in (nmi, reset, irq):
            if target:
                propose(target, "function", 40)
    return labels, tuple(dict.fromkeys(diagnostics))


def numeric_operand(fact: InstructionFact) -> str:
    operand = SPACE_RE.sub("", fact.operands).replace("|", ", ")

    def replace(match: re.Match[str]) -> str:
        value = int(match.group(1), 16)
        width = 2 if value <= 0xFF else 4
        return f"${value:0{width}X}"

    operand = HEX_RE.sub(replace, operand)
    operand = re.sub(r"\s*,\s*", ",", operand).strip()
    if fact.length == 3 and fact.mnemonic not in {"JMP", "JSR"}:
        if re.fullmatch(r"\$[0-9A-Fa-f]{2,4}(?:,[XY])?", operand):
            operand = "a:" + operand
    return operand


def relative_branch_operand(fact: InstructionFact) -> str:
    """Express a branch target relative to the relocatable instruction address."""
    if fact.length != 2 or len(fact.raw) != 2:
        raise EmitError(
            f"branch ${fact.cpu_address:04X} does not have a two-byte encoding"
        )
    displacement = fact.raw[1] if fact.raw[1] < 0x80 else fact.raw[1] - 0x100
    target_delta = 2 + displacement
    operator = "+" if target_delta >= 0 else "-"
    return f"* {operator} {abs(target_delta)}"


def format_instruction(
    fact: InstructionFact, image: InesImage, labels: dict[int, str]
) -> str | None:
    if fact.mnemonic not in OFFICIAL_6502:
        return None
    operand = numeric_operand(fact)
    direct = fact.mnemonic in DIRECT_CONTROL and not (
        fact.mnemonic == "JMP" and operand.startswith("(")
    )
    internal_flows = [target for target in fact.flows if internal_address(image, target)]
    if direct and len(internal_flows) == 1 and internal_flows[0] in labels:
        operand = labels[internal_flows[0]]
    elif fact.mnemonic in BRANCHES and len(internal_flows) == 1:
        # A legal 6502 branch may target a byte inside another decoded
        # instruction. Such a byte cannot own a ca65 label, so preserve the
        # encoded displacement with a relocatable expression instead.
        operand = relative_branch_operand(fact)
    elif not direct:
        match = DIRECT_ADDRESS_RE.fullmatch(operand)
        if match is not None:
            address = int(match.group(1), 16)
            if address in labels:
                force_absolute = "a:" if fact.length == 3 else ""
                operand = force_absolute + labels[address] + (match.group(2) or "")
    statement = f"    {fact.mnemonic}"
    if operand:
        statement += " " + operand
    encoded = " ".join(f"{value:02X}" for value in fact.raw)
    return f"{statement:<32} ; ${fact.cpu_address:04X}: {encoded}"


def data_line(payload: bytes) -> str:
    return "    .byte " + ", ".join(f"${value:02X}" for value in payload)


def prg_source(
    image: InesImage,
    facts: dict[int, InstructionFact],
    pointer_candidates: tuple[PointerCandidate, ...] = (),
) -> tuple[str, EmitResult]:
    labels, diagnostics = label_plan(image, facts, pointer_candidates)
    pointer_tables = {
        candidate.physical_start: candidate
        for candidate in accepted_pointer_tables(pointer_candidates)
    }
    canonical_start = canonical_prg_start(image)
    attachable = {
        cpu_to_prg_offset(image, address): name
        for address, name in labels.items()
        if canonical_start <= address <= 0xFFFF
    }
    aliases = {
        address: name
        for address, name in labels.items()
        if not canonical_start <= address <= 0xFFFF
    }
    lines = [
        '; Generated by Retrolarium Kit from neutral instruction facts.',
        '; Unknown or unsupported ranges remain byte-exact raw data.',
        '',
        '.setcpu "6502"',
        '',
    ]
    for address, name in sorted(aliases.items()):
        lines.append(f"{name} = ${address:04X}")
    if aliases:
        lines.append("")
    lines.extend(['.segment "PRG"', ''])

    offset = 0
    instruction_count = 0
    instruction_bytes = 0
    pointer_bytes = 0
    raw_bytes = 0
    vector_offset = len(image.prg) - 6
    while offset < len(image.prg):
        label = attachable.get(offset)
        if label:
            if lines[-1] != "":
                lines.append("")
            lines.append(label + ":")
        if offset == vector_offset:
            nmi, reset, irq = struct.unpack_from("<HHH", image.prg, vector_offset)
            for index, (name, target) in enumerate(
                (("Nmi", nmi), ("Reset", reset), ("Irq", irq))
            ):
                if index:
                    lines.append("")
                operand = labels.get(target, f"${target:04X}")
                lines.append(f"{name}Vector:")
                lines.append(f"    .addr {operand}")
            offset += 6
            pointer_bytes += 6
            continue
        pointer_table = pointer_tables.get(offset)
        if pointer_table is not None:
            if pointer_table.schema_id == "nes.u16le":
                for index, entry in enumerate(pointer_table.entries):
                    if index:
                        entry_label = attachable.get(entry.physical_offset)
                        if entry_label:
                            lines.append("")
                            lines.append(entry_label + ":")
                    operand = labels.get(entry.target, f"${entry.target:04X}")
                    lines.append(f"    .addr {operand}")
            elif pointer_table.schema_id == "nes.split_lo_hi":
                for index, entry in enumerate(pointer_table.entries):
                    if index:
                        entry_label = attachable.get(entry.physical_offset)
                        if entry_label:
                            lines.append("")
                            lines.append(entry_label + ":")
                    operand = labels.get(entry.target, f"${entry.target:04X}")
                    lines.append(f"    .byte .lobyte({operand})")
                for entry in pointer_table.entries:
                    if entry.high_physical_offset is None:
                        raise EmitError(
                            f"split pointer table {pointer_table.candidate_id} "
                            "has an incomplete entry"
                        )
                    entry_label = attachable.get(entry.high_physical_offset)
                    if entry_label:
                        lines.append("")
                        lines.append(entry_label + ":")
                    operand = labels.get(entry.target, f"${entry.target:04X}")
                    lines.append(f"    .byte .hibyte({operand})")
            else:
                raise EmitError(f"unsupported pointer schema {pointer_table.schema_id}")
            offset = pointer_table.physical_end
            pointer_bytes += pointer_table.physical_end - pointer_table.physical_start
            continue
        fact = facts.get(offset)
        statement = format_instruction(fact, image, labels) if fact else None
        if fact is not None and statement is not None:
            lines.append(statement)
            offset += fact.length
            instruction_count += 1
            instruction_bytes += fact.length
            continue

        start = offset
        limit = min(start + 16, len(image.prg))
        if start < vector_offset:
            limit = min(limit, vector_offset)
        offset += 1
        while offset < limit:
            if offset in attachable:
                break
            if offset in pointer_tables:
                break
            candidate = facts.get(offset)
            if candidate is not None and format_instruction(candidate, image, labels) is not None:
                break
            offset += 1
        payload = image.prg[start:offset]
        lines.append(data_line(payload))
        raw_bytes += len(payload)

    result = EmitResult(
        instruction_count=instruction_count,
        instruction_bytes=instruction_bytes,
        pointer_bytes=pointer_bytes,
        raw_bytes=raw_bytes,
        labels=len(labels),
        diagnostics=diagnostics,
    )
    if result.instruction_bytes + result.pointer_bytes + result.raw_bytes != len(image.prg):
        raise EmitError("PRG coverage is not complete")
    return "\n".join(lines).rstrip() + "\n", result


def linker_config(image: InesImage) -> str:
    prg_start = canonical_prg_start(image)
    memory = [
        '    HEADER: start = $0000, size = $0010, file = %O, fill = yes;',
    ]
    segments = ['    HEADER: load = HEADER, type = ro;']
    if image.trainer:
        memory.append('    TRAINER: start = $0000, size = $0200, file = %O, fill = yes;')
        segments.append('    TRAINER: load = TRAINER, type = ro;')
    memory.append(
        f"    PRG: start = ${prg_start:04X}, size = ${len(image.prg):04X}, file = %O, fill = yes;"
    )
    segments.append('    PRG: load = PRG, type = ro;')
    if image.chr:
        memory.append(
            f"    CHR: start = $0000, size = ${len(image.chr):04X}, file = %O, fill = yes;"
        )
        segments.append('    CHR: load = CHR, type = ro;')
    return (
        "MEMORY {\n" + "\n".join(memory) + "\n}\n\nSEGMENTS {\n" +
        "\n".join(segments) + "\n}\n"
    )


def emit_project(
    output: Path,
    image: InesImage,
    facts: dict[int, InstructionFact],
    pointer_candidates: tuple[PointerCandidate, ...] = (),
) -> EmitResult:
    output.mkdir(parents=True, exist_ok=True)
    assets = output / "assets"
    source = output / "src"
    assets.mkdir(exist_ok=True)
    source.mkdir(exist_ok=True)
    (assets / "header.bin").write_bytes(image.header)
    if image.trainer:
        (assets / "trainer.bin").write_bytes(image.trainer)
    if image.chr:
        (assets / "chr.bin").write_bytes(image.chr)

    prg, result = prg_source(image, facts, pointer_candidates)
    main_lines = [
        '.segment "HEADER"',
        '    .incbin "assets/header.bin"',
    ]
    if image.trainer:
        main_lines.extend(['', '.segment "TRAINER"', '    .incbin "assets/trainer.bin"'])
    main_lines.extend(['', '.include "src/prg.asm"'])
    if image.chr:
        main_lines.extend(['', '.segment "CHR"', '    .incbin "assets/chr.bin"'])
    (output / "main.asm").write_text("\n".join(main_lines) + "\n", encoding="utf-8", newline="\n")
    (source / "prg.asm").write_text(prg, encoding="utf-8", newline="\n")
    (output / "linker.cfg").write_text(linker_config(image), encoding="utf-8", newline="\n")
    makefile = """.PHONY: all clean
all: build/rebuilt.nes

build/main.o: main.asm src/prg.asm assets/header.bin linker.cfg
	mkdir -p build
	ca65 -g -o $@ main.asm

build/rebuilt.nes: build/main.o linker.cfg
	ld65 -C linker.cfg -m build/rebuilt.map -o $@ build/main.o

clean:
	rm -rf build
"""
    (output / "Makefile").write_text(makefile, encoding="utf-8", newline="\n")
    metadata = {
        "schema_version": 1,
        "input_sha256": image.sha256,
        "mapper": image.mapper,
        "prg_size": len(image.prg),
        "chr_size": len(image.chr),
        "instruction_count": result.instruction_count,
        "instruction_bytes": result.instruction_bytes,
        "pointer_bytes": result.pointer_bytes,
        "raw_prg_bytes": result.raw_bytes,
        "labels": result.labels,
        "diagnostics": list(result.diagnostics),
    }
    (output / "emission.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return result
