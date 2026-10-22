"""Exact-first modular ca65 source emission for plain LoROM and HiROM images."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from retrolarium_core.snes import SnesImage, snes_to_rom_offset
from retrolarium_disassembler.snes.analysis import AnalysisResult, Instruction
from retrolarium_disassembler.snes.pointers import PointerCandidate
from retrolarium_disassembler.snes.symbols import TechnicalSymbol


class SnesEmitError(RuntimeError):
    """The SNES source project could not provide exact, non-overlapping coverage."""


@dataclass(frozen=True)
class EmissionResult:
    bank_units: tuple[str, ...]
    instruction_bytes: int
    pointer_bytes: int
    header_bytes: int
    raw_bytes: int
    instruction_fallback_bytes: int
    labels: int
    diagnostics: tuple[str, ...]


def _hex_bytes(payload: bytes, *, indent: str = "    ") -> list[str]:
    lines: list[str] = []
    for start in range(0, len(payload), 16):
        chunk = payload[start : start + 16]
        values = ", ".join(f"${value:02X}" for value in chunk)
        lines.append(f"{indent}.byte {values}")
    return lines


def _private_label(physical_offset: int) -> str:
    return f"__Rom_{physical_offset:06X}"


def _symbol_value(address: int, symbols: dict[int, TechnicalSymbol]) -> str:
    symbol = symbols.get(address)
    return symbol.name if symbol is not None else f"${address:06X}"


def _operand_value(raw: bytes) -> int:
    return int.from_bytes(raw[1:], "little")


def _format_instruction(
    image: SnesImage,
    instruction: Instruction,
    symbols: dict[int, TechnicalSymbol],
    instruction_offsets: set[int],
) -> list[str] | None:
    mnemonic = instruction.mnemonic.lower()
    mode = instruction.addressing_mode
    raw = instruction.raw
    prefix: list[str] = []
    if instruction.state_before.m is not None:
        prefix.append("    .a8" if instruction.state_before.m else "    .a16")
    if instruction.state_before.x is not None:
        prefix.append("    .i8" if instruction.state_before.x else "    .i16")

    control_target = next(
        (
            flow.target
            for flow in instruction.flows
            if flow.kind in {"branch", "call", "jump"} and flow.target is not None
        ),
        None,
    )
    operand: str
    if mode == "imp":
        operand = ""
    elif mode == "acc":
        operand = "a"
    elif mode in {"immM", "immX"}:
        width = (len(raw) - 1) * 2
        operand = f"#${_operand_value(raw):0{width}X}"
    elif mode == "imm8":
        marker = "#" if instruction.mnemonic in {"REP", "SEP"} else ""
        operand = f"{marker}${raw[1]:02X}"
    elif mode in {"rel8", "rel16"}:
        if control_target is None:
            return None
        try:
            target_offset = snes_to_rom_offset(image, control_target)
        except ValueError:
            return None
        if target_offset not in instruction_offsets:
            return None
        operand = _private_label(target_offset)
    elif mode == "dp":
        operand = f"${raw[1]:02X}"
    elif mode == "dpx":
        operand = f"${raw[1]:02X},x"
    elif mode == "dpy":
        operand = f"${raw[1]:02X},y"
    elif mode == "dpi":
        operand = f"(${raw[1]:02X})"
    elif mode == "dpix":
        operand = f"(${raw[1]:02X},x)"
    elif mode == "dpiy":
        operand = f"(${raw[1]:02X}),y"
    elif mode == "dpil":
        operand = f"[${raw[1]:02X}]"
    elif mode == "dpily":
        operand = f"[${raw[1]:02X}],y"
    elif mode == "sr":
        operand = f"${raw[1]:02X},s"
    elif mode == "sriy":
        operand = f"(${raw[1]:02X},s),y"
    elif mode == "abs":
        value = int.from_bytes(raw[1:3], "little")
        if control_target is not None:
            # A near JSR/JMP keeps only the 16-bit target in the current PBR.
            # ca65 otherwise promotes a 24-bit symbol to a four-byte long call.
            operand = f".loword({_symbol_value(control_target, symbols)})"
        elif instruction.mnemonic == "PEA":
            operand = f"${value:04X}"
        else:
            operand = f"a:${value:04X}"
    elif mode == "absx":
        operand = f"a:${int.from_bytes(raw[1:3], 'little'):04X},x"
    elif mode == "absy":
        operand = f"a:${int.from_bytes(raw[1:3], 'little'):04X},y"
    elif mode == "absi":
        operand = f"(${int.from_bytes(raw[1:3], 'little'):04X})"
    elif mode == "absix":
        operand = f"(${int.from_bytes(raw[1:3], 'little'):04X},x)"
    elif mode == "absil":
        operand = f"[${int.from_bytes(raw[1:3], 'little'):04X}]"
    elif mode == "long":
        value = int.from_bytes(raw[1:4], "little")
        operand = _symbol_value(control_target, symbols) if control_target is not None else f"f:${value:06X}"
    elif mode == "longx":
        operand = f"f:${int.from_bytes(raw[1:4], 'little'):06X},x"
    elif mode == "block":
        return None
    else:
        raise SnesEmitError(f"unknown W65C816 addressing mode: {mode}")
    suffix = f" {operand}" if operand else ""
    return [*prefix, f"    {mnemonic}{suffix}"]


def _pointer_lines(
    candidate: PointerCandidate,
    symbols: dict[int, TechnicalSymbol],
) -> list[str]:
    lines = [f"    ; {candidate.schema_id} at ROM ${candidate.physical_start:06X}"]
    targets = [_symbol_value(entry.target, symbols) for entry in candidate.entries]
    if candidate.schema_id == "snes.u16le.current-bank":
        lines.extend(f"    .word .loword({target})" for target in targets)
    elif candidate.schema_id == "snes.u24le.far":
        lines.extend(f"    .faraddr {target}" for target in targets)
    elif candidate.schema_id == "snes.split-lo-hi-bank":
        joined = ", ".join(targets)
        lines.extend(
            (
                f"    .lobytes {joined}",
                f"    .hibytes {joined}",
                f"    .bankbytes {joined}",
            )
        )
    elif candidate.schema_id == "snes.s16le.table-base":
        base = candidate.logical_start
        lines.extend(f"    .word ({target} - ${base:06X}) & $FFFF" for target in targets)
    else:
        raise SnesEmitError(f"unsupported pointer schema: {candidate.schema_id}")
    return lines


def _header_lines(
    image: SnesImage,
    symbols: dict[int, TechnicalSymbol],
) -> list[str]:
    data = image.header_data
    lines = ["; SNES internal header, checksum and native/emulation vectors."]
    lines.extend(_hex_bytes(data[:0x1C]))
    lines.append(f"    .word ${image.header.checksum_complement:04X}")
    lines.append(f"    .word ${image.header.checksum:04X}")
    for vector in image.vector_table:
        if vector.cpu_address is None:
            value = f"${vector.raw_value:04X}"
        else:
            value = f".loword({_symbol_value(vector.cpu_address, symbols)})"
        lines.append(f"    .word {value} ; {vector.mode} {vector.name}")
    return lines


def _memory_start(image: SnesImage, bank: int) -> int:
    if image.header.map_mode == "lorom":
        logical_bank = bank if bank not in {0x7E, 0x7F} else bank | 0x80
        return (logical_bank << 16) | 0x8000
    return bank << 16


def _write_linker(path: Path, image: SnesImage, bank_size: int) -> None:
    bank_count = -(-len(image.data) // bank_size)
    memory: list[str] = []
    segments: list[str] = []
    if image.copier_header:
        memory.append(f"    COPIER: start = $7D0000, size = ${len(image.copier_header):X}, file = %O, fill = no;")
        segments.append("    COPIER: load = COPIER, type = ro;")
    for bank in range(bank_count):
        name = f"BANK{bank:02X}"
        memory.append(
            f"    {name}: start = ${_memory_start(image, bank):06X}, "
            f"size = ${min(bank_size, len(image.data) - bank * bank_size):X}, file = %O, fill = no;"
        )
        segments.append(f"    {name}: load = {name}, type = ro;")
    text = "MEMORY {\n" + "\n".join(memory) + "\n}\n\nSEGMENTS {\n" + "\n".join(segments) + "\n}\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_makefile(path: Path) -> None:
    path.write_text(
        ".PHONY: all clean\n\n"
        "all: build/rebuilt.sfc\n\n"
        "build/main.o: main.asm linker.cfg symbols.inc src/*.asm\n"
        "\tmkdir -p build\n"
        "\tca65 -g -o $@ main.asm\n\n"
        "build/rebuilt.sfc: build/main.o linker.cfg\n"
        "\tld65 -C linker.cfg -m build/rebuilt.map -o $@ build/main.o\n\n"
        "clean:\n"
        "\trm -rf build\n",
        encoding="utf-8",
        newline="\n",
    )


def emit_project(
    output: Path,
    image: SnesImage,
    analysis: AnalysisResult,
    pointer_candidates: tuple[PointerCandidate, ...],
    symbols: tuple[TechnicalSymbol, ...],
) -> EmissionResult:
    output.mkdir(parents=True, exist_ok=True)
    source_dir = output / "src"
    asset_dir = output / "assets"
    source_dir.mkdir(parents=True, exist_ok=True)
    asset_dir.mkdir(parents=True, exist_ok=True)

    symbols_by_address = {symbol.logical_address: symbol for symbol in symbols}
    symbol_lines = ["; Stable logical SNES symbols."]
    for symbol in symbols:
        symbol_lines.append(f"{symbol.name} = ${symbol.logical_address:06X}")
        for alias in symbol.aliases:
            symbol_lines.append(f"{alias} = ${symbol.logical_address:06X}")
    (output / "symbols.inc").write_text("\n".join(symbol_lines) + "\n", encoding="utf-8", newline="\n")
    (source_dir / "header.asm").write_text(
        "\n".join(_header_lines(image, symbols_by_address)) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    instructions: dict[int, Instruction] = {}
    diagnostics: list[str] = []
    for instruction in analysis.instructions:
        previous = instructions.get(instruction.physical_offset)
        if previous is None:
            instructions[instruction.physical_offset] = instruction
        elif previous.raw != instruction.raw:
            diagnostics.append(f"logical aliases disagree at ROM ${instruction.physical_offset:06X}")
            instructions.pop(instruction.physical_offset, None)

    pointers: dict[int, PointerCandidate] = {}
    for candidate in pointer_candidates:
        if candidate.status != "accepted" or candidate.schema_id.startswith("snes.vectors"):
            continue
        if candidate.physical_start in pointers:
            diagnostics.append(f"overlapping pointer claims at ROM ${candidate.physical_start:06X}")
            continue
        pointers[candidate.physical_start] = candidate

    header_start = image.header_offset
    header_end = header_start + 0x40
    # Decodes that share bytes (one routine reached through two bus aliases
    # with different widths) are both guesses: neither is kept, and their
    # bytes go out as they are. So does one over the internal header.
    owners: dict[int, int] = {}
    for instruction in instructions.values():
        for offset in range(instruction.physical_offset, instruction.physical_offset + instruction.length):
            owners[offset] = owners.get(offset, 0) + 1
    for offset in sorted(instructions):
        instruction = instructions[offset]
        byte_range = range(offset, offset + instruction.length)
        if any(owners[item] > 1 for item in byte_range):
            diagnostics.append(f"instructions overlap at ROM ${offset:06X}: kept as bytes")
            del instructions[offset]
        elif any(header_start <= item < header_end for item in byte_range):
            diagnostics.append(f"instruction at ROM ${offset:06X} runs into the internal header: kept as bytes")
            del instructions[offset]
    instruction_offsets = set(instructions)
    claims: set[int] = set(range(header_start, header_end))
    for instruction in instructions.values():
        claims.update(range(instruction.physical_offset, instruction.physical_offset + instruction.length))
    for start in sorted(pointers):
        candidate = pointers[start]
        byte_range = set(range(candidate.physical_start, candidate.physical_end))
        if claims & byte_range:
            diagnostics.append(f"pointer table at ROM ${start:06X} overlaps another claim: kept as bytes")
            del pointers[start]
            continue
        claims.update(byte_range)

    bank_size = 0x8000 if image.header.map_mode == "lorom" else 0x10000
    # A HiROM image an odd number of 32 KB long ends in half a bank.
    bank_count = -(-len(image.data) // bank_size)
    units: list[str] = []
    instruction_bytes = 0
    pointer_bytes = 0
    raw_bytes = 0
    fallback_bytes = 0
    main_lines = ['.setcpu "65816"', '.include "symbols.inc"', ""]
    if image.copier_header:
        (asset_dir / "copier-header.bin").write_bytes(image.copier_header)
        main_lines.extend(
            (
                '.segment "COPIER"',
                '    .incbin "assets/copier-header.bin"',
                "",
            )
        )

    classified_starts = set(instructions) | set(pointers) | {header_start}
    for bank in range(bank_count):
        bank_start = bank * bank_size
        bank_end = min(bank_start + bank_size, len(image.data))
        name = f"bank{bank:02X}.asm"
        units.append(f"src/{name}")
        main_lines.extend((f'.segment "BANK{bank:02X}"', f'.include "src/{name}"', ""))
        lines = [f"; Physical ROM bank {bank:02X}, offsets ${bank_start:06X}-${bank_end - 1:06X}."]
        cursor = bank_start
        while cursor < bank_end:
            if cursor == header_start:
                lines.append('    .include "src/header.asm"')
                cursor = header_end
                continue
            pointer = pointers.get(cursor)
            if pointer is not None:
                lines.extend(_pointer_lines(pointer, symbols_by_address))
                pointer_bytes += pointer.physical_end - pointer.physical_start
                cursor = pointer.physical_end
                continue
            instruction = instructions.get(cursor)
            if instruction is not None:
                lines.append(f"{_private_label(cursor)}:")
                formatted = _format_instruction(
                    image,
                    instruction,
                    symbols_by_address,
                    instruction_offsets,
                )
                if formatted is None:
                    lines.append(f"    ; {instruction.mnemonic} {instruction.addressing_mode}: exact fallback")
                    lines.extend(_hex_bytes(instruction.raw))
                    fallback_bytes += instruction.length
                else:
                    lines.extend(formatted)
                    instruction_bytes += instruction.length
                cursor += instruction.length
                continue
            stop = min(
                (offset for offset in classified_starts if cursor < offset < bank_end),
                default=bank_end,
            )
            payload = image.data[cursor:stop]
            lines.append(f"    ; Opaque bytes at ROM ${cursor:06X}-${stop - 1:06X}.")
            lines.extend(_hex_bytes(payload))
            raw_bytes += len(payload)
            cursor = stop
        (source_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    if instruction_bytes + fallback_bytes + pointer_bytes + 0x40 + raw_bytes != len(image.data):
        raise SnesEmitError("source ownership does not cover the ROM exactly once")
    (output / "main.asm").write_text("\n".join(main_lines), encoding="utf-8", newline="\n")
    _write_linker(output / "linker.cfg", image, bank_size)
    _write_makefile(output / "Makefile")
    result = EmissionResult(
        bank_units=tuple(units),
        instruction_bytes=instruction_bytes,
        pointer_bytes=pointer_bytes,
        header_bytes=0x40,
        raw_bytes=raw_bytes,
        instruction_fallback_bytes=fallback_bytes,
        labels=len(symbols),
        diagnostics=tuple(diagnostics),
    )
    emission = {
        "schema": "retrolarium.snes.emission",
        "schema_version": 1,
        "input_sha256": image.rom_sha256,
        "mapping": image.header.map_mode,
        "units": list(result.bank_units),
        "coverage": {
            "instruction_bytes": result.instruction_bytes,
            "instruction_fallback_bytes": result.instruction_fallback_bytes,
            "pointer_bytes": result.pointer_bytes,
            "header_bytes": result.header_bytes,
            "raw_bytes": result.raw_bytes,
            "rom_bytes": len(image.data),
        },
        "whole_rom_fallback": False,
        "diagnostics": list(result.diagnostics),
    }
    import json

    (output / "emission.json").write_text(
        json.dumps(emission, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return result
