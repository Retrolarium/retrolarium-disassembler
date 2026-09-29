"""Exact-first ASM68K project emitter for analyzed Mega Drive ROMs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .megadrive_pointers import PointerCandidate
from .megadrive_structures import (
    LONG_FF_PADDING_MIN_BYTES,
    StandardBootSetup,
    discover_standard_boot_setups,
)
from .megadrive_symbols import (
    TechnicalSymbol,
    pc_displacement_target,
    pc_indexed_target,
    pc_indexed_jsr_target,
)
from .megadrive_z80 import CrossCpuCopy
from .z80_dispatch import Z80DispatchTable


MODULE_SIZE = 0x10000
FF_ORG_MIN_BYTES = LONG_FF_PADDING_MIN_BYTES
OPAQUE_INCLUDE_MIN_BYTES = 256
M68K_INDENT = " " * 16
SIMPLE_OPCODES = {
    "RESET": bytes.fromhex("4E70"),
    "NOP": bytes.fromhex("4E71"),
    "RTE": bytes.fromhex("4E73"),
    "RTS": bytes.fromhex("4E75"),
    "TRAPV": bytes.fromhex("4E76"),
    "ILLEGAL": bytes.fromhex("4AFC"),
}
AMBIGUOUS_IMMEDIATE_BASES = {"ADD", "SUB", "CMP", "AND", "OR"}


class MegaDriveEmitError(ValueError):
    """Analysis artifacts cannot be emitted without changing ROM bytes."""


@dataclass(frozen=True)
class EmitResult:
    source_units: tuple[str, ...]
    assets: tuple[dict[str, object], ...]
    z80_builds: tuple[dict[str, str], ...]
    instruction_bytes: int
    pointer_bytes: int
    asset_bytes: int
    raw_bytes: int
    padding_bytes: int
    # Subset of instruction_bytes emitted as mnemonics rather than dc.b.
    symbolic_instruction_bytes: int = 0


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hex_bytes(payload: bytes) -> str:
    return ", ".join(f"${value:02X}" for value in payload)


def _m68k_operand(
    operand: str,
    *,
    fact: InstructionFact | None = None,
    primary: dict[int, TechnicalSymbol] | None = None,
) -> str | None:
    operand = operand.strip()
    register = re.fullmatch(r"([DA][0-7])(?:[bwl])?", operand, re.I)
    if register:
        return register.group(1).lower()
    if operand.upper() in ("SP", "SR", "CCR", "USP"):
        return operand.lower()
    immediate = re.fullmatch(r"#(-?0x[0-9a-f]+|-?\d+)", operand, re.I)
    if immediate:
        return f"#{int(immediate.group(1), 0)}"
    direct = re.fullmatch(r"\(?(0x[0-9a-f]+|-0x[0-9a-f]+)\)?\.([wl])", operand, re.I)
    if direct:
        width = 4 if direct.group(2).lower() == "w" else 8
        address = int(direct.group(1), 0) & ((1 << (width * 4)) - 1)
        if width == 4 and address >= 0x8000:
            return f"({address - 0x10000}).w"
        return f"(${address:0{width}X}).{direct.group(2).lower()}"
    indirect = re.fullmatch(r"\(([Aa][0-7]|SP)\)(\+)?", operand, re.I)
    if indirect:
        return f"({indirect.group(1).lower()}){indirect.group(2) or ''}"
    predecrement = re.fullmatch(r"-\(([Aa][0-7]|SP)\)", operand, re.I)
    if predecrement:
        return f"-({predecrement.group(1).lower()})"
    displacement = re.fullmatch(r"\((-?0x[0-9a-f]+),([Aa][0-7]|SP)\)", operand, re.I)
    if displacement:
        value = int(displacement.group(1), 0)
        if value == 0:
            return f"0.w({displacement.group(2).lower()})"
        return f"{value}({displacement.group(2).lower()})"
    indexed = re.fullmatch(
        r"\((-?0x[0-9a-f]+),([Aa][0-7]|SP),([DA][0-7])([wl])\*0x1\)",
        operand,
        re.I,
    )
    if indexed:
        value = int(indexed.group(1), 0)
        prefix = "" if value == 0 else str(value)
        return (
            f"{prefix}({indexed.group(2).lower()},"
            f"{indexed.group(3).lower()}.{indexed.group(4).lower()})"
        )
    pc_indexed = re.fullmatch(
        r"\((0x[0-9a-f]+),PC,([DA][0-7])([wl])\*0x1\)", operand, re.I
    )
    if pc_indexed and fact is not None:
        indexed_target = pc_indexed_target(fact)
        if indexed_target is not None:
            target = indexed_target[0]
            return (
                f"{_target_expression(target, primary or {}, 6)}"
                f"(pc,{pc_indexed.group(2).lower()}."
                f"{pc_indexed.group(3).lower()})"
            )
    pc_displacement = re.fullmatch(r"\((-?0x[0-9a-f]+),PC\)", operand, re.I)
    if pc_displacement and fact is not None:
        target = pc_displacement_target(fact)
        if target is not None:
            return f"{_target_expression(target, primary or {}, 6)}(pc)"
    return None


def _movem_registers(operand: str, *, predecrement: bool, mask: int) -> str | None:
    if not re.fullmatch(r"\{\s*(?:[DA][0-7][bwl]?\s*)+\}", operand, re.I):
        return None
    names = re.findall(r"([DA])([0-7])(?:[bwl])?", operand, re.I)
    indices = sorted({(0 if kind.upper() == "D" else 8) + int(index)
                      for kind, index in names})
    if len(indices) != len(names):
        return None
    expected = sum(1 << (15 - index if predecrement else index) for index in indices)
    if expected != mask:
        return None
    groups = []
    start = previous = indices[0]
    for index in indices[1:] + [32]:
        if index == previous + 1 and index != 8:
            previous = index
            continue
        left = f"{'d' if start < 8 else 'a'}{start % 8}"
        right = f"{'d' if previous < 8 else 'a'}{previous % 8}"
        groups.append(left if start == previous else f"{left}-{right}")
        start = previous = index
    return "/".join(groups)


def _asm_instruction(
    fact: InstructionFact,
    primary: dict[int, TechnicalSymbol] | None = None,
) -> str | None:
    """Render ROM-derived instruction candidates; project build proves encoding."""
    byte_immediate_mnemonics = {
        "MOVE.B", "ORI.B", "ANDI.B", "SUBI.B", "ADDI.B", "EORI.B", "CMPI.B",
        "BTST.B", "BTST.L", "BCHG.B", "BCHG.L", "BCLR.B", "BCLR.L",
        "BSET.B", "BSET.L",
    }
    if (fact.mnemonic.upper() in byte_immediate_mnemonics
            and fact.operands.lstrip().startswith("#")
            and len(fact.raw) >= 4 and fact.raw[2] != 0):
        # The 68000 ignores the upper byte of these immediate extension words.
        # Assemblers canonicalize it to zero, so preserve unusual ROM encodings
        # as data to keep rebuilds byte exact.
        return None
    if (fact.mnemonic.upper().startswith(("BTST.", "BCHG.", "BCLR.", "BSET."))
            and fact.operands.lstrip().startswith("#") and len(fact.raw) >= 4):
        bit_limit = 32 if int.from_bytes(fact.raw[:2], "big") & 0x38 == 0 else 8
        if int.from_bytes(fact.raw[2:4], "big") >= bit_limit:
            # AS reduces an out-of-range immediate bit number modulo the
            # operand width. Its otherwise equivalent instruction changes bytes.
            return None
    if (fact.mnemonic.upper().split(".", 1)[0] in AMBIGUOUS_IMMEDIATE_BASES
            and len(fact.raw) >= 2
            and (int.from_bytes(fact.raw[:2], "big") & 0x3F == 0x3C
                 or fact.operands.lstrip().startswith("#"))):
        # Ea-form immediates such as D07C (add.w #imm,d0) have ADDI/SUBI/
        # CMPI/ANDI/ORI twins that assemblers prefer, so keep exact bytes.
        return None
    opcode = SIMPLE_OPCODES.get(fact.mnemonic.upper())
    if opcode is not None and not fact.operands and fact.raw == opcode:
        return fact.mnemonic.lower()
    if fact.mnemonic.upper() == "MOVEQ" and len(fact.raw) == 2:
        match = re.fullmatch(r"(?:#)?(-?0x[0-9a-f]+|-?\d+)\|D([0-7])", fact.operands, re.I)
        if match:
            value = int(match.group(1), 0) & 0xFF
            register = int(match.group(2))
            encoded = 0x7000 | register << 9 | value
            if fact.raw == encoded.to_bytes(2, "big"):
                signed = value if value < 0x80 else value - 0x100
                return f"moveq #{signed},d{register}"
    if fact.mnemonic.upper() == "TRAP" and len(fact.raw) == 2:
        vector = fact.raw[1] & 0xF
        if fact.raw == bytes((0x4E, 0x40 | vector)):
            return f"trap #{vector}"
    if (fact.mnemonic.upper() == "MOVE" and len(fact.raw) == 4
            and fact.raw[:2] == b"\x44\xfc"):
        value = int.from_bytes(fact.raw[2:], "big")
        if fact.operands.lower() == f"#0x{value:x}":
            return f"move #{value},ccr"
    if len(fact.raw) == 4:
        opcode = int.from_bytes(fact.raw[:2], "big")
        if opcode in (0x4EBA, 0x4EFA):
            mnemonic = "jsr" if opcode == 0x4EBA else "jmp"
            displacement = int.from_bytes(fact.raw[2:], "big", signed=True)
            target = (fact.cpu_address + 2 + displacement) & 0xFFFFFF
            operand = re.fullmatch(r"0x[0-9a-f]+", fact.operands.strip(), re.I)
            if (fact.mnemonic.lower() == mnemonic and operand is not None
                    and int(operand.group(), 16) == target):
                return f"{mnemonic} {_target_expression(target, primary or {}, 6)}(pc)"
            return None
        status_immediates = {
            0x003C: ("ori", "ccr"), 0x007C: ("ori", "sr"),
            0x023C: ("andi", "ccr"), 0x027C: ("andi", "sr"),
            0x0A3C: ("eori", "ccr"), 0x0A7C: ("eori", "sr"),
        }
        if opcode in status_immediates:
            mnemonic, register = status_immediates[opcode]
            value = int.from_bytes(fact.raw[2:], "big")
            match = re.fullmatch(
                r"#(-?0x[0-9a-f]+|-?\d+)(?:\|(SR|CCR))?",
                fact.operands, re.I,
            )
            mask = 0xFF if register == "ccr" else 0xFFFF
            if (fact.mnemonic.lower() == mnemonic and match is not None
                    and value <= mask
                    and int(match.group(1), 0) & mask == value
                    and (match.group(2) is None
                         or match.group(2).lower() == register)):
                return f"{mnemonic} #${value:X},{register}"
            return None
        if opcode == 0x4E72 and fact.mnemonic.upper() == "STOP":
            value = int.from_bytes(fact.raw[2:], "big")
            match = re.fullmatch(r"#(-?0x[0-9a-f]+|-?\d+)", fact.operands, re.I)
            if match is not None and int(match.group(1), 0) & 0xFFFF == value:
                return f"stop #${value:X}"
    if len(fact.raw) in (2, 4) and 0x60 <= fact.raw[0] <= 0x6F:
        condition = (
            "bra", "bsr", "bhi", "bls", "bcc", "bcs", "bne", "beq",
            "bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble",
        )[fact.raw[0] & 0xF]
        if len(fact.raw) == 2 and fact.raw[1] != 0:
            displacement = int.from_bytes(fact.raw[1:], "big", signed=True)
            suffix = "s"
        elif len(fact.raw) == 4 and fact.raw[1] == 0:
            displacement = int.from_bytes(fact.raw[2:], "big", signed=True)
            suffix = "w"
        else:
            return None
        target = (fact.cpu_address + 2 + displacement) & 0xFFFFFF
        if fact.mnemonic.upper() == f"{condition.upper()}.{ 'B' if suffix == 's' else 'W'}":
            return f"{condition}.{suffix} {_target_expression(target, primary or {}, 6)}"
    db_names = ("DBT", "DBF", "DBHI", "DBLS", "DBCC", "DBCS", "DBNE", "DBEQ",
                "DBVC", "DBVS", "DBPL", "DBMI", "DBGE", "DBLT", "DBGT", "DBLE")
    if (len(fact.raw) == 4 and 0x50 <= fact.raw[0] <= 0x5F
            and 0xC8 <= fact.raw[1] <= 0xCF
            and fact.mnemonic.upper() == db_names[fact.raw[0] & 0xF]):
        register = fact.raw[1] & 7
        displacement = int.from_bytes(fact.raw[2:], "big", signed=True)
        target = (fact.cpu_address + 2 + displacement) & 0xFFFFFF
        return (
            f"{fact.mnemonic.lower()} d{register},"
            f"{_target_expression(target, primary or {}, 6)}"
        )
    indexed = pc_indexed_jsr_target(fact)
    if indexed is not None and primary is not None:
        target, register = indexed
        symbol = primary.get(target)
        if symbol is not None and symbol.kind == "table":
            return f"jsr {symbol.name}(pc,d{register}.w)"
    if fact.mnemonic.upper() == "LEA" and len(fact.raw) == 4 and primary is not None:
        opcode = int.from_bytes(fact.raw[:2], "big")
        match = re.fullmatch(r"\((-?0x[0-9a-f]+),PC\)\|A([0-7])", fact.operands, re.I)
        if match is not None and opcode & 0xF1FF == 0x41FA:
            register = (opcode >> 9) & 7
            displacement = int.from_bytes(fact.raw[2:], "big", signed=True)
            target = (fact.cpu_address + 2 + displacement) & 0xFFFFFF
            symbol = primary.get(target)
            if (register == int(match.group(2))
                    and displacement == int(match.group(1), 0)
                    and symbol is not None):
                return f"lea {symbol.name}(pc),a{register}"
    if fact.mnemonic.upper() in ("MOVEM.W", "MOVEM.L") and len(fact.raw) >= 4:
        operands = fact.operands.split("|")
        if len(operands) == 2:
            set_index = 0 if operands[0].lstrip().startswith("{") else 1
            ea_mode = int.from_bytes(fact.raw[:2], "big") & 0x38
            if (set_index == 1 and ea_mode == 0x20
                    or set_index == 0 and ea_mode == 0x18):
                # MOVEM loads permit postincrement; stores permit predecrement.
                return None
            address = _m68k_operand(
                operands[1 - set_index], fact=fact, primary=primary
            )
            if address is not None:
                registers = _movem_registers(
                    operands[set_index],
                    predecrement=set_index == 0 and address.startswith("-("),
                    mask=int.from_bytes(fact.raw[2:4], "big"),
                )
                if registers is not None:
                    ordered = (registers, address) if set_index == 0 else (address, registers)
                    return fact.mnemonic.lower() + " " + ",".join(ordered)
    allowed = {
        "MOVE", "MOVE.B", "MOVE.W", "MOVE.L", "MOVEA.W", "MOVEA.L",
        "LEA", "CLR.B", "CLR.W", "CLR.L", "TST.B", "TST.W", "TST.L",
        "ADD.B", "ADD.W", "ADD.L", "ADDA.W", "ADDA.L",
        "SUB.B", "SUB.W", "SUB.L", "SUBA.W", "SUBA.L",
        "CMP.B", "CMP.W", "CMP.L", "CMPA.W", "CMPA.L",
        "CMPM.B", "CMPM.W", "CMPM.L",
        "AND.B", "AND.W", "AND.L", "EOR.B", "EOR.W", "EOR.L",
        "OR.B", "OR.W", "OR.L", "ADDI.B", "ADDI.W", "ADDI.L",
        "SUBI.B", "SUBI.W", "SUBI.L", "ANDI.B", "ANDI.W", "ANDI.L",
        "ORI.B", "ORI.W", "ORI.L", "EORI.B", "EORI.W", "EORI.L",
        "CMPI.B", "CMPI.W", "CMPI.L",
        "ADDQ.B", "ADDQ.W", "ADDQ.L", "SUBQ.B", "SUBQ.W", "SUBQ.L",
        "LSL.B", "LSL.W", "LSL.L", "LSR.B", "LSR.W", "LSR.L",
        "ASL.B", "ASL.W", "ASL.L", "ASR.B", "ASR.W", "ASR.L",
        "ROL.B", "ROL.W", "ROL.L", "ROR.B", "ROR.W", "ROR.L",
        "ROXL.B", "ROXL.W", "ROXL.L", "ROXR.B", "ROXR.W", "ROXR.L",
        "SWAP", "NEG.B", "NEG.W", "NEG.L", "NOT.B", "NOT.W", "NOT.L",
        "NEGX.B", "NEGX.W", "NEGX.L", "NBCD", "EXG", "PEA", "LINK", "UNLK",
        "ADDX.B", "ADDX.W", "ADDX.L", "SUBX.B", "SUBX.W", "SUBX.L",
        "ASL", "ASR", "LSL", "LSR", "ROL", "ROR", "ROXL", "ROXR",
        "ABCD", "SBCD", "MULU.W", "MULS.W", "DIVU.W", "DIVS.W",
        "ST", "SF", "SHI", "SLS", "SCC", "SCS", "SNE", "SEQ",
        "SVC", "SVS", "SPL", "SMI", "SGE", "SLT", "SGT", "SLE",
        "EXT.W", "EXT.L", "BTST.B", "BTST.L", "BSET.B", "BSET.L",
        "BCLR.B", "BCLR.L", "BCHG.B", "BCHG.L", "JSR", "JMP",
    }
    if fact.mnemonic.upper() in allowed:
        opcode = int.from_bytes(fact.raw[:2], "big")
        if fact.mnemonic.upper().startswith("TST.") and opcode & 0x38 == 0x08:
            return None  # Address-register TST is a 68020+ form.
        if (fact.mnemonic.upper().startswith(("MULU.", "MULS.", "DIVU.", "DIVS."))
                and opcode & 0x38 == 0x08):
            # The 68000 data-EA forms do not accept address-register direct.
            return None
        if opcode & 0xF0C0 == 0xE0C0 and (
                opcode & 0x38 in {0, 8} or opcode & 0x3F >= 0x3A):
            # Memory shifts require an alterable memory EA, excluding PC.
            return None
        has_ea = opcode & 0xF000 != 0xE000 or opcode & 0xC0 == 0xC0
        indexed_eas = int(has_ea and (opcode & 0x38 == 0x30 or opcode & 0x3F == 0x3B))
        if fact.mnemonic.upper().startswith(("MOVE.", "MOVEA.")):
            indexed_eas += int(opcode >> 6 & 7 == 6)
        described_indices = len(re.findall(r",[DA][0-7][wl]\*0x[1248]\)", fact.operands, re.I))
        if indexed_eas > described_indices:
            # Ghidra can decode a 68020 full extension while analysing 68000
            # data and describe it as a plain displacement. Rendering that EA
            # would shorten the instruction and shift the rest of the ROM.
            return None
        operands = fact.operands.split("|") if fact.operands else []
        if fact.mnemonic.upper() == "MOVE" and len(operands) != 2:
            return None
        if (operands and operands[-1].strip().startswith("#")
                and fact.mnemonic.upper() != "LINK"):
            # None of the generic forms accepts an immediate destination.
            return None
        if fact.mnemonic.upper().endswith(".B") and any(
            re.fullmatch(r"(?:A[0-7][bwl]?|SP)", operand.strip(), re.I)
            for operand in operands
        ):
            # Address registers have no byte-sized direct operand on 68000.
            return None
        if fact.mnemonic.upper().startswith(("ADDQ.", "SUBQ.")) and operands:
            operands[0] = "#" + operands[0].lstrip("#")
        converted = [
            _m68k_operand(operand, fact=fact, primary=primary)
            for operand in operands
        ]
        if (len(converted) in (1, 2) and all(part is not None for part in converted)):
            mnemonic = fact.mnemonic.lower()
            if mnemonic.startswith(("btst.", "bset.", "bclr.", "bchg.")):
                mnemonic = mnemonic.split(".", 1)[0]
            return mnemonic + " " + ",".join(converted)
    return None


def _symbol_maps(
    symbols: tuple[TechnicalSymbol, ...],
    facts: dict[int, InstructionFact] | None = None,
) -> tuple[dict[int, TechnicalSymbol], dict[int, tuple[str, ...]]]:
    instruction_interiors = {
        address
        for fact in (facts or {}).values()
        for address in range(fact.cpu_address + 1, fact.cpu_address + fact.length)
    }
    primary = {
        symbol.logical_address: symbol
        for symbol in symbols
        if (symbol.cpu_id == "m68k"
            and symbol.logical_address not in instruction_interiors)
    }
    aliases = {
        address: tuple(alias for alias in symbol.aliases if alias != symbol.name)
        for address, symbol in primary.items()
    }
    return primary, aliases


def _emit_labels(
    lines: list[str],
    logical_address: int,
    primary: dict[int, TechnicalSymbol],
    aliases: dict[int, tuple[str, ...]],
) -> None:
    symbol = primary.get(logical_address)
    if symbol is None:
        return
    lines.append(f"{symbol.name}:")
    lines.extend(f"{alias}:" for alias in aliases.get(logical_address, ()))


def _target_expression(
    address: int, primary: dict[int, TechnicalSymbol], width: int
) -> str:
    symbol = primary.get(address)
    if symbol is not None:
        return symbol.name
    return f"${address:0{width}X}"


def _pointer_lines(
    candidate: PointerCandidate,
    image: MegaDriveImage,
    primary: dict[int, TechnicalSymbol],
) -> list[str]:
    lines = [f"{M68K_INDENT}; {candidate.schema_id}"]
    table = _target_expression(candidate.logical_start, primary, 6)
    if candidate.schema_id == "megadrive.counted-u16be.absolute":
        count_word = len(candidate.entries) - 1
        encoded_count = count_word.to_bytes(2, "big")
        original_count = image.data[
            candidate.physical_start:candidate.physical_start + 2
        ]
        if encoded_count != original_count:
            raise MegaDriveEmitError(
                f"counted pointer header changes bytes at "
                f"{candidate.physical_start:#x}"
            )
        lines.append(f"{M68K_INDENT}dc.w    ${count_word:X}")
    elif candidate.schema_id == "megadrive.counted-u16be.ram-copy-offset":
        header = image.data[
            candidate.physical_start:candidate.physical_start + 2
        ]
        if len(header) != 2 or header[0] != len(candidate.entries):
            raise MegaDriveEmitError(
                f"animation count header disagrees at "
                f"{candidate.physical_start:#x}"
            )
        lines.append(
            f"{M68K_INDENT}dc.b    ${header[0]:02X}, ${header[1]:02X}"
        )
    for entry in candidate.entries:
        target = _target_expression(entry.target, primary, 6)
        if candidate.schema_id == "megadrive.u32be.absolute":
            lines.append(f"{M68K_INDENT}dc.l    {target}")
            encoded = entry.target.to_bytes(4, "big")
        elif candidate.schema_id in {
            "megadrive.u16be.absolute",
            "megadrive.counted-u16be.absolute",
        }:
            lines.append(f"{M68K_INDENT}dc.w    {target}")
            encoded = entry.target.to_bytes(2, "big")
        elif candidate.schema_id == "megadrive.s16be.target-table_base":
            lines.append(f"{M68K_INDENT}dc.w    {target}-{table}")
            encoded = ((entry.target - candidate.logical_start) & 0xFFFF).to_bytes(
                2, "big"
            )
        elif candidate.schema_id == "megadrive.s16be.target-entry_address":
            lines.append(f"{M68K_INDENT}dc.w    {target}-*")
            encoded = ((entry.target - entry.logical_address) & 0xFFFF).to_bytes(
                2, "big"
            )
        elif candidate.schema_id in {
            "megadrive.counted-u16be.ram-copy-offset",
            "megadrive.s16be.target-code_base",
        }:
            if entry.base_address is None:
                raise MegaDriveEmitError("relative pointer is missing its ROM base")
            base = _target_expression(entry.base_address, primary, 6)
            lines.append(f"{M68K_INDENT}dc.w    {target}-{base}")
            encoded = ((entry.target - entry.base_address) & 0xFFFF).to_bytes(
                2, "big"
            )
        else:
            raise MegaDriveEmitError(
                f"unsupported accepted pointer schema: {candidate.schema_id}"
            )
        original = image.data[
            entry.physical_offset:entry.physical_offset + candidate.entry_size
        ]
        if encoded != original:
            raise MegaDriveEmitError(
                f"pointer expression changes bytes at {entry.physical_offset:#x}"
            )
    return lines


def _standard_boot_setup_lines(
    setup: StandardBootSetup,
    image: MegaDriveImage,
) -> list[str]:
    offset = setup.physical_start
    lines: list[str] = []

    for _ in range(3):
        value = int.from_bytes(image.data[offset:offset + 2], "big")
        lines.append(f"{M68K_INDENT}dc.w    ${value:X}")
        offset += 2
    for _ in range(5):
        value = int.from_bytes(image.data[offset:offset + 4], "big")
        lines.append(f"{M68K_INDENT}dc.l    Io_{value:06X}")
        offset += 4

    def emit_bytes(size: int) -> None:
        nonlocal offset
        end = offset + size
        while offset < end:
            next_offset = min(offset + 8, end)
            lines.append(
                f"{M68K_INDENT}dc.b    {_hex_bytes(image.data[offset:next_offset])}"
            )
            offset = next_offset

    def emit_longs(count: int) -> None:
        nonlocal offset
        for _ in range(count):
            value = int.from_bytes(image.data[offset:offset + 4], "big")
            lines.append(f"{M68K_INDENT}dc.l    ${value:08X}")
            offset += 4

    emit_bytes(24)
    emit_longs(1)
    emit_bytes(38)
    emit_longs(3)
    emit_bytes(4)
    if offset != setup.physical_end:
        raise MegaDriveEmitError("standard boot setup layout has the wrong size")
    return lines


def _selected_tables(
    candidates: tuple[PointerCandidate, ...],
    assets: tuple[tuple[int, int], ...],
) -> dict[int, PointerCandidate]:
    selected: dict[int, PointerCandidate] = {}
    occupied: set[int] = set()
    for candidate in sorted(
        candidates,
        key=lambda item: (-item.score, item.physical_start, -item.entry_size),
    ):
        if candidate.status != "accepted" or candidate.physical_start < 0x200:
            continue
        byte_range = set(range(candidate.physical_start, candidate.physical_end))
        if any(
            candidate.physical_start < end and start < candidate.physical_end
            for start, end in assets
        ):
            continue
        if occupied & byte_range:
            continue
        selected[candidate.physical_start] = candidate
        occupied.update(byte_range)
    return selected


def _opaque_include_ranges(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    tables: dict[int, PointerCandidate],
    asset_ranges: dict[int, tuple[int, str]],
    primary: dict[int, TechnicalSymbol],
) -> tuple[tuple[int, int], ...]:
    """Select large evidence-free ROM spans for reversible binary includes."""
    blocked = bytearray(len(image.data))

    def mark(start: int, end: int) -> None:
        start = max(0x200, start)
        end = min(len(blocked), end)
        if start < end:
            blocked[start:end] = b"\x01" * (end - start)

    for start, fact in facts.items():
        mark(start, start + fact.length)
    for table in tables.values():
        mark(table.physical_start, table.physical_end)
    for start, (size, _) in asset_ranges.items():
        mark(start, start + size)
    for match in re.finditer(
        bytes([0xFF]) + f"{{{FF_ORG_MIN_BYTES},}}".encode("ascii"),
        image.data[0x200:],
    ):
        mark(0x200 + match.start(), 0x200 + match.end())

    boundaries = {0x200, len(image.data)}
    boundaries.update(range(MODULE_SIZE, len(image.data), MODULE_SIZE))
    for address in primary:
        offset = address - image.header.rom_start
        if 0x200 < offset < len(image.data):
            boundaries.add(offset)

    selected: list[tuple[int, int]] = []
    start: int | None = None
    for offset in range(0x200, len(image.data) + 1):
        unavailable = offset == len(image.data) or bool(blocked[offset])
        if start is not None and (offset in boundaries or unavailable):
            if offset - start >= OPAQUE_INCLUDE_MIN_BYTES:
                selected.append((start, offset))
            start = None
        if offset < len(image.data) and not blocked[offset] and start is None:
            start = offset
    return tuple(selected)


def _z80_one_byte_asm(raw: bytes) -> str | None:
    if len(raw) != 1:
        return None
    opcode = raw[0]
    simple = {
        0x00: "nop", 0x07: "rlca", 0x08: "ex af,af'", 0x0F: "rrca",
        0x17: "rla", 0x1F: "rra", 0x27: "daa", 0x2F: "cpl",
        0x37: "scf", 0x3F: "ccf", 0x76: "halt", 0xC9: "ret",
        0xD9: "exx", 0xE9: "jp (hl)", 0xEB: "ex de,hl",
        0xF3: "di", 0xF9: "ld sp,hl", 0xFB: "ei",
        0x02: "ld (bc),a", 0x12: "ld (de),a",
        0x0A: "ld a,(bc)", 0x1A: "ld a,(de)",
    }
    if opcode in simple:
        return simple[opcode]
    registers = ("b", "c", "d", "e", "h", "l", "(hl)", "a")
    pairs = ("bc", "de", "hl", "sp")
    if 0x40 <= opcode <= 0x7F:
        return f"ld {registers[(opcode >> 3) & 7]},{registers[opcode & 7]}"
    if 0x80 <= opcode <= 0xBF:
        register = registers[opcode & 7]
        operations = ("add a,", "adc a,", "sub ", "sbc a,",
                      "and ", "xor ", "or ", "cp ")
        return operations[(opcode - 0x80) >> 3] + register
    for index, register in enumerate(registers):
        if opcode == 0x04 + index * 8:
            return f"inc {register}"
        if opcode == 0x05 + index * 8:
            return f"dec {register}"
    for index, pair in enumerate(pairs):
        if opcode == 0x03 + index * 0x10:
            return f"inc {pair}"
        if opcode == 0x0B + index * 0x10:
            return f"dec {pair}"
        if opcode == 0x09 + index * 0x10:
            return f"add hl,{pair}"
    stack_pairs = ("bc", "de", "hl", "af")
    for index, pair in enumerate(stack_pairs):
        if opcode == 0xC1 + index * 0x10:
            return f"pop {pair}"
        if opcode == 0xC5 + index * 0x10:
            return f"push {pair}"
    conditions = ("nz", "z", "nc", "c", "po", "pe", "p", "m")
    for index, condition in enumerate(conditions):
        if opcode == 0xC0 + index * 8:
            return f"ret {condition}"
        if opcode == 0xC7 + index * 8:
            return f"rst {index * 8}"
    return None


def _z80_asm(raw: bytes, address: int) -> str | None:
    """Decode unambiguous Z80 encodings without consulting reference source."""
    one_byte = _z80_one_byte_asm(raw)
    if one_byte is not None:
        return one_byte
    registers = ("b", "c", "d", "e", "h", "l", "(hl)", "a")
    pairs = ("bc", "de", "hl", "sp")
    conditions = ("nz", "z", "nc", "c", "po", "pe", "p", "m")
    if len(raw) == 2:
        opcode, value = raw
        if opcode in (0xDD, 0xFD):
            index = "ix" if opcode == 0xDD else "iy"
            if value in (0x23, 0x2B):
                return f"{'inc' if value == 0x23 else 'dec'} {index}"
            if value in (0x09, 0x19, 0x29, 0x39):
                pair = ("bc", "de", index, "sp")[(value >> 4) & 3]
                return f"add {index},{pair}"
        if opcode in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
            target = (address + 2 + int.from_bytes(raw[1:], "little", signed=True)) & 0xFFFF
            if opcode == 0x10:
                return f"djnz ${target:04X}"
            if opcode == 0x18:
                return f"jr ${target:04X}"
            return f"jr {conditions[(opcode - 0x20) // 8]},${target:04X}"
        if (opcode & 0xC7) == 0x06:
            return f"ld {registers[(opcode >> 3) & 7]},${value:02X}"
        immediate = {
            0xC6: "add a,", 0xCE: "adc a,", 0xD6: "sub ",
            0xDE: "sbc a,", 0xE6: "and ", 0xEE: "xor ",
            0xF6: "or ", 0xFE: "cp ",
        }
        if opcode in immediate:
            return f"{immediate[opcode]}${value:02X}"
        if opcode == 0xCB:
            register = registers[value & 7]
            if value < 0x40:
                operation = ("rlc", "rrc", "rl", "rr", "sla", "sra", "sll", "srl")[value >> 3]
                return f"{operation} {register}"
            operation = ("bit", "res", "set")[(value >> 6) - 1]
            return f"{operation} {(value >> 3) & 7},{register}"
        if opcode == 0xED:
            simple = {0x44: "neg", 0x56: "im 1", 0x5F: "ld a,r",
                      0xA0: "ldi", 0xB0: "ldir"}
            if value in simple:
                return simple[value]
            if value in (0x42, 0x52, 0x62, 0x72):
                return f"sbc hl,{pairs[(value - 0x42) // 0x10]}"
    if len(raw) == 3:
        opcode = raw[0]
        value = int.from_bytes(raw[1:], "little")
        if (opcode & 0xCF) == 0x01:
            return f"ld {pairs[(opcode >> 4) & 3]},${value:04X}"
        memory_moves = {0x22: f"ld (${value:04X}),hl", 0x2A: f"ld hl,(${value:04X})",
                        0x32: f"ld (${value:04X}),a", 0x3A: f"ld a,(${value:04X})"}
        if opcode in memory_moves:
            return memory_moves[opcode]
        if opcode in (0xC3, 0xCD):
            return f"{'jp' if opcode == 0xC3 else 'call'} ${value:04X}"
        if (opcode & 0xC7) in (0xC2, 0xC4):
            operation = "jp" if (opcode & 0xC7) == 0xC2 else "call"
            return f"{operation} {conditions[(opcode >> 3) & 7]},${value:04X}"
        if opcode in (0xDD, 0xFD):
            index = "ix" if opcode == 0xDD else "iy"
            subcode, displacement = raw[1], raw[2]
            signed = displacement if displacement < 128 else displacement - 256
            indexed = f"({index}{signed:+d})"
            if subcode == 0x21:
                return None
            if subcode in (0x46, 0x4E, 0x56, 0x5E, 0x66, 0x6E, 0x7E):
                return f"ld {registers[(subcode >> 3) & 7]},{indexed}"
            if 0x70 <= subcode <= 0x77 and subcode != 0x76:
                return f"ld {indexed},{registers[subcode & 7]}"
            if subcode in (0x34, 0x35):
                return f"{'inc' if subcode == 0x34 else 'dec'} {indexed}"
            indexed_alu = {0x86: "add a,", 0x8E: "adc a,", 0x96: "sub ",
                           0x9E: "sbc a,", 0xA6: "and ", 0xAE: "xor ",
                           0xB6: "or ", 0xBE: "cp "}
            if subcode in indexed_alu:
                return indexed_alu[subcode] + indexed
    if len(raw) == 4 and raw[0] == 0xED:
        opcode = raw[1]
        value = int.from_bytes(raw[2:], "little")
        # ED63/ED6B alias the shorter LD (nn),HL / LD HL,(nn) encodings.
        # Assemblers prefer 22/2A, so those aliases must retain their raw bytes.
        if opcode in (0x43, 0x53, 0x73):
            return f"ld (${value:04X}),{pairs[(opcode >> 4) & 3]}"
        if opcode in (0x4B, 0x5B, 0x7B):
            return f"ld {pairs[(opcode >> 4) & 3]},(${value:04X})"
    if len(raw) == 4 and raw[0] in (0xDD, 0xFD):
        index = "ix" if raw[0] == 0xDD else "iy"
        subcode = raw[1]
        value = int.from_bytes(raw[2:], "little")
        if subcode == 0x21:
            return f"ld {index},${value:04X}"
        if subcode == 0x22:
            return f"ld (${value:04X}),{index}"
        if subcode == 0x2A:
            return f"ld {index},(${value:04X})"
        if subcode == 0x36:
            signed = raw[2] if raw[2] < 128 else raw[2] - 256
            return f"ld ({index}{signed:+d}),${raw[3]:02X}"
        if subcode == 0xCB:
            signed = raw[2] if raw[2] < 128 else raw[2] - 256
            opcode = raw[3]
            if 0x40 <= opcode <= 0xFF and opcode & 7 == 6:
                operation = ("bit", "res", "set")[(opcode >> 6) - 1]
                return f"{operation} {(opcode >> 3) & 7},({index}{signed:+d})"
    return None


def _emit_z80_source(
    path: Path,
    payload: bytes,
    facts: dict[int, InstructionFact],
    *,
    base_address: int = 0,
    dispatch_tables: tuple[Z80DispatchTable, ...] = (),
) -> None:
    occupied: set[int] = set()
    interiors: set[int] = set()
    for start, fact in facts.items():
        occupied.update(range(start, start + fact.length))
        interiors.update(range(start + 1, start + fact.length))
    tables: dict[int, int] = {}
    for table in dispatch_tables:
        start = table.logical_start - base_address
        end = table.logical_end - base_address
        span = set(range(start, end))
        if (not 0 <= start < end <= len(payload) or (end - start) % 2
                or span & occupied):
            raise MegaDriveEmitError(
                f"Z80 dispatch table ${table.logical_start:04X} does not fit "
                "between instructions"
            )
        tables[start] = end
        occupied.update(span)
        interiors.update(range(start + 1, end))
    # Only words read from the payload are emitted, so labels always
    # reassemble to the original little-endian bytes.
    labels: dict[int, str] = {}
    for start, end in tables.items():
        labels[start] = f"Z80_Table_{base_address + start:04X}"
        for entry in range(start, end, 2):
            target = int.from_bytes(payload[entry:entry + 2], "little")
            offset = target - base_address
            if 0 <= offset < len(payload) and offset not in interiors:
                labels.setdefault(offset, f"Z80_Loc_{target:04X}")

    lines = ["    cpu z80", "    page 0", "    org 0"]
    if base_address:
        # p2bin writes from physical zero. ORG base_address would insert an
        # address-sized prefix into the fragment included in the M68K ROM.
        lines.append(f"    phase {base_address}")
    lines += ["", "Z80_Entry:" if base_address == 0 else f"Z80_Payload_{base_address:04X}:"]
    offset = 0
    while offset < len(payload):
        if offset in labels:
            lines.append(f"{labels[offset]}:")
        table_end = tables.get(offset)
        if table_end is not None:
            for entry in range(offset, table_end, 2):
                value = int.from_bytes(payload[entry:entry + 2], "little")
                target = labels.get(value - base_address)
                lines.append(f"    dw {target if target is not None else value}")
            offset = table_end
            continue
        fact = facts.get(offset)
        if fact is not None:
            if payload[offset:offset + fact.length] != fact.raw:
                raise MegaDriveEmitError(f"Z80 fact disagrees with payload at {offset:#x}")
            asm = _z80_asm(fact.raw, base_address + offset)
            if asm is not None:
                asm = re.sub(r"\$([0-9A-F]+)", lambda match: str(int(match.group(1), 16)), asm)
                lines.append(f"    {asm}")
            else:
                lines.append(
                    f"    db {', '.join(str(value) for value in fact.raw)}"
                    f"    ; {fact.mnemonic} {fact.operands}".rstrip()
                )
            offset += fact.length
        else:
            next_fact = min(
                (start for start in (*facts, *tables, *labels) if start > offset),
                default=len(payload),
            )
            limit = min(offset + 16, next_fact, len(payload))
            lines.append(f"    db {', '.join(str(value) for value in payload[offset:limit])}")
            offset = limit
    if base_address:
        lines += ["", "    dephase"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _emit_payload_module(
    path: Path,
    image: MegaDriveImage,
    start: int,
    limit: int,
    facts: dict[int, InstructionFact],
    tables: dict[int, PointerCandidate],
    boot_setups: dict[int, StandardBootSetup],
    asset_ranges: dict[int, tuple[int, str]],
    primary: dict[int, TechnicalSymbol],
    aliases: dict[int, tuple[str, ...]],
) -> tuple[int, int, int, int, int, int, int]:
    lines = [f"; ROM ${start:06X}..${limit - 1:06X}"]
    instruction_bytes = 0
    symbolic_bytes = 0
    pointer_bytes = 0
    asset_bytes = 0
    raw_bytes = 0
    padding_bytes = 0
    offset = start
    ff_starts = {
        start + match.start()
        for match in re.finditer(
            bytes([0xFF]) + f"{{{FF_ORG_MIN_BYTES},}}".encode("ascii"),
            image.data[start:limit],
        )
    }
    event_offsets = (
        set(facts) | set(tables) | set(boot_setups) | set(asset_ranges)
        | set(primary) | ff_starts
    )
    while offset < limit:
        logical_address = image.header.rom_start + offset
        _emit_labels(lines, logical_address, primary, aliases)
        asset = asset_ranges.get(offset)
        if asset is not None:
            size, asset_path = asset
            lines.append(f'{M68K_INDENT}binclude "{asset_path}"')
            lines.append("")
            asset_bytes += size
            offset += size
            continue
        setup = boot_setups.get(offset)
        if setup is not None:
            lines.extend(_standard_boot_setup_lines(setup, image))
            lines.append("")
            size = setup.physical_end - setup.physical_start
            raw_bytes += size
            offset += size
            continue
        table = tables.get(offset)
        if table is not None:
            lines.extend(_pointer_lines(table, image, primary))
            lines.append("")
            size = table.physical_end - table.physical_start
            pointer_bytes += size
            offset += size
            continue
        instruction = facts.get(offset)
        if instruction is not None:
            if image.data[offset:offset + instruction.length] != instruction.raw:
                raise MegaDriveEmitError(
                    f"instruction facts disagree with ROM at {offset:#x}"
                )
            asm = _asm_instruction(instruction, primary)
            if asm is not None:
                lines.append(f"{M68K_INDENT}{asm}")
                symbolic_bytes += instruction.length
            else:
                lines.append(
                    f"{M68K_INDENT}dc.b    {_hex_bytes(instruction.raw)}"
                    f"    ; {instruction.mnemonic} {instruction.operands}".rstrip()
                )
            instruction_bytes += instruction.length
            offset += instruction.length
            continue

        next_event = min((event for event in event_offsets if offset < event < limit), default=limit)
        if image.data[offset] == 0xFF:
            ff_end = offset
            while ff_end < next_event and image.data[ff_end] == 0xFF:
                ff_end += 1
            if ff_end - offset >= FF_ORG_MIN_BYTES:
                # End with a real byte so p2bin preserves terminal FF padding.
                lines.append(f"{M68K_INDENT}org     ${image.header.rom_start + ff_end - 1:06X}")
                lines.append(f"{M68K_INDENT}dc.b    $FF")
                padding_bytes += ff_end - offset
                offset = ff_end
                continue
        end = min(offset + 16, next_event)
        payload = image.data[offset:end]
        lines.append(f"{M68K_INDENT}dc.b    {_hex_bytes(payload)}")
        raw_bytes += len(payload)
        offset = end
    path.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return (
        offset, instruction_bytes, pointer_bytes, asset_bytes, raw_bytes,
        padding_bytes, symbolic_bytes,
    )


def emit_project(
    root: Path,
    image: MegaDriveImage,
    m68k_facts: dict[int, InstructionFact],
    pointer_candidates: tuple[PointerCandidate, ...],
    symbols: tuple[TechnicalSymbol, ...],
    z80_copies: tuple[CrossCpuCopy, ...],
    z80_programs: tuple[tuple[str, int, dict[int, InstructionFact]], ...] = (),
    z80_dispatch_tables: tuple[tuple[Z80DispatchTable, ...], ...] = (),
) -> EmitResult:
    root.mkdir(parents=True, exist_ok=True)
    source_root = root / "src"
    asset_root = root / "data"
    source_root.mkdir(exist_ok=True)
    asset_root.mkdir(exist_ok=True)
    for stale in asset_root.glob("opaque-*.bin"):
        stale.unlink()
    (source_root / "system").mkdir(exist_ok=True)
    (source_root / "data").mkdir(exist_ok=True)
    (source_root / "memory").mkdir(exist_ok=True)
    primary, aliases = _symbol_maps(symbols, m68k_facts)

    vector_lines = ["; Mega Drive 68000 vector table"]
    for vector in image.vector_table:
        logical_address = image.header.rom_start + vector.index * 4
        _emit_labels(vector_lines, logical_address, primary, aliases)
        vector_lines.append(
            f"{M68K_INDENT}dc.l    ${vector.raw_value:08X}"
            f"    ; {vector.index}: {vector.name} -> ${vector.address:06X}"
        )
    vectors_path = source_root / "system" / "vectors.s"
    vectors_path.write_text(
        "\n".join(vector_lines) + "\n", encoding="utf-8", newline="\n"
    )

    header_asset = asset_root / "header.bin"
    header_asset.write_bytes(image.header_data)
    header_source = source_root / "data" / "header.s"
    header_source.write_text(
        f'{M68K_INDENT}binclude "data/header.bin"\n', encoding="utf-8", newline="\n"
    )
    assets: list[dict[str, object]] = [
        {
            "id": "megadrive.cartridge.header",
            "kind": "container_header",
            "path": "data/header.bin",
            "rom_file_offset": 0x100,
            "size": len(image.header_data),
            "sha256": _sha256(image.header_data),
            "emit": "binclude",
        }
    ]

    asset_ranges: dict[int, tuple[int, str]] = {}
    ranges: list[tuple[int, int]] = []
    z80_builds: list[dict[str, str]] = []
    if z80_copies and len(z80_programs) != len(z80_copies):
        raise MegaDriveEmitError("Z80 source facts are required for every extracted program")
    if z80_dispatch_tables and len(z80_dispatch_tables) != len(z80_copies):
        raise MegaDriveEmitError("Z80 dispatch tables must be given per extracted program")
    for index, copy in enumerate(z80_copies):
        offset = copy.source_start - image.header.rom_start
        payload = image.data[offset:offset + copy.size]
        name = f"z80-program{index:02d}.bin"
        path = asset_root / name
        path.write_bytes(payload)
        relative = f"data/{name}"
        build_relative = f"build/{name}"
        build_path = root / build_relative
        build_path.parent.mkdir(exist_ok=True)
        build_path.write_bytes(payload)
        source_relative = f"src/sound/z80/program{index:02d}.asm"
        _, base_address, z80_facts = z80_programs[index]
        if base_address != copy.target_start:
            raise MegaDriveEmitError("Z80 source base does not match copy destination")
        _emit_z80_source(
            root / source_relative,
            payload,
            z80_facts,
            base_address=base_address,
            dispatch_tables=z80_dispatch_tables[index] if z80_dispatch_tables else (),
        )
        z80_builds.append({
            "source": source_relative,
            "object": f"build/z80-program{index:02d}.p",
            "output": build_relative,
        })
        asset_ranges[offset] = (copy.size, build_relative)
        ranges.append((offset, offset + copy.size))
        assets.append(
            {
                "id": f"megadrive.z80.program{index:02d}",
                "kind": "z80_program",
                "path": relative,
                "rom_file_offset": offset,
                "size": copy.size,
                "sha256": copy.payload_sha256,
                "emit": "binclude",
                "address": {
                    "space": "z80",
                    "start": copy.target_start,
                    "end": copy.target_end,
                },
            }
        )
    tables = _selected_tables(pointer_candidates, tuple(ranges))
    boot_setups = {
        setup.physical_start: setup
        for setup in discover_standard_boot_setups(image, m68k_facts)
    }
    # A label inside a directive that emits several bytes cannot be defined at
    # that address.  Keep references to such addresses numeric as well.
    consumed_interiors = {
        image.header.rom_start + offset
        for start, end in (
            *((table.physical_start, table.physical_end) for table in tables.values()),
            *((setup.physical_start, setup.physical_end) for setup in boot_setups.values()),
            *((start, start + size) for start, (size, _) in asset_ranges.items()),
        )
        for offset in range(start + 1, end)
    }
    primary = {
        address: symbol for address, symbol in primary.items()
        if address not in consumed_interiors
    }
    aliases = {address: names for address, names in aliases.items() if address in primary}
    for start, end in _opaque_include_ranges(
        image, m68k_facts, tables, asset_ranges, primary
    ):
        payload = image.data[start:end]
        name = f"opaque-{start:06x}.bin"
        relative = f"data/{name}"
        (asset_root / name).write_bytes(payload)
        asset_ranges[start] = (len(payload), relative)
        assets.append(
            {
                "id": f"megadrive.opaque.{start:06x}",
                "kind": "opaque_rom",
                "path": relative,
                "rom_file_offset": start,
                "size": len(payload),
                "sha256": _sha256(payload),
                "emit": "binclude",
                "heuristic": {
                    "minimum_size": OPAQUE_INCLUDE_MIN_BYTES,
                    "evidence": "no instructions, pointer tables, assets, or internal symbols",
                },
                "address": {
                    "space": "m68k",
                    "start": image.header.rom_start + start,
                    "end": image.header.rom_start + end - 1,
                },
            }
        )

    source_units = ["src/system/vectors.s", "src/data/header.s"]
    counts = [0, 0, 0, 0, 0, 0]
    offset = 0x200
    while offset < len(image.data):
        nominal_limit = min(
            len(image.data), ((offset // MODULE_SIZE) + 1) * MODULE_SIZE
        )
        name = f"rom-{offset:06x}.s"
        path = source_root / name
        result = _emit_payload_module(
            path,
            image,
            offset,
            nominal_limit,
            m68k_facts,
            tables,
            boot_setups,
            asset_ranges,
            primary,
            aliases,
        )
        offset = result[0]
        counts = [left + right for left, right in zip(counts, result[1:])]
        source_units.append(f"src/{name}")

    main_lines = [
        "; Generated Mega Drive source. ROM address order is significant.",
        f"{M68K_INDENT}cpu     68000",
        f"{M68K_INDENT}page    0",
        f'{M68K_INDENT}include "memory/hardware.inc"',
        f'{M68K_INDENT}include "memory/ram.inc"',
        f"{M68K_INDENT}org     $000000",
        "",
    ]
    main_lines.extend(
        f'{M68K_INDENT}include "{unit.removeprefix("src/")}"' for unit in source_units
    )
    referenced = {
        (reference.address & 0xFFFFFF)
        if 0xFFFF0000 <= reference.address <= 0xFFFFFFFF
        else reference.address
        for fact in m68k_facts.values()
        for reference in fact.references
    }
    hardware = sorted(address for address in referenced if 0xA00000 <= address <= 0xC0001F)
    work_ram = sorted(address for address in referenced if 0xFF0000 <= address <= 0xFFFFFF)
    (source_root / "memory" / "hardware.inc").write_text(
        "; ROM-referenced Mega Drive hardware addresses.\n"
        + "".join(f"Io_{address:06X}: equ ${address:06X}\n" for address in hardware),
        encoding="utf-8", newline="\n",
    )
    (source_root / "memory" / "ram.inc").write_text(
        "; ROM-referenced work RAM addresses. Technical names only.\n"
        + "".join(f"Ram_{address:06X}: equ ${address:06X}\n" for address in work_ram),
        encoding="utf-8", newline="\n",
    )
    (source_root / "main.s").write_text(
        "\n".join(main_lines) + "\n", encoding="utf-8", newline="\n"
    )
    source_units.insert(0, "src/main.s")
    source_units.extend(item["source"] for item in z80_builds)
    covered = 0x100 + len(image.header_data) + sum(counts[:5])
    if covered != len(image.data):
        raise MegaDriveEmitError(
            f"emitter covered {covered} of {len(image.data)} ROM bytes"
        )
    return EmitResult(
        source_units=tuple(source_units),
        assets=tuple(assets),
        z80_builds=tuple(z80_builds),
        instruction_bytes=counts[0],
        pointer_bytes=counts[1],
        asset_bytes=counts[2] + len(image.header_data),
        raw_bytes=counts[3],
        padding_bytes=counts[4],
        symbolic_instruction_bytes=counts[5],
    )
