"""Mega Drive cartridges, Ghidra facts and dispatch images for the tests."""

from __future__ import annotations

from dataclasses import replace

from retrolarium_core.megadrive import cartridge_checksum, parse_megadrive
from retrolarium_disassembler.facts import InstructionFact, InstructionReference


def cartridge(
    *,
    size: int = 0x400,
    declared_end: int | None = None,
    checksum: bool = True,
) -> bytes:
    data = bytearray(size)
    data[0:4] = (0x01000000).to_bytes(4, "big")
    data[4:8] = (0x200).to_bytes(4, "big")
    data[8:12] = (0x01000240).to_bytes(4, "big")
    data[0x100:0x110] = b"SEGA MEGA DRIVE "
    data[0x120:0x150] = b"RETROLARIUM PROBE".ljust(48)
    data[0x150:0x180] = b"RETROLARIUM PROBE".ljust(48)
    data[0x180:0x18E] = b"GM TEST-001-00"
    data[0x190:0x1A0] = b"J".ljust(16)
    data[0x1A0:0x1A4] = (0).to_bytes(4, "big")
    data[0x1A4:0x1A8] = (
        size - 1 if declared_end is None else declared_end
    ).to_bytes(4, "big")
    data[0x1A8:0x1AC] = (0xFF0000).to_bytes(4, "big")
    data[0x1AC:0x1B0] = (0xFFFFFF).to_bytes(4, "big")
    data[0x1F0:0x200] = b"JUE".ljust(16)
    data[0x200:] = bytes(index & 0xFF for index in range(size - 0x200))
    if checksum:
        data[0x18E:0x190] = cartridge_checksum(data).to_bytes(2, "big")
    return bytes(data)


def fact(
    address: int,
    mnemonic: str,
    operands: str,
    *,
    flows: tuple[int, ...] = (),
    references: tuple[InstructionReference, ...] = (),
) -> InstructionFact:
    return InstructionFact(
        physical_offset=address,
        bank=0,
        cpu_address=address,
        length=2,
        raw=b"\0\0",
        mnemonic=mnemonic,
        operands=operands,
        flows=flows,
        flow_type="FALL_THROUGH",
        backend_space="ram",
        backend_block="ROM",
        backend_symbol="",
        backend_function="",
        references=references,
    )


def dispatch_image(*targets: int):
    data = bytearray(cartridge(size=0x800))
    data[0x300:0x320] = bytes(0x20)
    for index, target in enumerate(targets):
        offset = 0x300 + index * 4
        data[offset:offset + 4] = target.to_bytes(4, "big")
    return parse_megadrive(bytes(data))


def dispatch_facts(index_source: str = "D0w|A0") -> dict[int, InstructionFact]:
    index_mnemonic = "MOVEA.W" if index_source.startswith("D") else "LEA"
    items = (
        fact(0x200, index_mnemonic, index_source),
        replace(fact(0x202, "MOVEA.L", "(0x300,A0)|A0"), length=4),
        replace(fact(0x206, "JSR", "(A0)"), flow_type="COMPUTED_CALL"),
        replace(fact(0x208, "RTS", ""), flow_type="TERMINATOR"),
    )
    return {item.physical_offset: item for item in items}


def word_dispatch_image():
    data = bytearray(cartridge(size=0x800))
    targets = (0x340, 0x350, 0x280, 0x360)
    data[0x300:0x308] = b"".join(((target - 0x340) & 0xFFFF).to_bytes(2, "big") for target in targets)
    data[0x308:0x30A] = bytes.fromhex("FF FF")
    for target in targets:
        data[target:target + 2] = bytes.fromhex("4E75")
    items = (
        replace(fact(0x200, "MOVEA.W", "(0x300,PC,D2w*0x1)|A4"), length=4),
        replace(fact(0x204, "ADDA.L", "#0x340|A4"), length=6),
        replace(fact(0x20A, "JMP", "(A4)"), flow_type="COMPUTED_JUMP"),
    )
    return parse_megadrive(bytes(data)), {item.physical_offset: item for item in items}, targets
