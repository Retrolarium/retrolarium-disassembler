#!/usr/bin/env python3
"""Pack the common 65816 probe as a deterministic LoROM or HiROM image."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


ROM_SIZE = 0x20000
LABEL_PATTERN = re.compile(r"^[a-z][a-z]\s+([0-9A-Fa-f]{6})\s+\.(\S+)$")


def labels(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LABEL_PATTERN.match(line.strip())
        if match:
            result[match.group(2)] = int(match.group(1), 16)
    required = {
        "Reset",
        "NativeNmi",
        "NativeIrq",
        "NearSub",
        "FarSub",
        "LocalTarget",
        "Pointer16",
        "Pointer24",
        "PointerSplit",
        "RelativePointers",
        "ApuUpload",
        "ApuUploadLoop",
        "ApuProgram",
        "ApuProgramEnd",
    }
    missing = sorted(required - result.keys())
    if missing:
        raise ValueError(f"linker labels missing: {', '.join(missing)}")
    return result


def checksum(image: bytes) -> int:
    return sum(image) & 0xFFFF


def rom_offset(mapping: str, cpu_address: int) -> int:
    bank = cpu_address >> 16
    address = cpu_address & 0xFFFF
    if bank != 0 or address < 0x8000:
        raise ValueError(f"probe label is outside bank 00 ROM: {cpu_address:06X}")
    if mapping == "lorom":
        return address - 0x8000
    return address


def pack(code: bytes, symbols: dict[str, int], mapping: str) -> bytes:
    image = bytearray([0xFF] * ROM_SIZE)
    start = rom_offset(mapping, symbols["Reset"])
    if start + len(code) > ROM_SIZE:
        raise ValueError("probe program does not fit the image")
    image[start : start + len(code)] = code

    header_offset = 0x7FC0 if mapping == "lorom" else 0xFFC0
    header = memoryview(image)[header_offset : header_offset + 0x40]
    header[:] = bytes(0x40)
    title = f"RETROLARIUM {mapping.upper()}".encode("ascii")
    header[0:21] = title.ljust(21)
    header[0x15] = 0x30 if mapping == "lorom" else 0x21
    header[0x16] = 0x00
    header[0x17] = 7
    header[0x18] = 0
    header[0x19] = 1
    header[0x1A] = 0x33
    header[0x1B] = 0
    vectors = {
        0x24: "NativeNmi",
        0x26: "NativeNmi",
        0x28: "NativeNmi",
        0x2A: "NativeNmi",
        0x2E: "NativeIrq",
        0x34: "NativeNmi",
        0x38: "NativeNmi",
        0x3A: "NativeNmi",
        0x3C: "Reset",
        0x3E: "NativeIrq",
    }
    for offset, name in vectors.items():
        header[offset : offset + 2] = (symbols[name] & 0xFFFF).to_bytes(2, "little")
    header.release()
    value = (checksum(image) + 0x1FE) & 0xFFFF
    image[header_offset + 0x1C : header_offset + 0x1E] = (value ^ 0xFFFF).to_bytes(2, "little")
    image[header_offset + 0x1E : header_offset + 0x20] = value.to_bytes(2, "little")
    if checksum(image) != value:
        raise ValueError("internal checksum construction failed")
    return bytes(image)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mapping", choices=("lorom", "hirom"))
    parser.add_argument("code", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_bytes(pack(args.code.read_bytes(), labels(args.labels), args.mapping))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
