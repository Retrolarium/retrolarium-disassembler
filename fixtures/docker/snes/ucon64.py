#!/usr/bin/env python3
"""Minimal ucon64 --snes --nhd --chk compatibility command."""

from pathlib import Path
import sys


def find_header(data: bytearray) -> int:
    candidates = (0x7FC0, 0xFFC0, 0x40FFC0)
    for offset in candidates:
        if offset + 0x20 <= len(data) and data[offset + 0x15] & 0x0F in (0, 1, 2, 3, 5):
            return offset
    raise SystemExit("ucon64 compatibility command: SNES header not found")


def patch_checksum(data: bytearray, header: int) -> int:
    checksum_offset = header + 0x1C
    data[checksum_offset : checksum_offset + 4] = bytes(4)
    # A valid checksum/complement pair always contributes 0x1fe to the sum.
    checksum = (sum(data) + 0x1FE) & 0xFFFF
    complement = checksum ^ 0xFFFF
    data[checksum_offset : checksum_offset + 2] = complement.to_bytes(2, "little")
    data[checksum_offset + 2 : checksum_offset + 4] = checksum.to_bytes(2, "little")
    return checksum


def main(argv: list[str]) -> int:
    paths = [Path(argument) for argument in argv if not argument.startswith("-")]
    if len(paths) != 1 or "--chk" not in argv or "--snes" not in argv:
        raise SystemExit("usage: ucon64 --snes --nhd --chk ROM")

    rom = paths[0]
    data = bytearray(rom.read_bytes())
    header = find_header(data)
    checksum = patch_checksum(data, header)
    rom.write_bytes(data)
    print(f"SNES checksum: {checksum:04X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
