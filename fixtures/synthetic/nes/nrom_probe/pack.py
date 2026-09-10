#!/usr/bin/env python3
"""Pack the NROM probe's assembled PRG and deterministic CHR data."""

from __future__ import annotations

import argparse
from pathlib import Path


PRG_SIZE = 0x4000
CHR_SIZE = 0x2000


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("prg", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    prg = args.prg.read_bytes()
    if len(prg) != PRG_SIZE:
        raise SystemExit(f"expected {PRG_SIZE} PRG bytes, got {len(prg)}")
    header = b"NES\x1a" + bytes((1, 1, 0x00, 0x00)) + bytes(8)
    chr_data = bytes((index & 0xFF for index in range(CHR_SIZE)))
    args.output.write_bytes(header + prg + chr_data)


if __name__ == "__main__":
    main()
