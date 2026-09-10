#!/usr/bin/env python3
"""Pack the CNROM probe's assembled PRG and generated CHR banks."""

from __future__ import annotations

import argparse
from pathlib import Path


PRG_SIZE = 0x8000
CHR_BANK_SIZE = 0x2000
CHR_BANKS = 4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("prg", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    prg = args.prg.read_bytes()
    if len(prg) != PRG_SIZE:
        raise SystemExit(f"expected {PRG_SIZE} PRG bytes, got {len(prg)}")
    header = b"NES\x1a" + bytes((2, CHR_BANKS, 0x30, 0x00)) + bytes(8)
    chr_data = b"".join(
        bytes((bank,)) * CHR_BANK_SIZE for bank in range(CHR_BANKS)
    )
    args.output.write_bytes(header + prg + chr_data)


if __name__ == "__main__":
    main()
