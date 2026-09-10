#!/usr/bin/env python3
"""Pack independently linked GNROM PRG banks and generated CHR banks."""

from __future__ import annotations

import argparse
from pathlib import Path


PRG_BANK_SIZE = 0x8000
PRG_BANKS = 4
CHR_BANK_SIZE = 0x2000
CHR_BANKS = 4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("banks", nargs=PRG_BANKS, type=Path)
    args = parser.parse_args()
    banks = [path.read_bytes() for path in args.banks]
    for index, bank in enumerate(banks):
        if len(bank) != PRG_BANK_SIZE:
            raise SystemExit(
                f"bank {index} has {len(bank)} bytes, expected {PRG_BANK_SIZE}"
            )
    header = b"NES\x1a" + bytes((8, CHR_BANKS, 0x20, 0x40)) + bytes(8)
    chr_data = b"".join(
        bytes((0x40 + bank,)) * CHR_BANK_SIZE for bank in range(CHR_BANKS)
    )
    args.output.write_bytes(header + b"".join(banks) + chr_data)


if __name__ == "__main__":
    main()
