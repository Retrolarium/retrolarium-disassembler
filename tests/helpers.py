from __future__ import annotations

from pathlib import Path


def nrom16_image() -> bytes:
    header = b"NES\x1a" + bytes((1, 1, 0, 0)) + bytes(8)
    prg = bytearray(0x4000)
    prg[0:6] = bytes.fromhex("AD 02 20 10 FB 60")
    prg[-6:] = bytes.fromhex("00 C0 00 C0 00 00")
    chr_data = bytes((index & 0xFF for index in range(0x2000)))
    return header + prg + chr_data


def write_facts(path: Path) -> None:
    path.write_text(
        "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
        "PRG0\tPRG0\tC000\t3\tAD 02 20\tBIT\t0x2002\t\tFALL_THROUGH\t\tFUN_PRG0__c000\n"
        "PRG0\tPRG0\tC003\t2\t10 FB\tBPL\tPRG0::0xc000\tPRG0::c000\tCONDITIONAL_JUMP\t\t\n"
        "PRG0\tPRG0\tC005\t1\t60\tRTS\t\t\tTERMINATOR\t\t\n",
        encoding="utf-8",
        newline="\n",
    )
