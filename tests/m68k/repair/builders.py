"""Overlay fact rows in the Ghidra export format."""

from __future__ import annotations




HEADER = "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\treferences\tflow_type\tsymbol\tfunction\n"


def row(address, raw, mnemonic, operands="", flows="", flow="TERMINATOR"):
    return f"CD_MODULE\tram\t{address:08X}\t{len(bytes.fromhex(raw))}\t{raw}\t{mnemonic}\t{operands}\t{flows}\t\t{flow}\t\t\n"
