"""SNES probe images for the pointer and pipeline tests."""

from __future__ import annotations

from retrolarium_core.snes import cartridge_checksum, HIROM_HEADER_OFFSET, LOROM_HEADER_OFFSET, parse_snes

from helpers import cartridge


PROBE = bytes.fromhex(
    "78 18 FB C2 30 A9 34 12 A2 78 56 E2 20 A9 12 20 "
    "1B 90 22 23 90 00 20 4E 90 80 09 C2 20 A9 BC 9A "
    "E2 20 60 6B CB 80 FD 40 40 00 90 1B 90 24 90 27 "
    "90 00 90 00 23 90 00 27 90 00 00 1B 24 27 90 90 "
    "90 90 00 00 00 00 BA FF D5 FF DE FF E1 FF 4B AB C2 "
    "30 A9 00 02 8D 42 21 A2 00 00 E2 20 BD 72 90 8D 41 "
    "21 8A 8D 40 21 C2 20 E8 E0 06 00 D0 EC E2 20 60 E8 "
    "12 C4 F4 2F FA"
)


def probe_image(mapping: str):
    data = bytearray(cartridge(mapping))
    physical = 0x1000 if mapping == "lorom" else 0x9000
    data[physical : physical + len(PROBE)] = PROBE
    header = LOROM_HEADER_OFFSET if mapping == "lorom" else HIROM_HEADER_OFFSET
    data[header + 0x20 : header + 0x40] = bytes(0x20)
    vectors = {
        0x24: 0x9027,
        0x26: 0x9027,
        0x28: 0x9027,
        0x2A: 0x9027,
        0x2E: 0x9028,
        0x34: 0x9027,
        0x38: 0x9027,
        0x3A: 0x9027,
        0x3C: 0x9000,
        0x3E: 0x9028,
    }
    for offset, value in vectors.items():
        data[header + offset : header + offset + 2] = value.to_bytes(2, "little")
    data[header + 0x1C : header + 0x20] = bytes(4)
    checksum = (cartridge_checksum(data) + 0x1FE) & 0xFFFF
    data[header + 0x1C : header + 0x1E] = (checksum ^ 0xFFFF).to_bytes(2, "little")
    data[header + 0x1E : header + 0x20] = checksum.to_bytes(2, "little")
    return parse_snes(bytes(data))
