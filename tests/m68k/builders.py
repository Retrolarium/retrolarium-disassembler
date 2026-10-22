"""68000 instruction facts with their encoded bytes."""

from __future__ import annotations

from dataclasses import replace

from megadrive.builders import fact


def instruction(address, raw, mnemonic, operands="", flow="FALL_THROUGH", flows=()):
    payload = bytes.fromhex(raw)
    return replace(fact(address, mnemonic, operands, flows=flows), raw=payload, length=len(payload), flow_type=flow)
