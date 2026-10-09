"""A constructor-record fixture: a table walked by a copy loop."""

from __future__ import annotations

from dataclasses import replace

from retrolarium_core.megadrive import parse_megadrive

from megadrive.builders import cartridge, fact


def instruction(*args, **kwargs):
    address, mnemonic, *rest = args
    operands = rest[0] if rest else ''
    length = kwargs.get('length', 2)
    f = replace(
        fact(address, mnemonic, operands, flows=kwargs.get('flows', ())), length=length,
        raw=bytes.fromhex('4E75') if mnemonic == 'RTS' else bytes.fromhex('4E71') * (length // 2),
        flow_type=kwargs.get('flow', 'FALL_THROUGH'),
    )
    base = f.mnemonic.upper().split('.')[0]
    if base in {'JSR', 'BSR'}:
        opcode = bytes.fromhex('6100' if base == 'BSR' else '4E91' if f.operands == '(A1)' else '4EB9')
        f = replace(f, raw=opcode + b'\x00' * (f.length - 2))
    return f


def fixture():
    data = bytearray(cartridge(size=0x1000))
    for i, target in enumerate((0x800, 0x900, 0xa00)):
        data[0x500 + i * 12:0x504 + i * 12] = target.to_bytes(4, 'big')
        data[target:target + 2] = bytes.fromhex('7000')
    items = [
        instruction(0x200, 'LEA', '(0x500).l|A2', length=6),
        instruction(0x206, 'MOVE.W', '#0x2|D0w', length=4),
        instruction(0x20a, 'MOVEA.L', '(A2)+|A1'),
        instruction(0x20c, 'JSR', '0x300', length=6, flows=(0x300,), flow='UNCONDITIONAL_CALL'),
        instruction(0x212, 'BCS.W', '0x232', length=4, flows=(0x232,), flow='CONDITIONAL_JUMP'),
        instruction(0x216, 'MOVE.L', 'A3|(0x2e,A1)', length=4),
        instruction(0x21a, 'MOVE.L', '(A2)+|(0x32,A1)', length=4),
        instruction(0x21e, 'MOVE.W', '(A2)+|(0xa,A1)', length=4),
        instruction(0x222, 'MOVE.W', '(A2)+|(0xe,A1)', length=4),
        instruction(0x226, 'DBF', 'D0w|0x20a', length=4, flows=(0x20a,), flow='CONDITIONAL_JUMP'),
        instruction(0x22a, 'RTS', flow='TERMINATOR'),
        instruction(0x232, 'RTS', flow='TERMINATOR'),
        instruction(0x300, 'BSR.W', '0x350', length=4, flows=(0x350,), flow='UNCONDITIONAL_CALL'),
        instruction(0x304, 'RTS', flow='TERMINATOR'),
        instruction(0x350, 'MOVEM.L', '{ A0 D0}|-(SP)', length=4),
        instruction(0x354, 'LEA', '(0xffe000).l|A0', length=6),
        instruction(0x35a, 'MOVE.W', '#0x3f|D0w', length=4),
        instruction(0x35e, 'TST.W', '(0x0,A0)', length=4),
        instruction(0x362, 'BEQ.W', '0x380', length=4, flows=(0x380,), flow='CONDITIONAL_JUMP'),
        instruction(0x366, 'ADDA.L', '#0x40|A0', length=6),
        instruction(0x36c, 'DBF', 'D0w|0x35e', length=4, flows=(0x35e,), flow='CONDITIONAL_JUMP'),
        instruction(0x370, 'MOVEM.L', '(SP)+|{ D0 A0}', length=4),
        instruction(0x374, 'RTS', flow='TERMINATOR'),
        instruction(0x380, 'MOVE.L', 'A1|(0x2,A0)', length=4),
        instruction(0x384, 'MOVEA.L', 'A0|A1'),
        instruction(0x386, 'MOVEM.L', '(SP)+|{ D0 A0}', length=4),
        instruction(0x38a, 'RTS', flow='TERMINATOR'),
        instruction(0x400, 'LEA', '(0xffe000).l|A0', length=6),
        instruction(0x406, 'MOVE.W', '#0x3f|D0w', length=4),
        instruction(0x40a, 'TST.W', '(0x0,A0)', length=4),
        instruction(0x40e, 'BEQ.W', '0x41e', length=4, flows=(0x41e,), flow='CONDITIONAL_JUMP'),
        instruction(0x412, 'MOVEA.L', '(0x2,A0)|A1', length=4),
        instruction(0x416, 'JSR', '(A1)', flow='COMPUTED_CALL'),
        instruction(0x418, 'NOP'),
        instruction(0x41a, 'NOP'),
        instruction(0x41c, 'NOP'),
        instruction(0x41e, 'ADDA.L', '#0x40|A0', length=6),
        instruction(0x424, 'DBF', 'D0w|0x40a', length=4, flows=(0x40a,), flow='CONDITIONAL_JUMP'),
        instruction(0x428, 'RTS', flow='TERMINATOR'),
    ]
    return (parse_megadrive(bytes(data)), {f.cpu_address: f for f in items})
