from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.dispatch.record import discover_record_callback_seeds
from retrolarium_disassembler.m68k.abstract import discover_object_field_handler_candidates
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from megadrive.builders import fact


class RecordCallbackTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(cartridge(size=0x800))
        self.data[0x300:0x328] = bytes(40)
        # Five eight-byte records, including a completely empty slot.
        for i, target in enumerate((0x400, 0, 0x420, 0x440, 0x460)):
            self.data[0x304 + i * 8:0x308 + i * 8] = target.to_bytes(4, "big")
            if target:
                self.data[target:target + 2] = bytes.fromhex("7001")
        self.items = [
            replace(fact(0x200, "LEA", "(0x300).l|A3"), length=6),
            fact(0x206, "CLR.W", "D2w"),
            fact(0x208, "MOVE.B", "(A1)|D2b"),
            fact(0x20A, "LSL.W", "#0x3|D2w"),
            replace(fact(0x20C, "MOVE.L", "(0x4,A3,D2w*0x1)|(0x4,A0)"), length=6),
            replace(fact(0x240, "MOVE.L", "(0x4,A5)|-(SP)"), length=4),
            replace(fact(0x244, "RTS", ""), raw=bytes.fromhex("4e75"), flow_type="TERMINATOR"),
            fact(0x400, "MOVEQ", "0x1|D0"),
        ]

    def seeds(self):
        return discover_record_callback_seeds(parse_megadrive(bytes(self.data)),
                                             {f.cpu_address: f for f in self.items})

    def test_record_stride_empty_slot_and_different_object_register(self):
        self.assertEqual([0x400, 0x420, 0x440, 0x460], [s.address for s in self.seeds()])

    def test_requires_executed_field_and_unsigned_index(self):
        for address, changes in ((0x244, {"mnemonic": "NOP"}),
                                 (0x206, {"mnemonic": "NOP"}),
                                 (0x20A, {"operands": "#0x2|D2w"}),
                                 (0x240, {"operands": "(0x8,A5)|-(SP)"})):
            old = self.items[:]
            self.items = [replace(f, **changes) if f.cpu_address == address else f for f in old]
            self.assertFalse(self.seeds())
            self.items = old

    def test_data_read_is_not_execution_and_bad_record_stops_scan(self):
        self.items[5] = replace(self.items[5], operands="(0x4,A5)|D0")
        self.assertFalse(self.seeds())
        self.items[5] = replace(self.items[5], operands="(0x4,A5)|-(SP)")
        self.data[0x314:0x318] = (0x421).to_bytes(4, "big")
        self.assertFalse(self.seeds())

    def test_conflicting_code_and_explicit_boundary_stop_records(self):
        self.items.append(replace(fact(0x318, "RTS", ""), raw=bytes.fromhex("4e75")))
        self.assertFalse(self.seeds())

    def test_callback_assignment_uses_stack_execution_evidence(self):
        self.items += [
            replace(fact(0x260, "MOVE.L", "#0x500|(0x4,A0)"), length=8),
            replace(fact(0x4FE, "RTS", ""), raw=bytes.fromhex("4e75"), flow_type="TERMINATOR"),
        ]
        self.data[0x500:0x502] = bytes.fromhex("7001")
        result = discover_object_field_handler_candidates(
            parse_megadrive(bytes(self.data)), {f.cpu_address: f for f in self.items})
        self.assertEqual([0x500], [c.address for c in result])


if __name__ == "__main__":
    unittest.main()
