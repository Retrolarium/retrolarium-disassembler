from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.m68k.dispatch.table import (
    discover_lea_indexed_call_seeds, discover_trap_relative_dispatch_seeds,
)
from retrolarium_core.megadrive import parse_megadrive
from megadrive.builders import cartridge
from megadrive.builders import fact


class TableDispatchTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(cartridge(size=0x800))
        for i, target in enumerate((0x400, 0x420, 0x440)):
            self.data[0x300 + i * 4:0x304 + i * 4] = target.to_bytes(4, "big")
            self.data[target:target + 2] = bytes.fromhex("7001")
        self.items = [replace(fact(0x200, "LEA", "(0x300).l|A2"), length=6),
                      replace(fact(0x206, "MOVEA.L", "(0x0,A2,D3w*0x1)|A0"), length=4),
                      replace(fact(0x20A, "JSR", "(A0)"), flow_type="COMPUTED_CALL"),
                      fact(0x400, "MOVEQ", "0x1|D0")]

    def discover(self, function):
        return [s.address for s in function(parse_megadrive(bytes(self.data)),
                                            {f.cpu_address: f for f in self.items})]

    def test_table_base_and_indirect_call_do_not_require_byte_only_index(self):
        self.assertEqual([0x400, 0x420, 0x440], self.discover(discover_lea_indexed_call_seeds))
        self.items[2] = replace(self.items[2], operands="(A1)")
        self.assertFalse(self.discover(discover_lea_indexed_call_seeds))

    def test_odd_or_overlapping_table_target_stops_scan(self):
        self.data[0x304:0x308] = (0x421).to_bytes(4, "big")
        self.assertFalse(self.discover(discover_lea_indexed_call_seeds))

    def test_index_preparation_between_lea_and_load_preserves_table_base(self):
        lea, load, call, target = self.items
        self.items = [lea, replace(fact(0x206, "MOVE.W", "(0x2,A4)|D3w"), length=4),
                      fact(0x20A, "LSL.W", "0x2|D3w"),
                      replace(load, cpu_address=0x20C, physical_offset=0x20C),
                      replace(call, cpu_address=0x210, physical_offset=0x210), target]
        self.assertEqual([0x400, 0x420, 0x440], self.discover(discover_lea_indexed_call_seeds))
        self.items[1] = replace(self.items[1], mnemonic="MOVEA.L", operands="D0|A2")
        self.assertFalse(self.discover(discover_lea_indexed_call_seeds))

    def trap(self):
        self.data[34 * 4:35 * 4] = (0x240).to_bytes(4, "big")
        for i, target in enumerate((0x400, 0x420, 0x440)):
            self.data[0x300 + i * 2:0x302 + i * 2] = (target - 0x300).to_bytes(2, "big")
        self.data[0x306:0x30C] = bytes.fromhex("ffff ffff ffff")
        self.items[1] = replace(self.items[1], mnemonic="MOVE.W", operands="(0x4,A4)|D3w")
        self.items[2] = replace(self.items[2], mnemonic="TRAP", raw=bytes.fromhex("4e42"),
                                operands="0x2", flow_type="FALL_THROUGH")
        self.items += [fact(0x240, "ADD.W", "D3w|D3w"),
                       replace(fact(0x242, "ADDA.W", "(0x0,A2,D3w*0x1)|A2"), length=4),
                       replace(fact(0x246, "JSR", "(A2)"), flow_type="COMPUTED_CALL"),
                       replace(fact(0x248, "RTE", ""), raw=bytes.fromhex("4e73"), flow_type="TERMINATOR")]

    def test_trap_table_offsets_are_relative_to_lea_base_not_entry(self):
        self.trap()
        self.assertEqual([0x400, 0x420, 0x440], self.discover(discover_trap_relative_dispatch_seeds))

    def test_ordinary_trap_and_clobbered_table_base_do_not_promote_data(self):
        self.trap()
        original = self.items[:]
        self.items = [replace(f, operands="D4w|D4w") if f.cpu_address == 0x240 else f for f in original]
        self.assertFalse(self.discover(discover_trap_relative_dispatch_seeds))
        self.items = [replace(f, mnemonic="MOVEA.L", operands="(A4)|A2")
                      if f.cpu_address == 0x206 else f for f in original]
        self.assertFalse(self.discover(discover_trap_relative_dispatch_seeds))


if __name__ == "__main__":
    unittest.main()
