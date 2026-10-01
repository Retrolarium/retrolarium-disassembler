import sys
from pathlib import Path
from dataclasses import replace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retrolarium_kit.m68k_register_callbacks import discover_register_callback_seeds
from retrolarium_kit.m68k_returns import discover_returning_call_seeds
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.facts import InstructionReference
from test_m68k_unused import instruction
from test_megadrive import cartridge


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.fs = {
            0x200: instruction(0x200, '43fa00fe', 'LEA', '(0xfe,PC)|A1'),
            0x204: instruction(0x204, '600001fa', 'BRA.W', '0x400', 'CALL_TERMINATOR', (0x400,)),
            0x300: instruction(0x300, '4e75', 'RTS', flow='TERMINATOR'),
            0x400: instruction(0x400, '41f8cb84', 'LEA', '(-0x347c).w|A0'),
            0x404: instruction(0x404, '4241', 'CLR.W', 'D1w'),
            0x406: instruction(0x406, '4240', 'CLR.W', 'D0w'),
            0x408: instruction(0x408, '4e91', 'JSR', '(A1)', 'COMPUTED_CALL'),
        }
        data = bytearray(cartridge(size=0x800))
        for p,f in self.fs.items(): data[p:p+f.length] = f.raw
        self.image = parse_megadrive(bytes(data))
    def discover(self, execution=None):
        return {s.address for s in discover_register_callback_seeds(self.image, self.fs, execution_facts=execution)}
    def test_rooted_parameter_executes_before_unknown_state_merge(self):
        self.assertEqual({0x300}, self.discover())
    def test_unrooted_writer_cannot_prove_callback(self):
        self.assertFalse(self.discover({p:f for p,f in self.fs.items() if p != 0x200}))
    def test_unrooted_helper_cannot_prove_callback(self):
        self.assertFalse(self.discover({p:f for p,f in self.fs.items() if p != 0x400}))
    def test_register_clobber_blocks_execution(self):
        self.fs[0x404] = instruction(0x404, '2240', 'MOVEA.L', 'D0|A1')
        self.assertFalse(self.discover())
    def test_width_annotated_address_register_clobber_blocks_execution(self):
        for operand in ('A1w', 'A1l'):
            with self.subTest(operand=operand):
                self.fs[0x404] = instruction(0x404, '5349', 'SUBQ.W', '0x1|' + operand)
                self.assertFalse(self.discover())
    def test_exg_blocks_execution(self):
        self.fs[0x404] = instruction(0x404, 'c348', 'EXG', 'D1|A0')
        self.assertEqual({0x300}, self.discover())
        self.fs[0x404] = instruction(0x404, 'c349', 'EXG', 'D1|A1')
        self.assertFalse(self.discover())
    def test_movem_range_restore_blocks_execution(self):
        self.fs[0x404] = instruction(0x404, '4cdf7fff', 'MOVEM.L', '(SP)+|D0-A6')
        self.assertFalse(self.discover())
    def test_postincrement_blocks_execution(self):
        self.fs[0x404] = instruction(0x404, '1219', 'MOVE.B', '(A1)+|D1b')
        self.assertFalse(self.discover())
    def test_unknown_call_blocks_execution(self):
        self.fs[0x404] = instruction(0x404, '6100001e', 'BSR.W', '0x424', 'UNCONDITIONAL_CALL', (0x424,))
        self.assertFalse(self.discover())
    def test_conditional_branch_does_not_prove_execution(self):
        self.fs[0x404] = instruction(0x404, '6602', 'BNE.B', '0x408', 'CONDITIONAL_JUMP', (0x408,))
        self.assertFalse(self.discover())
    def test_explicit_data_read_blocks_callback(self):
        self.fs[0x406] = replace(self.fs[0x406], references=(InstructionReference(0x300, 'READ', 0),))
        self.assertFalse(self.discover())
    def test_operand_interior_is_not_entrypoint(self):
        self.fs[0x2fe] = instruction(0x2fe, '203c4e750000', 'MOVE.L', '#0x4e750000|D0')
        self.fs.pop(0x300)
        self.assertFalse(self.discover())
    def test_unknown_or_looping_tail_helper_is_rejected(self):
        self.fs[0x400] = instruction(0x400, '60fe', 'BRA.B', '0x400', 'UNCONDITIONAL_JUMP', (0x400,))
        self.assertFalse(self.discover())


class RootRepairTests(unittest.TestCase):
    def setUp(self):
        self.image=parse_megadrive(cartridge(size=0x800))
        self.fs={0x200:instruction(0x200, '4eb900000300', 'JSR', '0x300.l', 'CALL_TERMINATOR', (0x300,)),
                 0x300:instruction(0x300, '4e75', 'RTS', flow='TERMINATOR')}
    def test_only_existing_root_can_repair_unrooted_predecessor(self):
        self.assertFalse(discover_returning_call_seeds(self.image,self.fs,{}))
        result=discover_returning_call_seeds(self.image,self.fs,{},planned_roots={0x206})
        self.assertEqual([0x206],[s.address for s in result])
    def test_approximate_root_does_not_repair_call(self):
        self.assertFalse(discover_returning_call_seeds(self.image,self.fs,{},planned_roots={0x208}))
    def test_nonreturning_callee_cannot_restore_root(self):
        self.fs[0x300]=instruction(0x300,'60fe','BRA.B','0x300','UNCONDITIONAL_JUMP',(0x300,))
        self.assertFalse(discover_returning_call_seeds(self.image,self.fs,{},planned_roots={0x206}))

if __name__ == '__main__': unittest.main()
