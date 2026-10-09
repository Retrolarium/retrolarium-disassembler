from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from retrolarium_disassembler.m68k.callbacks.absolute_ram import discover_absolute_ram_callback_seeds as discover
from retrolarium_disassembler.facts import InstructionReference
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_m68k_unused import instruction


def fixture():
    instructions = [
        instruction(0x300,'43fa05fe','LEA','(0x5fe,PC)|A1'),
        instruction(0x304,'6000001a','BRA.W','0x320','UNCONDITIONAL_JUMP',(0x320,)),
        instruction(0x310,'43fa060e','LEA','(0x60e,PC)|A1'),
        instruction(0x314,'6000000a','BRA.W','0x320','UNCONDITIONAL_JUMP',(0x320,)),
        instruction(0x320,'21c9e000','MOVE.L','A1|(0xffffe000).w'),
        instruction(0x324,'4e75','RTS',flow='TERMINATOR'),
        instruction(0x400,'2678e000','MOVEA.L','(0xffffe000).w|A3'),
        instruction(0x404,'6000001a','BRA.W','0x420','UNCONDITIONAL_JUMP',(0x420,)),
        instruction(0x420,'610000de','BSR.W','0x500','UNCONDITIONAL_CALL',(0x500,)),
        instruction(0x424,'4e75','RTS',flow='TERMINATOR'),
        instruction(0x500,'48e78040','MOVEM.L','{ A1 D0}|-(SP)'),
        instruction(0x504,'610000fa','BSR.W','0x600','UNCONDITIONAL_CALL',(0x600,)),
        instruction(0x508,'4a40','TST.W','D0w'),
        instruction(0x50A,'6702','BEQ.B','0x50e','CONDITIONAL_JUMP',(0x50E,)),
        instruction(0x50C,'4e93','JSR','(A3)','COMPUTED_CALL'),
        instruction(0x50E,'4cdf0201','MOVEM.L','(SP)+|{ D0 A1}'),
        instruction(0x512,'4e75','RTS',flow='TERMINATOR'),
        instruction(0x600,'48e78010','MOVEM.L','{ A3 D0}|-(SP)'),
        instruction(0x604,'47f900fff000','LEA','(0xfff000).l|A3'),
        instruction(0x60A,'3013','MOVE.W','(A3)|D0w'),
        instruction(0x60C,'4cdf0801','MOVEM.L','(SP)+|{ D0 A3}'),
        instruction(0x610,'4e75','RTS',flow='TERMINATOR'),
        instruction(0x900,'48e7e000','MOVEM.L','{ D2 D1 D0}|-(SP)'),
        instruction(0x904,'4cdf0007','MOVEM.L','(SP)+|{ D0 D1 D2}'),
        instruction(0x908,'4e75','RTS',flow='TERMINATOR'),
        instruction(0x920,'7000','MOVEQ','0x0|D0'),
        instruction(0x922,'4e75','RTS',flow='TERMINATOR'),
    ]
    return {f.cpu_address:f for f in instructions}


def image_for(facts):
    data=bytearray(cartridge(size=0x1200))
    for f in facts.values():data[f.physical_offset:f.physical_offset+f.length]=f.raw
    return parse_megadrive(bytes(data))


class AbsoluteRamCallbacksTests(unittest.TestCase):
    def run_model(self,facts=None,rooted=None,**kwargs):
        facts=fixture() if facts is None else facts
        rooted={a:f for a,f in facts.items() if a<0x900} if rooted is None else rooted
        return discover(image_for(facts),rooted,facts,**kwargs)

    def test_shared_store_two_leas_and_preserved_interprocedural_reader(self):
        seeds=self.run_model()
        self.assertEqual([0x900,0x920],[s.address for s in seeds])
        self.assertTrue(all(s.confidence=='high' for s in seeds))
        for fragment in ('000300','000320','FFE000','000400','00050C','000504->000600','not runtime ordering'):
            self.assertIn(fragment,seeds[0].evidence)

    def test_unknown_whole_pointer_writer_is_allowed_but_not_target_evidence(self):
        facts=fixture();facts[0x800]=instruction(0x800,'21c8e000','MOVE.L','A0|(0xffffe000).w')
        self.assertEqual([0x900,0x920],[s.address for s in self.run_model(facts)])

    def test_unknown_helper_and_register_clobber_do_not_preserve_callback(self):
        facts=fixture()
        cases=[instruction(0x504,'610001fa','BSR.W','0x700','UNCONDITIONAL_CALL',(0x700,)),
               instruction(0x508,'2640','MOVEA.L','D0|A3'),
               instruction(0x508,'d6c0','ADDA.W','D0w|A3'),
               instruction(0x508,'344b','MOVEA.W','A3w|A2')]
        for changed in cases:
            self.assertEqual((),self.run_model({**facts,changed.cpu_address:changed}),str(changed))

    def test_wrong_restore_does_not_preserve_callee_argument(self):
        facts=fixture();facts[0x60C]=instruction(0x60C,'4cdf0401','MOVEM.L','(SP)+|{ D0 A2}')
        self.assertEqual((),self.run_model(facts))

    def test_callee_stack_alias_not_accepted_as_preserving_return(self):
        facts=fixture();facts[0x60A]=instruction(0x60A,'304f','MOVEA.W','A7w|A0')
        self.assertEqual((),self.run_model(facts))

    def test_sibling_data_use_rejects_otherwise_valid_execution_path(self):
        facts=fixture()
        facts[0x50E]=instruction(0x50E,'3013','MOVE.W','(A3)|D0w')
        facts[0x510]=instruction(0x510,'4e75','RTS',flow='TERMINATOR')
        self.assertEqual((),self.run_model(facts))

    def test_sibling_missing_frontier_or_unknown_call_rejects_slot_typing(self):
        facts=fixture()
        facts[0x50A]=instruction(0x50A,'670001f4','BEQ.W','0x700','CONDITIONAL_JUMP',(0x700,))
        # Preserve a valid fallthrough route at the branch's new end.
        facts[0x50E]=instruction(0x50E,'4e93','JSR','(A3)','COMPUTED_CALL')
        del facts[0x50C]
        self.assertEqual((),self.run_model(facts))
        facts=fixture()
        facts[0x50E]=instruction(0x50E,'610001f0','BSR.W','0x700','UNCONDITIONAL_CALL',(0x700,))
        self.assertEqual((),self.run_model(facts))

    def test_sibling_plain_return_or_pointer_replacement_can_discard_value(self):
        facts=fixture()
        for branch in (instruction(0x50E,'4e75','RTS',flow='TERMINATOR'),
                       instruction(0x50E,'2640','MOVEA.L','D0|A3')):
            self.assertEqual([0x900,0x920],[s.address for s in self.run_model({**facts,0x50E:branch})])

    def test_preserved_helper_must_not_read_incoming_pointer_as_data(self):
        facts=fixture()
        # MOVEM saves/restores A3, but the read occurs before its local reuse.
        facts[0x604]=instruction(0x604,'3013','MOVE.W','(A3)|D0w')
        facts[0x606]=instruction(0x606,'47f900fff000','LEA','(0xfff000).l|A3')
        del facts[0x60A]
        self.assertEqual((),self.run_model(facts))

    def test_preserved_helper_after_restore_cannot_read_original_pointer(self):
        facts=fixture()
        facts[0x610]=instruction(0x610,'3013','MOVE.W','(A3)|D0w')
        facts[0x612]=instruction(0x612,'4e75','RTS',flow='TERMINATOR')
        self.assertEqual((),self.run_model(facts))

    def test_preserved_helper_cannot_escape_original_pointer_alias(self):
        facts=fixture()
        facts[0x604]=instruction(0x604,'344b','MOVEA.W','A3w|A2')
        facts[0x606]=instruction(0x606,'47f900fff000','LEA','(0xfff000).l|A3')
        del facts[0x60A]
        self.assertEqual((),self.run_model(facts))

    def test_unrooted_read_writer_callee_or_executor_cannot_supply_witness(self):
        facts=fixture()
        for missing in (0x320,0x400,0x500,0x504,0x600,0x50C):
            rooted={a:f for a,f in facts.items() if a<0x900 and a!=missing}
            self.assertEqual((),self.run_model(facts,rooted),hex(missing))

    def test_writer_pointer_clobber_or_alias_rejected(self):
        facts=fixture()
        del facts[0x310];del facts[0x314]
        for changed in [instruction(0x304,'2240','MOVEA.L','D0|A1'),
                        instruction(0x304,'2449','MOVEA.L','A1|A2')]:
            self.assertEqual((),self.run_model({**facts,0x304:changed}))

    def test_foreign_slot_does_not_link_writer_and_executor(self):
        facts=fixture();facts[0x400]=instruction(0x400,'2678e004','MOVEA.L','(0xffffe004).w|A3')
        self.assertEqual((),self.run_model(facts))

    def test_partial_overlap_scalar_read_unknown_scalar_write_and_address_taking_reject(self):
        facts=fixture()
        for bad in (
            instruction(0x800,'11fc0000e001','MOVE.B','#0x0|(0xffffe001).w'),
            instruction(0x800,'21fc00123456e000','MOVE.L','#0x123456|(0xffffe000).w'),
            instruction(0x800,'21c0e000','MOVE.L','D0|(0xffffe000).w'),
            instruction(0x800,'2238e000','MOVE.L','(0xffffe000).w|D1'),
            instruction(0x800,'41f8e000','LEA','(-0x2000).w|A0'),
            instruction(0x800,'21c8dffe','MOVE.L','A0|(0xffffdffe).w'),
        ):
            self.assertEqual((),self.run_model({**facts,0x800:bad}),bad.operands)

    def test_longword_null_and_pointer_tests_are_permitted(self):
        facts=fixture()
        for allowed in (instruction(0x800,'42b8e000','CLR.L','(0xffffe000).w'),
                        instruction(0x800,'4ab8e000','TST.L','(0xffffe000).w'),
                        instruction(0x800,'21fc00000000e000','MOVE.L','#0x0|(0xffffe000).w')):
            self.assertEqual([0x900,0x920],[s.address for s in self.run_model({**facts,0x800:allowed})])

    def test_every_absolute_slot_load_needs_its_own_preserving_execution_route(self):
        facts=fixture();facts[0x800]=instruction(0x800,'2678e000','MOVEA.L','(0xffffe000).w|A3')
        facts[0x804]=instruction(0x804,'3013','MOVE.W','(A3)|D0w')
        facts[0x806]=instruction(0x806,'4e75','RTS',flow='TERMINATOR')
        self.assertEqual((),self.run_model(facts))

    def test_code_writer_lea_data_annotation_is_not_a_scalar_read(self):
        facts=fixture();facts[0x300]=replace(facts[0x300],references=(InstructionReference(0x900,'DATA',0),))
        self.assertEqual([0x900,0x920],[s.address for s in self.run_model(facts)])

    def test_real_scalar_read_full_span_protects_callback_head(self):
        facts=fixture()
        facts[0x800]=replace(instruction(0x800,'2239000008fe','MOVE.L','(0x8fe).l|D1'),
                            references=(InstructionReference(0x8FE,'READ',0),))
        self.assertEqual([0x920],[s.address for s in self.run_model(facts)])
        self.assertEqual([0x920],[s.address for s in self.run_model(protected_ranges=((0x902,0x904),))])

    def test_target_inside_trusted_instruction_rejected(self):
        facts=fixture();facts[0x8FE]=instruction(0x8FE,'203c48e7e000','MOVE.L','#0x48e7e000|D0')
        self.assertEqual([0x920],[s.address for s in self.run_model(facts)])

    def test_backing_offsets_lengths_and_target_renderability_checked(self):
        facts=fixture();image=image_for(facts)
        for address in (0x300,0x320,0x400,0x600):
            changed={**facts,address:replace(facts[address],physical_offset=address+2)}
            expected=[0x920] if address==0x300 else []
            self.assertEqual(expected,[s.address for s in discover(image,{a:f for a,f in changed.items() if a<0x900},changed)])
        facts[0x900]=instruction(0x900,'a000','LINEA','0x0',flow='TERMINATOR')
        self.assertEqual([0x920],[s.address for s in self.run_model(facts)])

    def test_missing_target_is_only_a_decode_request(self):
        facts=fixture();image=image_for(facts);del facts[0x900]
        requests=[]
        result=discover(image,{a:f for a,f in facts.items() if a<0x900},facts,
                        decode_request=lambda *args:requests.append(args))
        self.assertEqual([0x920],[s.address for s in result])
        self.assertEqual([(0x900,0x320,'typed absolute RAM callback first instruction')],requests)

    def test_nonzero_origin_preserves_logical_roots_and_physical_backing(self):
        facts=fixture();image=image_for(facts);origin=0x100000
        image=replace(image,header=replace(image.header,rom_start=origin,rom_end=origin+len(image.data)-1))
        shifted={}
        for a,f in facts.items():
            flows=tuple(t+origin for t in f.flows)
            operands=f'0x{flows[0]:x}' if flows else f.operands
            shifted[a+origin]=replace(f,cpu_address=a+origin,flows=flows,operands=operands)
        rooted={a:f for a,f in shifted.items() if a<origin+0x900}
        self.assertEqual([origin+0x900,origin+0x920],
                         [s.address for s in discover(image,rooted,shifted)])
        self.assertEqual([origin+0x920], [s.address for s in discover(image,rooted,shifted,
                                         protected_ranges=((origin+0x902,origin+0x904),))])


if __name__=='__main__':unittest.main()
