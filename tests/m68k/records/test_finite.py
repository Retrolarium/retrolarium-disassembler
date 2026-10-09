from pathlib import Path
import sys, unittest
from dataclasses import replace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))
from test_megadrive import cartridge
from test_megadrive_z80 import fact
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.emit import _asm_instruction
from retrolarium_disassembler.facts import InstructionReference
from retrolarium_disassembler.m68k.abstract import OrphanCandidate
from retrolarium_disassembler.m68k.records.packed import _complete_cfg
from retrolarium_disassembler.m68k.records.finite import (
 _discover_models as discover, Engine, State, Rejected,
 discover_finite_record_callback_seeds, put_pointer,
)

def ins(address,raw,mnemonic,operands='',flow='FALL_THROUGH',flows=()):
 raw=bytes.fromhex(raw)
 return replace(fact(address,mnemonic,operands),raw=raw,length=len(raw),flow_type=flow,flows=flows)

def fixture(records=None):
 fs=[
 ins(0x200,'41f900000800','LEA','(0x800).l|A0'),ins(0x206,'4e75','RTS',flow='TERMINATOR'),
 ins(0x400,'6100fdfe','BSR.W','0x200','UNCONDITIONAL_CALL',(0x200,)),
 ins(0x404,'0c50ffff','CMPI.W','#-0x1|(A0)'),
 ins(0x408,'6746','BEQ.B','0x450','CONDITIONAL_JUMP',(0x450,)),
 ins(0x40a,'20680008','MOVEA.L','(0x8,A0)|A0'),ins(0x40e,'4247','CLR.W','D7w'),
 ins(0x410,'0c3000fd7000','CMPI.B','#-0x3|(0x0,A0,D7w*0x1)'),
 ins(0x416,'6606','BNE.B','0x41e','CONDITIONAL_JUMP',(0x41e,)),
 ins(0x418,'d0f07002','ADDA.W','(0x2,A0,D7w*0x1)|A0'),
 ins(0x41c,'602a','BRA.B','0x448','UNCONDITIONAL_JUMP',(0x448,)),
 ins(0x41e,'b2307000','CMP.B','(0x0,A0,D7w*0x1)|D1b'),
 ins(0x422,'661c','BNE.B','0x440','CONDITIONAL_JUMP',(0x440,)),
 ins(0x424,'b4307001','CMP.B','(0x1,A0,D7w*0x1)|D2b'),
 ins(0x428,'671a','BEQ.B','0x444','CONDITIONAL_JUMP',(0x444,)),
 ins(0x42a,'6014','BRA.B','0x440','UNCONDITIONAL_JUMP',(0x440,)),
 ins(0x440,'5847','ADDQ.W','0x4|D7w'),
 ins(0x442,'60cc','BRA.B','0x410','UNCONDITIONAL_JUMP',(0x410,)),
 ins(0x444,'d0f07002','ADDA.W','(0x2,A0,D7w*0x1)|A0'),
 ins(0x448,'4e90','JSR','(A0)','COMPUTED_CALL'),ins(0x450,'4e75','RTS',flow='TERMINATOR'),
 ]
 data=bytearray(cartridge(size=0x2000))
 data[0x800:0x812]=b'\0'*18
 data[0x808:0x80c]=(0x900).to_bytes(4,'big')
 records=records or [(1,2,0x300),(0xfd,0,0x310),(2,3,0x320)]
 for index,(x,y,offset) in enumerate(records):
  a=0x900+index*4
  data[a:a+4]=bytes((x,y))+offset.to_bytes(2,'big')
 heads={a:ins(a,'4e75','RTS',flow='TERMINATOR') for a in (0xc00,0xc08,0xc10,0xc20)}
 for f in [*fs,*heads.values()]:data[f.cpu_address:f.cpu_address+f.length]=f.raw
 return parse_megadrive(bytes(data)),{f.cpu_address:f for f in fs},heads

def update(image,facts,item):
 data=bytearray(image.data);data[item.cpu_address:item.cpu_address+item.length]=item.raw
 return parse_megadrive(bytes(data)),{**facts,item.cpu_address:item}

def result(image,facts,heads,**kwargs):
 return discover(image,facts,direct_heads=heads,render_instruction=_asm_instruction,**kwargs)[0]

def seeds(image,facts,heads,**kwargs):
 return discover_finite_record_callback_seeds(image,{**heads,**facts},execution_facts=facts,
                                             render_instruction=_asm_instruction,**kwargs)

class FiniteRecordTests(unittest.TestCase):
 def test_terminal_record_and_fake_adjacent_record(self):
  image,facts,heads=fixture()
  row=result(image,facts,heads)
  self.assertEqual(row['accepted'],[0xc00,0xc10])
  self.assertNotIn(0x908,row['typed_read_addresses'])

 def test_repeated_selector_second_matching_record_unreachable(self):
  image,facts,heads=fixture([(1,2,0x300),(1,2,0x308),(0xfd,0,0x310)])
  row=result(image,facts,heads)
  self.assertEqual(row['accepted'],[0xc00,0xc10])

 def test_changed_second_selector_is_reachable(self):
  image,facts,heads=fixture([(1,2,0x300),(1,3,0x308),(0xfd,0,0x310)])
  self.assertEqual(result(image,facts,heads)['accepted'],[0xc00,0xc08,0xc10])

 def test_missing_sentinel_fails_entire_candidate(self):
  image,facts,heads=fixture()
  data=bytearray(image.data);data[0x900:]=b'\0'*(len(data)-0x900)
  self.assertEqual(result(parse_megadrive(bytes(data)),facts,heads)['status'],'rejected')

 def test_unknown_producer_call_rejected(self):
  image,facts,heads=fixture()
  image,facts=update(image,facts,ins(0x200,'4eb900001000','JSR','0x1000','UNCONDITIONAL_CALL',(0x1000,)))
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_unknown_consumer_call_rejected(self):
  image,facts,heads=fixture()
  image,facts=update(image,facts,ins(0x440,'4e91','JSR','(A1)','COMPUTED_CALL'))
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_unknown_cursor_mutation_rejected(self):
  image,facts,heads=fixture()
  image,facts=update(image,facts,ins(0x440,'de41','ADD.W','D1w|D7w'))
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_odd_table_pointer_rejected(self):
  image,facts,heads=fixture()
  data=bytearray(image.data);data[0x808:0x80c]=(0x901).to_bytes(4,'big')
  self.assertEqual(result(parse_megadrive(bytes(data)),facts,heads)['status'],'rejected')

 def test_postincrement_data_cursor_not_frozen(self):
  image,facts,heads=fixture()
  # A counterexample to forgetting address writeback: CMPI.W advances A0;
  # the subsequent MOVEA.L must use the adjusted header, not the old one.
  image,facts=update(image,facts,ins(0x404,'0c58ffff','CMPI.W','#-0x1|(A0)+'))
  self.assertEqual(discover(image,facts,direct_heads=heads,render_instruction=_asm_instruction),[])

 def test_unrooted_producer_body_rejected(self):
  image,facts,heads=fixture();del facts[0x206]
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_full_head_operand_data_overlap_rejected(self):
  image,facts,heads=fixture()
  head=ins(0xc00,'303c1234','MOVE.W','#0x1234|D0w')
  image,heads=update(image,heads,head)
  row=result(image,facts,heads,protected_ranges=((0xc02,0xc04),))
  self.assertEqual(row['accepted'],[0xc10])

 def test_stale_source_fact_rejected(self):
  image,facts,heads=fixture()
  facts[0x404]=replace(facts[0x404],raw=bytes.fromhex('0c500001'))
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_noncanonical_head_rejected(self):
  image,facts,heads=fixture()
  image,heads=update(image,heads,ins(0xc00,'00046102','ORI.B','#0x2|D4b'))
  self.assertEqual(result(image,facts,heads)['accepted'],[0xc10])

 def test_byte_selector_cannot_return_word_selector_0x100_header(self):
  image,facts,heads=fixture()
  del facts[0x206]
  for f in [ins(0x200,'4240','CLR.W','D0w'),
    ins(0x202,'103900ff1000','MOVE.B','(0xff1000).l|D0b'),
    ins(0x208,'0c400100','CMPI.W','#0x100|D0w'),
    ins(0x20c,'670e','BEQ.B','0x21c','CONDITIONAL_JUMP',(0x21c,)),
    ins(0x20e,'41f900000800','LEA','(0x800).l|A0'),
    ins(0x214,'4e75','RTS',flow='TERMINATOR'),
    ins(0x21c,'41f900001000','LEA','(0x1000).l|A0'),
    ins(0x222,'4e75','RTS',flow='TERMINATOR')]:
   image,facts=update(image,facts,f)
  row=result(image,facts,heads)
  self.assertEqual(row['headers'],[0x800])
  self.assertEqual(row['accepted'],[0xc00,0xc10])

 def test_public_api_preserves_known_producer_selector_into_consumer(self):
  image,facts,heads=fixture();del facts[0x206]
  for f in [ins(0x200,'4241','CLR.W','D1w'),
            ins(0x202,'41f900000800','LEA','(0x800).l|A0'),
            ins(0x208,'4e75','RTS',flow='TERMINATOR')]:
   image,facts=update(image,facts,f)
  # The first record requires D1b=1, but the producer returned D1w=0.
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_header_selector_correlation_is_not_unioned_between_returns(self):
  image,facts,heads=fixture([(2,2,0x300),(0xfd,0,0x310)]);del facts[0x206]
  data=bytearray(image.data)
  data[0x1000:0x100c]=b'\0'*12
  data[0x1008:0x100c]=(0x1100).to_bytes(4,'big')
  data[0x1100:0x1108]=bytes.fromhex('01020300fd000310')
  image=parse_megadrive(bytes(data))
  for f in [ins(0x200,'4241','CLR.W','D1w'),
            ins(0x202,'123900ff1000','MOVE.B','(0xff1000).l|D1b'),
            ins(0x208,'0c010001','CMPI.B','#0x1|D1b'),
            ins(0x20c,'6708','BEQ.B','0x216','CONDITIONAL_JUMP',(0x216,)),
            ins(0x20e,'41f900001000','LEA','(0x1000).l|A0'),
            ins(0x214,'4e75','RTS',flow='TERMINATOR'),
            ins(0x216,'41f900000800','LEA','(0x800).l|A0'),
            ins(0x21c,'4e75','RTS',flow='TERMINATOR')]:
   image,facts=update(image,facts,f)
  for a in (0x1400,0x1410):image,heads=update(image,heads,ins(a,'4e75','RTS',flow='TERMINATOR'))
  # Header800 only comes with D1=1, header1000 only with D1!=1.
  # Both first records are impossible even though each selector is finite.
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10,0x1410])

 def test_movem_restore_keeps_ccr_from_pre_restore_comparison(self):
  for compared,expected in ((1,0x800),(0,0x1000)):
   image,facts,heads=fixture();del facts[0x206]
   data=bytearray(image.data);data[0x1800]=1
   image=parse_megadrive(bytes(data))
   for f in [ins(0x200,'4240','CLR.W','D0w'),
             ins(0x202,'48e78000','MOVEM.L','{ D0}|-(SP)'),
             ins(0x206,'103900001800','MOVE.B','(0x1800).l|D0b'),
             ins(0x20c,f'0c40000{compared}','CMPI.W',f'#0x{compared:x}|D0w'),
             ins(0x210,'4cdf0001','MOVEM.L','(SP)+|{ D0}'),
             ins(0x214,'6710','BEQ.B','0x226','CONDITIONAL_JUMP',(0x226,)),
             ins(0x216,'41f900001000','LEA','(0x1000).l|A0'),
             ins(0x21c,'4e75','RTS',flow='TERMINATOR'),
             ins(0x226,'41f900000800','LEA','(0x800).l|A0'),
             ins(0x22c,'4e75','RTS',flow='TERMINATOR')]:
    image,facts=update(image,facts,f)
   engine=Engine(image,facts)
   self.assertEqual(engine.run(0x200,output='A0')[0],{expected})

 def test_known_move_zero_flag_filters_returned_header(self):
  image,facts,heads=fixture();del facts[0x206]
  data=bytearray(image.data);data[0x1800]=0
  image=parse_megadrive(bytes(data))
  for f in [ins(0x200,'103900001800','MOVE.B','(0x1800).l|D0b'),
            ins(0x206,'6708','BEQ.B','0x210','CONDITIONAL_JUMP',(0x210,)),
            ins(0x208,'41f900001000','LEA','(0x1000).l|A0'),
            ins(0x20e,'4e75','RTS',flow='TERMINATOR'),
            ins(0x210,'41f900000800','LEA','(0x800).l|A0'),
            ins(0x216,'4e75','RTS',flow='TERMINATOR')]:
   image,facts=update(image,facts,f)
  self.assertEqual(Engine(image,facts).run(0x200,output='A0')[0],{0x800})

 def test_unbounded_word_selector_rejected(self):
  image,facts,heads=fixture()
  image,facts=update(image,facts,ins(0x200,'303900ff1000','MOVE.W','(0xff1000).l|D0w'))
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_code_head_read_as_typed_data_rejected(self):
  image,facts,heads=fixture([(1,2,0x0),(0xfd,0,0x310)])
  self.assertNotIn(0x900,result(image,facts,heads)['accepted'])

 def test_target_odd_rejected(self):
  image,facts,heads=fixture([(1,2,0x301),(0xfd,0,0x310)])
  self.assertEqual(result(image,facts,heads)['status'],'rejected')

 def test_forbidden_stream_consumer_rejected(self):
  image,facts,heads=fixture()
  self.assertEqual(result(image,facts,heads,forbidden_reads=((0x900,0x904),))['status'],'rejected')

 def test_renderable_first_opcode_is_not_whole_callback_proof(self):
  image,facts,heads=fixture()
  for f in [ins(0xc00,'0301','BTST.L','D1|D1'),
            ins(0xc02,'00046102','ORI.B','#0x2|D4b')]:
   image,heads=update(image,heads,f)
  # Deliberately demonstrates why the direct head-only model is insufficient:
  # a real returned pointer can target data whose first word is an opcode.
  self.assertIn(0xc00,result(image,facts,heads)['accepted'])
  scope=OrphanCandidate(0xc00,0xc00,0xd00,0x100,'high','test independently proved pointer')
  self.assertFalse(_complete_cfg(image,scope,facts,heads,(),_asm_instruction,()))

 def test_incoming_pointer_accepts_single_rts_body(self):
  image,facts,heads=fixture()
  scope=OrphanCandidate(0xc00,0xc00,0xd00,0x100,'high','test independently proved pointer')
  body=_complete_cfg(image,scope,facts,heads,(),_asm_instruction,())
  self.assertEqual(list(body),[0xc00])

 def test_public_api_complete_leaf_seeds_and_provenance(self):
  image,facts,heads=fixture()
  found=seeds(image,facts,heads)
  self.assertEqual([s.address for s in found],[0xc00,0xc10])
  self.assertEqual(found[0].source_address,0x448)
  self.assertEqual(found[0].confidence,'high')
  for text in ('producer 000200','header 000800 table 000900','fields [2]',
               'strides [4]','computed JSR sites 000448','complete callback body 1'):
   self.assertIn(text,found[0].evidence)

 def test_public_api_requires_execution_facts(self):
  image,facts,heads=fixture()
  self.assertEqual(discover_finite_record_callback_seeds(image,{**heads,**facts},
                   render_instruction=_asm_instruction),())

 def test_public_api_rejects_renderable_data_head(self):
  image,facts,heads=fixture()
  for f in [ins(0xc00,'0301','BTST.L','D1|D1'),
            ins(0xc02,'00046102','ORI.B','#0x2|D4b')]:
   image,heads=update(image,heads,f)
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_public_api_rejects_unknown_callee_even_with_rts(self):
  image,facts,heads=fixture()
  for f in [ins(0xc00,'4eb900001800','JSR','0x1800','UNCONDITIONAL_CALL',(0x1800,)),
            ins(0xc06,'4e75','RTS',flow='TERMINATOR')]:
   image,heads=update(image,heads,f)
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_public_api_rejects_open_loop(self):
  image,facts,heads=fixture()
  image,heads=update(image,heads,ins(0xc00,'60fe','BRA.B','0xc00','UNCONDITIONAL_JUMP',(0xc00,)))
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_public_api_rejects_unbalanced_stack(self):
  image,facts,heads=fixture()
  for f in [ins(0xc00,'2f00','MOVE.L','D0|-(SP)'),ins(0xc02,'4e75','RTS',flow='TERMINATOR')]:
   image,heads=update(image,heads,f)
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_public_api_protects_head_operand(self):
  image,facts,heads=fixture()
  for f in [ins(0xc00,'303c1234','MOVE.W','#0x1234|D0w'),ins(0xc04,'4e75','RTS',flow='TERMINATOR')]:
   image,heads=update(image,heads,f)
  self.assertEqual([s.address for s in seeds(image,facts,heads,protected_ranges=((0xc02,0xc04),))],[0xc10])

 def test_public_api_protects_entire_direct_read_width(self):
  image,facts,heads=fixture()
  # A rooted long read beginning before the callback overlaps its first word.
  image,facts=update(image,facts,replace(ins(0x600,'203900000bfe','MOVE.L','(0xbfe).l|D0'),
                         references=(InstructionReference(0xbfe,'READ',0),)))
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_physical_mismatch_source_rejected(self):
  image,facts,heads=fixture();facts[0x200]=replace(facts[0x200],physical_offset=0x202)
  self.assertEqual(seeds(image,facts,heads),())

 def test_physical_mismatch_callback_rejected(self):
  image,facts,heads=fixture();heads[0xc00]=replace(heads[0xc00],physical_offset=0xc02)
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_instruction_length_cap_in_producer(self):
  image,facts,heads=fixture()
  image,facts=update(image,facts,replace(facts[0x200],length=12,raw=facts[0x200].raw+b'\0'*6))
  self.assertEqual(seeds(image,facts,heads),())

 def test_address_arithmetic_bus_wrap_rejected(self):
  for value in (-2,0x1000000):
   with self.assertRaises(Rejected):put_pointer(State(0x200),'A0',value)

 def test_consumer_state_budget_fails_closed(self):
  image,facts,heads=fixture()
  engine=Engine(image,facts)
  with self.assertRaisesRegex(Rejected,'state budget'):
   engine.run(0x40e,initial=put_pointer(State(0x40e),'A0',0x900),consumer=True,maximum=2)

 def test_mutually_referenced_operand_heads_reject_both(self):
  image,facts,heads=fixture([(1,2,0x300),(2,3,0x302),(0xfd,0,0x310)])
  for f in [ins(0xc00,'303c4e75','MOVE.W','#0x4e75|D0w'),
            ins(0xc02,'4e75','RTS',flow='TERMINATOR'),
            ins(0xc04,'4e75','RTS',flow='TERMINATOR')]:
   image,heads=update(image,heads,f)
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc10])

 def test_nonzero_origin_uses_physical_bytes_and_logical_protection(self):
  image,facts,heads=fixture()
  base=0x200000
  data=bytearray(image.data)
  data[0x202:0x206]=(base+0x800).to_bytes(4,'big')
  data[0x808:0x80c]=(base+0x900).to_bytes(4,'big')
  facts={a+base:replace(f,cpu_address=a+base,flows=tuple(t+base for t in f.flows),
                      raw=bytes(data[a:a+f.length]),
                      operands=f'(0x{base+0x800:x}).l|A0' if a==0x200 else f.operands)
         for a,f in facts.items()}
  heads={a+base:replace(f,cpu_address=a+base) for a,f in heads.items()}
  image=replace(image,data=bytes(data),header=replace(image.header,rom_start=base))
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[base+0xc00,base+0xc10])
  self.assertEqual([s.address for s in seeds(image,facts,heads,
      protected_ranges=((base+0xc00,base+0xc02),))],[base+0xc10])

 def test_helper_summary_requires_current_raw_and_physical_bytes(self):
  image,facts,heads=fixture()
  for f in [ins(0x200,'4eb900000300','JSR','0x300','UNCONDITIONAL_CALL',(0x300,)),
            ins(0x206,'41f900000800','LEA','(0x800).l|A0'),
            ins(0x20c,'4e75','RTS',flow='TERMINATOR'),
            ins(0x300,'4e71','NOP'),ins(0x302,'4e75','RTS',flow='TERMINATOR')]:
   image,facts=update(image,facts,f)
  self.assertEqual([s.address for s in seeds(image,facts,heads)],[0xc00,0xc10])
  for bad in (replace(facts[0x300],raw=b'\x4e\x75'),replace(facts[0x300],physical_offset=0x302)):
   with self.subTest(bad=bad):
    self.assertEqual(seeds(image,{**facts,0x300:bad},heads),())

if __name__=='__main__':unittest.main(verbosity=2)
