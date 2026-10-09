"""Proof boundaries and persistent replay plans for canonical fallthroughs."""
from dataclasses import replace
import unittest

from test_m68k_unused import instruction
from test_megadrive import cartridge
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disasm.facts import InstructionReference
from retrolarium_disasm.m68k.repair.fallthrough import M68kFallthroughRepairs, _direct_data_ranges


class FallthroughRepairTests(unittest.TestCase):
    def fixture(self, origin=0, offset=0x300):
        source = instruction(origin+offset, '7001', 'MOVEQ', '#0x1|D0')
        candidate = instruction(origin+offset+2, '203c4e750001', 'MOVE.L', '#0x4e750001|D0')
        conflict = instruction(origin+offset+4, '4e75', 'RTS', flow='TERMINATOR')
        source, candidate, conflict = (replace(f, physical_offset=f.cpu_address-origin)
                                      for f in (source, candidate, conflict))
        data = bytearray(cartridge(size=0x2000))
        for fact in (source, candidate):
            data[fact.physical_offset:fact.physical_offset+fact.length] = fact.raw
        image = parse_megadrive(bytes(data))
        image = replace(image, header=replace(image.header, rom_start=origin, rom_end=origin+len(data)-1))
        return image, source, candidate, conflict

    def discover(self, *, alter=None, protected=(), planned=(), origin=0, offset=0x300, minimum=None):
        image, source, candidate, conflict = self.fixture(origin, offset)
        raw = {source.cpu_address:source, conflict.cpu_address:conflict}
        trusted = {source.cpu_address:source}
        probes = {candidate.cpu_address:candidate}
        if alter:
            image,raw,trusted,probes = alter(image,raw,trusted,probes,source,candidate,conflict)
        model = M68kFallthroughRepairs(image, minimum_address=minimum)
        return model.discover(raw,trusted,probes,protected_ranges=protected,planned_roots=planned)

    def test_exact_conflicting_operand_is_repairable(self):
        result = self.discover()
        self.assertEqual((0x300,0x302,'203c4e750001'),
                         (result[0].source_address,result[0].address,result[0].raw_bytes))
        self.assertEqual((0x304,'4e75'),(result[0].conflicts[0].address,result[0].conflicts[0].raw_bytes))

    def test_undefined_zero_fill_does_not_grow_a_repair_or_probe_frontier(self):
        image, source, _, _ = self.fixture()
        target = source.cpu_address + source.length
        data = bytearray(image.data)
        data[target:target + 64] = bytes(64)
        image = replace(image, data=bytes(data))
        model = M68kFallthroughRepairs(image)
        raw = {source.cpu_address: source}
        requests = []
        self.assertEqual((), model.discover(raw, raw, {}, decode_request=lambda *args: requests.append(args)))
        self.assertEqual([], requests)
        zero = instruction(target, '00000000', 'ORI.B', '#0x0|D0b')
        self.assertEqual((), model.discover(raw, raw, {target: zero}))
        self.assertEqual({}, model.repairs)
        # An actual immediate operation next to zeros remains repairable.
        nonzero = instruction(target, '00000001', 'ORI.B', '#0x1|D0b')
        data[target:target + 4] = nonzero.raw
        model = M68kFallthroughRepairs(replace(image, data=bytes(data)))
        self.assertEqual([target], [r.address for r in model.discover(raw, raw, {target: nonzero})])

    def test_protected_operand(self):
        self.assertFalse(self.discover(protected=((0x304,0x305),)))

    def test_planned_interior_root(self):
        self.assertFalse(self.discover(planned=(0x304,)))

    def test_trusted_interior(self):
        def change(i,r,t,p,s,c,x):
            t[x.cpu_address] = x
            return i,r,t,p
        self.assertFalse(self.discover(alter=change))

    def test_source_raw_must_match_image(self):
        def change(i,r,t,p,s,c,x):
            data=bytearray(i.data)
            data[s.physical_offset:s.physical_offset+2]=bytes.fromhex('4e71')
            return replace(i,data=bytes(data)),r,t,p
        self.assertFalse(self.discover(alter=change))

    def test_probe_wrong_logical_or_physical_address(self):
        for field in ('cpu_address','physical_offset'):
            with self.subTest(field=field):
                def change(i,r,t,p,s,c,x):
                    p[c.cpu_address]=replace(c,**{field:getattr(c,field)+2})
                    return i,r,t,p
                self.assertFalse(self.discover(alter=change))

    def test_probe_wrong_bytes(self):
        def change(i,r,t,p,s,c,x):
            p[c.cpu_address]=replace(c,raw=b'\x00'*c.length)
            return i,r,t,p
        self.assertFalse(self.discover(alter=change))

    def test_odd_branch_target(self):
        def change(i,r,t,p,s,c,x):
            p[c.cpu_address]=replace(c,flows=(0x501,))
            return i,r,t,p
        self.assertFalse(self.discover(alter=change))

    def test_left_crossing_unit(self):
        def change(i,r,t,p,s,c,x):
            r[c.cpu_address-2]=instruction(c.cpu_address-2,'203c4e750001','MOVE.L','#0x4e750001|D0')
            return i,r,t,p
        self.assertFalse(self.discover(alter=change))

    def right_union(self,i,r,t,p,s,c,x):
        address=c.cpu_address+4
        conflict=instruction(address,'00010001','ORI.B','#0x1|D1b')
        r[address]=conflict
        data=bytearray(i.data)
        data[address:address+conflict.length]=conflict.raw
        return replace(i,data=bytes(data)),r,t,p

    def test_right_crossing_safe_union(self):
        result=self.discover(alter=self.right_union)
        self.assertEqual(0x306,result[0].conflicts[-1].address)

    def test_union_data_beyond_canonical_end(self):
        self.assertFalse(self.discover(alter=self.right_union,protected=((0x308,0x309),)))

    def test_union_root_beyond_canonical_end(self):
        self.assertFalse(self.discover(alter=self.right_union,planned=(0x308,)))

    def test_union_trusted_beyond_canonical_end(self):
        def change(i,r,t,p,s,c,x):
            i,r,t,p=self.right_union(i,r,t,p,s,c,x)
            t[0x308]=instruction(0x308,'0001','FAKE')
            return i,r,t,p
        self.assertFalse(self.discover(alter=change))

    def test_stale_conflicting_unit_bytes(self):
        def change(i,r,t,p,s,c,x):
            r[x.cpu_address]=replace(x,raw=bytes.fromhex('4e71'))
            return i,r,t,p
        self.assertFalse(self.discover(alter=change))

    def test_nonzero_origin(self):
        self.assertEqual(0x10302,self.discover(origin=0x10000)[0].address)

    def test_overlay_first_512_bytes(self):
        self.assertEqual(0x10082,self.discover(origin=0x10000,offset=0x80,minimum=0x10000)[0].address)

    def test_no_unrooted_source(self):
        def change(i,r,t,p,s,c,x):
            return i,r,{},p
        self.assertFalse(self.discover(alter=change))

    def test_exception_call_or_status_write_source(self):
        for mnemonic,operands in [('TRAP','#0'),('JSR','0x500'),('STOP','#0'),
                                 ('DIVU.W','#0x8|D1'),('MOVE','#0|SR'),('ORI','#1|SR')]:
            with self.subTest(mnemonic=mnemonic):
                def change(i,r,t,p,s,c,x):
                    t[s.cpu_address]=replace(s,mnemonic=mnemonic,operands=operands)
                    return i,r,t,p
                self.assertFalse(self.discover(alter=change))

    def test_direct_read_filter(self):
        image,*_=self.fixture()
        indirect=replace(instruction(0x200,'3018','MOVE.W','(A0)+|D0w'),
                         references=(InstructionReference(0x400,'READ',0),))
        self.assertEqual((),_direct_data_ranges(image,{0x200:indirect}))
        direct=replace(instruction(0x200,'30380400','MOVE.W','(0x00000400).w|D0w'),
                       references=(InstructionReference(0x400,'READ',0),))
        self.assertEqual(((0x400,0x402),),_direct_data_ranges(image,{0x200:direct}))

    def test_movem_read_protects_entire_mask(self):
        image,*_=self.fixture()
        fact=replace(instruction(0x200,'4cf8000f0400','MOVEM.L','(0x00000400).w|{D0 D1 D2 D3}'),
                     references=(InstructionReference(0x400,'READ',0),))
        self.assertEqual(((0x400,0x410),),_direct_data_ranges(image,{0x200:fact}))

    def test_probe_request_is_not_a_repair_or_seed(self):
        image,source,candidate,conflict=self.fixture()
        model=M68kFallthroughRepairs(image)
        requests=[]
        result=model.discover({source.cpu_address:source},{source.cpu_address:source},{},
                              decode_request=lambda *args:requests.append(args))
        self.assertFalse(result)
        self.assertFalse(model.repairs)
        self.assertEqual((candidate.cpu_address,source.cpu_address),requests[0][:2])
        self.assertNotIn('REPAIR',model.plan_text())

    def test_replay_plan_survives_target_becoming_trusted(self):
        image,source,candidate,conflict=self.fixture()
        model=M68kFallthroughRepairs(image)
        raw={source.cpu_address:source,conflict.cpu_address:conflict}
        model.discover(raw,{source.cpu_address:source},{candidate.cpu_address:candidate})
        trusted={source.cpu_address:source,candidate.cpu_address:candidate}
        self.assertFalse(model.discover(trusted,trusted,{}))
        text=model.plan_text(protected_ranges=((0x308,0x30a),),planned_roots=(0x308,))
        self.assertIn('TRUSTED\t000302\t203c4e750001',text)
        self.assertIn('PROTECT_DATA\t000308\t00030A',text)
        self.assertIn('ROOT\t000308',text)
        self.assertIn('REPAIR\t000300\t7001\t000302\t203c4e750001\t000304:4e75',text)

    def test_budget_and_repeated_proof_do_not_keep_convergence_alive(self):
        image,source,candidate,conflict=self.fixture()
        model=M68kFallthroughRepairs(image,max_repairs=1)
        args=({source.cpu_address:source},{source.cpu_address:source},{candidate.cpu_address:candidate})
        self.assertEqual(1,len(model.discover(*args)))
        self.assertFalse(model.discover(*args))
        self.assertEqual(1,len(model.repairs))

    def test_changed_backend_conflict_refreshes_persistent_proof(self):
        image,source,_,_=self.fixture()
        candidate=instruction(0x302,'203c00000000','MOVE.L','#0x0|D0')
        first=instruction(0x304,'00000000','ORI.B','#0x0|D0b')
        second=instruction(0x306,'00000000','ORI.B','#0x0|D0b')
        data=bytearray(image.data)
        data[0x302:0x30a]=bytes.fromhex('203c000000000000')
        model=M68kFallthroughRepairs(replace(image,data=bytes(data)))
        trusted={source.cpu_address:source}
        probes={candidate.cpu_address:candidate}
        self.assertEqual(1,len(model.discover({**trusted,0x304:first},trusted,probes)))
        refreshed=model.discover({**trusted,0x306:second},trusted,probes)
        self.assertEqual(1,len(refreshed))
        self.assertEqual(0x306,refreshed[0].conflicts[0].address)
        self.assertFalse(model.discover({**trusted,0x306:second},trusted,probes))
        self.assertIn('000306:00000000',model.plan_text())
        self.assertNotIn('000304:00000000',model.plan_text())


if __name__=='__main__':
    unittest.main()
