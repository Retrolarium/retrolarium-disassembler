"""Physical scan bounds preserve pointer schemas without indexing FF prefixes."""
from array import array
from dataclasses import replace
from unittest.mock import patch
import unittest

from retrolarium_kit import megadrive_pointers as pointers
from retrolarium_kit import m68k_seeds as seeds
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.m68k_overlay import address_view
from test_megadrive_z80 import fact


class PointerScanBoundTests(unittest.TestCase):
    def image_and_facts(self,base):
        data=bytearray(b'\xff'*0x100)
        targets=(base+0x80,base+0x84,base+0x88,base+0x8c)
        for index,target in enumerate(targets):
            data[0x10+index*4:0x14+index*4]=target.to_bytes(4,'big')
            data[target-base:target-base+2]=bytes.fromhex('4e75')
            data[0x30+index*2:0x32+index*2]=(target-(base+0x30)).to_bytes(2,'big')
            data[0x50+index*2:0x52+index*2]=(target-(base+0x50+index*2)).to_bytes(2,'big')
        readers=[]
        for site,table in ((base,base+0x10),(base+4,base+0x30),(base+8,base+0x50)):
            readers.append(replace(fact(site,'LEA',f'(0x{table:x}).l|A0'),
                references=(InstructionReference(table,'DATA',0),)))
        facts={f.physical_offset:f for f in (*readers,*(fact(a,'RTS','') for a in targets))}
        return address_view(bytes(data),base,(base,)),facts

    def test_ff_prefix_bound_preserves_every_candidate_field(self):
        image,facts=self.image_and_facts(0x2000)
        full=pointers.detect_pointer_candidates(image,facts)
        bounded=pointers.detect_pointer_candidates(image,facts,scan_start=0x2000)
        self.assertEqual([c.as_dict() for c in full],[c.as_dict() for c in bounded])
        schemas={c.schema_id for c in bounded if c.status=='accepted'}
        self.assertIn('megadrive.u32be.absolute',schemas)
        self.assertIn('megadrive.s16be.target-table_base',schemas)
        self.assertIn('megadrive.s16be.target-entry_address',schemas)

    def test_default_is_explicit_200(self):
        image,facts=self.image_and_facts(0x400)
        self.assertEqual(pointers.detect_pointer_candidates(image,facts),
                         pointers.detect_pointer_candidates(image,facts,scan_start=0x200))

    def test_high_overlay_suffix_arrays_use_only_actual_module_bytes(self):
        base=0xff2000
        image=address_view(bytes.fromhex('70004e75ffffffff'),base,(base,))
        facts={base:fact(base,'MOVEQ','#0|D0'),base+2:fact(base+2,'RTS','')}
        copied=[]
        def counted_array(typecode,values):
            if isinstance(values,bytes):copied.append(len(values))
            return array(typecode,values)
        with patch.object(pointers,'array',side_effect=counted_array), \
                patch.object(pointers,'_mapped',wraps=pointers._mapped) as mapped, \
                patch.object(seeds,'_word',wraps=seeds._word) as ram_loader_words:
            result=pointers.detect_pointer_candidates(image,facts,scan_start=base)
        self.assertEqual([8,8],copied)
        self.assertLessEqual(mapped.call_count,8)
        self.assertEqual(0,ram_loader_words.call_count)
        self.assertEqual(['megadrive.m68k-vectors.u32be-masked24'],[c.schema_id for c in result])

    def test_scan_bound_may_be_at_or_beyond_image_end(self):
        image,facts=self.image_and_facts(0x400)
        for start in (len(image.data),len(image.data)+2):
            result=pointers.detect_pointer_candidates(image,{},scan_start=start)
            self.assertEqual(['megadrive.m68k-vectors.u32be-masked24'],[c.schema_id for c in result])

    def test_invalid_physical_bound_is_rejected(self):
        image,facts=self.image_and_facts(0x400)
        for start in (-2,0x401,2.5):
            with self.subTest(start=start),self.assertRaises(ValueError):
                pointers.detect_pointer_candidates(image,facts,scan_start=start)


if __name__=='__main__':unittest.main()
