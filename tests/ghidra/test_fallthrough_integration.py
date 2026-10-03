"""Opt-in actual decoder test: RETROLARIUM_RUN_GHIDRA_TESTS=1."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from retrolarium_kit.ghidra import find_headless

KIT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('RETROLARIUM_RUN_GHIDRA_TESTS')=='1','real Ghidra smoke is opt-in')
class FallthroughIntegrationTests(unittest.TestCase):
    def test_conflicts_guards_persistence_and_overlay_origin(self):
        ghidra=Path(os.environ.get('RETROLARIUM_GHIDRA_HOME',KIT/'.tools/ghidra'))
        for base,block in ((0,'ROM'),(0x200000,'CD_MODULE')):
            with self.subTest(base=base),tempfile.TemporaryDirectory(prefix='m68k_fallthrough_') as temporary:
                root=Path(temporary)
                image=bytearray(b'\xff'*0x500)
                for source in (0x200,0x240,0x280,0x2c0,0x300,0x340,0x380):
                    image[source:source+12]=bytes.fromhex('7001203c4e7500014e714e75')
                image[0x440:0x444]=bytes.fromhex('70016a01')
                image[0x3c0:0x3c6]=bytes.fromhex('700100000000')
                image[0x400:0x406]=bytes.fromhex('7001ffffffff')
                rom=root/'fixture.bin';rom.write_bytes(image)
                def record(source,conflicts=True,union=False):
                    target=source+2
                    raw={0x440:'6a01',0x3c0:'00000000',0x400:'ffffffff'}.get(source,'203c4e750001')
                    allowed=f'{base+source+4:06X}:4e75' if conflicts else '-'
                    if union:allowed+=f',{base+source+6:06X}:00014e71'
                    return f'REPAIR\t{base+source:06X}\t7001\t{base+target:06X}\t{raw}\t{allowed}\n'
                def code(address,raw):return f'TRUSTED\t{base+address:06X}\t{raw}\n'
                def data(address,length):return f'PROTECT_DATA\t{base+address:06X}\t{base+address+length:06X}\n'
                positive=record(0x200)+record(0x240,union=True)
                canonical=code(0x202,'203c4e750001')+code(0x242,'203c4e750001')
                texts=[
                    # A backend-decoded full extension may exceed the legal
                    # repair width. Keep its entire span protected in the plan.
                    code(0x480,'ffffffffffffffffffffffff')
                    +data(0x2c4,2)+data(0x348,2)+f'ROOT\t{base+0x304:06X}\n'+positive
                    +record(0x280)+record(0x2c0)+record(0x300)+record(0x340,union=True)
                    +record(0x380,conflicts=False)+record(0x440,conflicts=False),
                    canonical+code(0x248,'4e71')+positive,
                    canonical+data(0x248,2)+positive,
                    data(0x200,2)+record(0x200),
                    data(0x204,2)+record(0x200),
                ]
                # These deliberately emulate old plans generated before the
                # Python padding gate existed. Java must independently reject
                # the legal all-zero ORI instruction and the all-FF stream.
                texts[0]+=record(0x3c0,conflicts=False)+record(0x400,conflicts=False)
                plans=[]
                for i,text in enumerate(texts):
                    plan=root/f'plan{i}.tsv';plan.write_text(text);plans.append(str(plan))
                scripts=root/'scripts';scripts.mkdir()
                shutil.copy2(KIT/'src/retrolarium_kit/ghidra_scripts/RestoreM68kFallthrough.java',scripts)
                shutil.copy2(KIT/'tests/ghidra_scripts/VerifyM68kFallthrough.java',scripts)
                command=[str(find_headless(ghidra)),str(root),'fallthrough_smoke','-import',str(rom),
                    '-loader','BinaryLoader','-loader-blockName',block,'-loader-baseAddr',f'0x{base:X}',
                    '-processor','68000:BE:32:default','-noanalysis','-scriptPath',str(scripts),
                    '-postScript','VerifyM68kFallthrough.java',*plans,'-deleteProject']
                environment=dict(os.environ)
                for key in ('APPDATA','LOCALAPPDATA','XDG_CONFIG_HOME','XDG_CACHE_HOME'):
                    location=root/key.lower()
                    location.mkdir()
                    environment[key]=str(location)
                result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                      text=True,errors='replace',timeout=180,env=environment)
                self.assertEqual(0,result.returncode,result.stdout[-12000:])
                self.assertNotIn('REPORT SCRIPT ERROR:',result.stdout,result.stdout[-12000:])
                self.assertIn('[PASS] canonical repair protects',result.stdout,result.stdout[-12000:])
                self.assertIn('proofs satisfied=2 of 10',result.stdout,result.stdout[-12000:])
                self.assertEqual(2,result.stdout.count('proofs satisfied=0 of 1'))


if __name__=='__main__':unittest.main()
