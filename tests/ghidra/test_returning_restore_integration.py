"""Opt-in real Ghidra smoke: RETROLARIUM_RUN_GHIDRA_TESTS=1."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / 'src'))
from retrolarium_disassembler.ghidra import find_headless


@unittest.skipUnless(os.environ.get('RETROLARIUM_RUN_GHIDRA_TESTS') == '1', 'real Ghidra smoke is opt-in')
class ReturningRestoreIntegrationTests(unittest.TestCase):
    def test_only_protected_planned_walker_decodes_call_continuations(self):
        ghidra = Path(os.environ.get('RETROLARIUM_GHIDRA_HOME', KIT / '.tools/ghidra'))
        with tempfile.TemporaryDirectory(prefix='m68k_return_smoke_') as temporary:
            root = Path(temporary)
            image = bytearray(b'\xff' * 0x400)
            for offset, raw in {
                0x200:'4eb90000030070004e75', 0x220:'4eb900000300203c112233444e75',
                0x240:'4eb900000300303c4e754e75', 0x260:'4eb900000300203c4e7500014e75',
                0x280:'4eb9000003004e75', 0x2a0:'4eb90000030070004e75', 0x300:'4e75',
            }.items():
                image[offset:offset+len(raw)//2] = bytes.fromhex(raw)
            rom = root / 'fixture.bin'
            rom.write_bytes(image)
            return_plan = root / 'normal-return-calls.txt'
            return_plan.write_text(''.join(f'{a:06X} {a+6:06X}\n' for a in (0x200,0x220,0x240,0x260,0x280,0x2a0)))
            seed_plan = root / 'seeds.txt'
            # The $286 continuation was superseded by inline DATA and removed
            # from the root plan. $2A6 is an intentionally unplanned target.
            seed_plan.write_text('DATA 00022A 2\nDATA 000286 2\n000206\n000226\n000246\n000266\n')
            scripts = root / 'scripts'
            scripts.mkdir()
            for name in ('RestoreM68kReturningCalls.java', 'RestoreM68kPlannedSeeds.java'):
                shutil.copy2(KIT / 'src/retrolarium_disassembler/ghidra/scripts' / name, scripts)
            shutil.copy2(KIT / 'tests/ghidra_scripts/VerifyM68kReturningCalls.java', scripts)
            command = [str(find_headless(ghidra)),str(root),'return_smoke','-import',str(rom),
                       '-loader','BinaryLoader','-loader-blockName','ROM','-loader-baseAddr','0',
                       '-processor','68000:BE:32:default','-noanalysis','-scriptPath',str(scripts),
                       '-postScript','VerifyM68kReturningCalls.java',str(return_plan),str(seed_plan),'-deleteProject']
            environment = dict(os.environ)
            for key in ('APPDATA','LOCALAPPDATA','XDG_CONFIG_HOME','XDG_CACHE_HOME'):
                folder = root / key.lower()
                folder.mkdir()
                environment[key] = str(folder)
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors='replace', timeout=180,
                                    env=environment,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.assertEqual(0, result.returncode, result.stdout[-12000:])
            self.assertNotIn('REPORT SCRIPT ERROR:', result.stdout, result.stdout[-12000:])
            self.assertIn('[PASS] normal-return restoration uses protected', result.stdout, result.stdout[-12000:])


if __name__ == '__main__':
    unittest.main()
