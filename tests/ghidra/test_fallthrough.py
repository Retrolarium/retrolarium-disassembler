"""Backend ordering and address-space contracts for canonical repairs."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_ghidra
from retrolarium_disassembler.ghidra import GhidraError, run_megadrive_analysis, run_m68k_overlay_analysis


def complete(command, **kwargs):
    Path(command[command.index('InspectProgram.java') + 1]).write_text(
        json.dumps({'language':'68000:BE:32:default'}))
    Path(command[command.index('ExportInstructionFacts.java') + 1]).write_text('facts')
    return subprocess.CompletedProcess(command, 0, 'ok')


class GhidraFallthroughTests(unittest.TestCase):
    def test_cartridge_overrides_then_roots_then_repairs_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, home, scripts = test_ghidra.GhidraBackendTests.fake_layout(root)
            seeds = root / 'seeds.txt'
            seeds.write_text('000206\n')
            returns = root / 'normal-return-calls.txt'
            returns.write_text('000200 000206\n')
            repairs = root / 'fallthrough-repairs.tsv'
            repairs.write_text('REPAIR\t000300\t7001\t000302\t4e75\t-\n')
            with patch('retrolarium_disassembler.ghidra.subprocess.run',side_effect=complete) as backend:
                run_megadrive_analysis(image,root/'out',home,scripts,
                                      seed_plan=seeds,fallthrough_repairs=repairs)
            command = backend.call_args.args[0]
            returning = [i for i,name in enumerate(command) if name == 'RestoreM68kReturningCalls.java']
            self.assertEqual(2,len(returning))
            self.assertEqual(['-preScript','-postScript'],[command[i-1] for i in returning])
            self.assertEqual([str(returns.resolve())]*2,[command[i+1] for i in returning])
            ordered = [command.index(name,returning[1]) for name in (
                'RestoreM68kReturningCalls.java','RestoreM68kPlannedSeeds.java',
                'RestoreM68kFallthrough.java','ExportInstructionFacts.java')]
            self.assertEqual(ordered,sorted(ordered))
            for name,plan in (('RestoreM68kReturningCalls.java',returns),
                              ('RestoreM68kPlannedSeeds.java',seeds),
                              ('RestoreM68kFallthrough.java',repairs)):
                index = command.index(name,returning[1])
                self.assertEqual('-postScript',command[index-1])
                self.assertEqual(str(plan.resolve()),command[index+1])
            self.assertEqual('000206\n',seeds.read_text())

    def test_overlay_repairs_use_real_load_base_and_precede_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, home, scripts = test_ghidra.GhidraBackendTests.fake_layout(root)
            repairs = root / 'fallthrough-repairs.tsv'
            repairs.write_text('REPAIR\tFF2000\t7001\tFF2002\t4e75\t-\n')
            with patch('retrolarium_disassembler.ghidra.subprocess.run',side_effect=complete) as backend:
                run_m68k_overlay_analysis(image,root/'out',home,scripts,base_address=0xFF1F00,
                                          entry_addresses=(0xFF2000,),fallthrough_repairs=repairs)
            command = backend.call_args.args[0]
            repair_index = command.index('RestoreM68kFallthrough.java')
            export_index = command.index('ExportInstructionFacts.java')
            self.assertLess(repair_index,export_index)
            self.assertEqual('-postScript',command[repair_index-1])
            self.assertEqual(str(repairs.resolve()),command[repair_index+1])
            self.assertEqual('CD_MODULE',command[export_index+2])
            self.assertEqual('0x00FF1F00',command[command.index('-loader-baseAddr')+1])
            self.assertNotIn('RestoreM68kPlannedSeeds.java',command)
            self.assertEqual('00FF2000\n',(root/'out/overlay-seeds.txt').read_text())

    def test_explicit_missing_repair_plan_fails_before_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seeds = root / 'seeds.txt'
            seeds.write_text('000200\n')
            for overlay in (False,True):
                with self.subTest(overlay=overlay):
                    with patch('retrolarium_disassembler.ghidra._run_analysis') as backend:
                        with self.assertRaisesRegex(GhidraError,'fallthrough repair plan not found'):
                            if overlay:
                                run_m68k_overlay_analysis(root/'game.bin',root/'out',root,root,
                                    base_address=0x10000,entry_addresses=(0x10000,),
                                    fallthrough_repairs=root/'missing.tsv')
                            else:
                                run_megadrive_analysis(root/'game.bin',root/'out',root,root,
                                    seed_plan=seeds,fallthrough_repairs=root/'missing.tsv')
                        backend.assert_not_called()


if __name__ == '__main__':
    unittest.main()
