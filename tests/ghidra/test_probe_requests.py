import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_ghidra
from retrolarium_disasm.ghidra import GhidraError, run_megadrive_analysis, run_m68k_overlay_analysis


class GhidraProbeRequestTests(unittest.TestCase):
    def test_overlay_probe_plan_uses_real_base_and_never_enters_seed_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests.tsv'
            requests.write_text('FF2002\tFF2010\n')
            with patch('retrolarium_disasm.ghidra._run_analysis') as backend:
                run_m68k_overlay_analysis(root / 'module.bin', root / 'analysis', root, root,
                    base_address=0xFF1F00, entry_addresses=(0xFF2000,),
                    probe_orphans=True, probe_requests=requests)
            kwargs = backend.call_args.kwargs
            self.assertEqual(requests, kwargs['probe_requests'])
            arguments = kwargs['import_arguments']
            self.assertEqual('0x00FF1F00', arguments[arguments.index('-loader-baseAddr') + 1])
            self.assertEqual('00FF2000\n', (root / 'analysis/overlay-seeds.txt').read_text())

    def test_probe_plan_is_only_passed_to_pseudo_decoder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, home, scripts = test_ghidra.GhidraBackendTests.fake_layout(root)
            seeds = root / 'seeds.txt'
            seeds.write_text('000200\n')
            requests = root / 'requests.tsv'
            requests.write_text('000400\t000500\n')

            def complete(command, **kwargs):
                Path(command[command.index('InspectProgram.java') + 1]).write_text(
                    json.dumps({'language': '68000:BE:32:default'}))
                Path(command[command.index('ExportInstructionFacts.java') + 1]).write_text('facts')
                index = command.index('ProbeM68kUnusedCode.java')
                Path(command[index + 1]).write_text('speculative facts')
                self.assertEqual(str(requests.resolve()), command[index + 2])
                self.assertEqual(str(seeds.resolve()), command[command.index('SeedMegaDriveVectors.java') + 1])
                self.assertEqual(str(seeds.resolve()), command[command.index('RestoreM68kPlannedSeeds.java') + 1])
                return subprocess.CompletedProcess(command, 0, 'ok')

            with patch('retrolarium_disasm.ghidra.subprocess.run', side_effect=complete):
                artifacts = run_megadrive_analysis(image, root / 'out', home, scripts,
                    seed_plan=seeds, probe_orphans=True, probe_requests=requests)
            self.assertEqual('000200\n', seeds.read_text())
            self.assertEqual('speculative facts', artifacts.orphan_facts.read_text())

    def test_missing_plan_or_disabled_probing_is_an_explicit_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, home, scripts = test_ghidra.GhidraBackendTests.fake_layout(root)
            seeds = root / 'seeds.txt'
            seeds.write_text('000200\n')
            for enabled in (True, False):
                with self.assertRaisesRegex(GhidraError, 'probe requests'):
                    run_megadrive_analysis(image, root / 'out', home, scripts,
                        seed_plan=seeds, probe_orphans=enabled, probe_requests=root / 'missing.tsv')


if __name__ == '__main__':
    unittest.main()
