"""Repairs require another import, but never grant speculative code a root."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from retrolarium_disasm.megadrive import pipeline
from retrolarium_disasm.m68k.repair.fallthrough import M68kFallthroughRepairs
from retrolarium_disasm.m68k.dispatch.ram import InlineTrapCall
from test_megadrive_pipeline_convergence import _M68kHarness, _StopAfterLoop, _image
from test_megadrive_z80 import fact


def instruction(address, raw, mnemonic, operands='', **kwargs):
    raw = bytes.fromhex(raw)
    return replace(fact(address, mnemonic, operands), raw=raw, length=len(raw), **kwargs)


class FallthroughConvergenceTests(unittest.TestCase):
    def run_pipeline(self, passes, *, budget=4096):
        source = instruction(0x240, '4e71', 'NOP')
        candidate = instruction(0x242, '303c1234', 'MOVE.W', '#0x1234|D0w')
        conflict = instruction(0x244, '1234', 'MOVE.B', '(A4,D0w)|D1b')
        tail = instruction(0x246, '4e75', 'RTS', flow_type='TERMINATOR')
        other_source = instruction(0x280, '4e71', 'NOP')
        other_candidate = instruction(0x282, '4e75', 'RTS', flow_type='TERMINATOR')
        image = _image()
        data = bytearray(image.data)
        for item in (source, candidate, tail, other_source, other_candidate):
            data[item.cpu_address:item.cpu_address + item.length] = item.raw
        image.data = bytes(data)
        harness = _M68kHarness(passes)
        original = pipeline._discover_fallthrough_repairs

        def discover(repairs, image, trusted, raw, artifacts, inline, roots, request, context):
            current = harness._current()
            known = {source.cpu_address: source}
            decoded = {**known, candidate.cpu_address: candidate}
            raw = {**known, conflict.cpu_address: conflict, tail.cpu_address: tail}
            if current.get('second_candidate'):
                known[other_source.cpu_address] = other_source
                raw[other_source.cpu_address] = other_source
                decoded[other_candidate.cpu_address] = other_candidate
            if current.get('repaired'):
                raw.pop(conflict.cpu_address)
                raw[candidate.cpu_address] = candidate
                known[candidate.cpu_address] = candidate
            context = SimpleNamespace(decoded=decoded, protected=())
            return original(repairs, image, known, raw, artifacts, inline, roots, request, context)

        patches = harness.patches()
        patches.update(load_megadrive=lambda _: image,
                       _discover_fallthrough_repairs=discover,
                       M68kFallthroughRepairs=lambda image: M68kFallthroughRepairs(image, max_repairs=budget))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.multiple(pipeline, **patches), self.assertRaises(_StopAfterLoop):
                pipeline.analyze_megadrive(root / 'rom.bin', root / 'output', root / 'ghidra')
            progress = json.loads((root / 'output/m68k/decoder-passes.json').read_text())
            plan = (root / 'output/m68k/fallthrough-repairs.tsv').read_text()
            report = json.loads((root / 'output/m68k/fallthrough-repairs.json').read_text())
        return harness, progress, plan, report

    def test_repair_forces_import_and_persists_without_becoming_seed(self):
        harness, progress, plan, report = self.run_pipeline([{}, {'repaired': True}])
        self.assertEqual(['', ''], harness.plans_seen)
        self.assertEqual([set(), set()], harness.interpreter_entrypoints)
        self.assertEqual('', harness.repair_plans_seen[0])
        repair = 'REPAIR\t000240\t4e71\t000242\t303c1234\t000244:1234'
        self.assertIn(repair, harness.repair_plans_seen[1])
        self.assertIn(repair, plan)
        self.assertEqual([0x242], progress['passes'][0]['new_fallthrough_repair_addresses'])
        self.assertEqual([], progress['passes'][1]['new_fallthrough_repair_addresses'])
        self.assertTrue(progress['converged'])
        self.assertTrue(progress['candidate_repair_complete'])
        self.assertEqual('proven', report['repairs'][0]['confidence'])

    def test_new_inline_data_reaches_replay_protection_in_same_pass(self):
        call = InlineTrapCall(0x240, 0x242, 0x244, 0x300, 0x300)
        harness, progress, plan, _ = self.run_pipeline([{}, {'inline': (call,)}, {'inline': (call,)}])
        self.assertEqual(3, len(harness.plans_seen))
        self.assertIn('PROTECT_DATA\t000242\t000244', harness.repair_plans_seen[2])
        self.assertIn('PROTECT_DATA\t000242\t000244', plan)
        self.assertNotIn('ROOT\t000242', plan)
        self.assertTrue(progress['converged'])

    def test_repair_budget_reports_incomplete_candidates_without_infinite_passes(self):
        harness, progress, _, report = self.run_pipeline([{'second_candidate': True}], budget=1)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertTrue(progress['converged'])
        self.assertFalse(progress['candidate_repair_complete'])
        self.assertEqual([0x282], report['deferred_addresses'])
        self.assertEqual(1, progress['passes'][-1]['deferred_fallthrough_repair_count'])

    def test_wrapper_converts_physical_protections_to_logical_addresses(self):
        image = SimpleNamespace(header=SimpleNamespace(rom_start=0x1000))
        recorded = {}
        collector = SimpleNamespace(discover=lambda *args, **kwargs: recorded.update(kwargs))
        context = SimpleNamespace(decoded={}, protected=((0x20, 0x28),))
        pipeline._discover_fallthrough_repairs(collector, image, {}, {}, None,
            {0x1040: 4}, {0x1000}, None, context)
        self.assertEqual(((0x1020, 0x1028), (0x1040, 0x1044)), recorded['protected_ranges'])
        self.assertEqual({0x1000}, recorded['planned_roots'])


if __name__ == '__main__':
    unittest.main()
