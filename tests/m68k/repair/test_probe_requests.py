import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))
from retrolarium_disassembler.m68k.repair.probe_requests import M68kProbeRequests
from retrolarium_disassembler.megadrive import pipeline
from megadrive.pipeline_harness import _M68kHarness, _StopAfterLoop


class ProbeRequestTests(unittest.TestCase):
    def setUp(self):
        self.image = SimpleNamespace(data=bytes(0x4000), header=SimpleNamespace(rom_start=0))

    def test_hypothesis_is_bounded_by_next_known_instruction_and_never_a_root(self):
        collector = M68kProbeRequests(self.image)
        known = {0x300: SimpleNamespace(cpu_address=0x300, length=6)}
        collector.update_known(known)
        self.assertTrue(collector.request(0x240, 0x210, 'consumer hypothesis'))
        request = collector.requests[0x240]
        self.assertEqual((0x300, 'hypothesis', 'untrusted'), (request.end, request.stage, request.confidence))
        self.assertEqual({0x300}, set(known))
        self.assertEqual('000240\t000300\n', collector.plan_text())

    def test_explicit_module_lower_bound_does_not_reserve_cartridge_header(self):
        collector = M68kProbeRequests(self.image, minimum_address=0)
        self.assertTrue(collector.request(0x20))
        self.assertFalse(M68kProbeRequests(self.image).request(0x20))
        overlay = M68kProbeRequests(self.image, minimum_address=0x1000)
        self.assertFalse(overlay.request(0xFFE))
        self.assertTrue(overlay.request(0x1020))

    def test_entry_interior_header_odd_and_outside_rom_do_not_schedule(self):
        collector = M68kProbeRequests(self.image)
        collector.update_known({0x300: SimpleNamespace(cpu_address=0x300, length=6)})
        for address in (0x300, 0x302, 0x304, 0x1FE, 0x241, -2, 0x4000):
            self.assertFalse(collector.request(address), hex(address))
        self.assertEqual({}, collector.requests)

    def test_maximum_span_rom_end_duplicates_and_separate_images(self):
        collector = M68kProbeRequests(self.image)
        self.assertTrue(collector.request(0x400))
        self.assertEqual(0xC00, collector.requests[0x400].end)
        self.assertFalse(collector.request(0x400))
        self.assertTrue(collector.request(0x3FFE))
        self.assertEqual(0x4000, collector.requests[0x3FFE].end)
        self.assertTrue(M68kProbeRequests(self.image).request(0x400))

    def test_budget_deferral_is_explicit_and_cannot_schedule_endlessly(self):
        collector = M68kProbeRequests(self.image, max_requests=1)
        self.assertTrue(collector.request(0x400))
        for _ in range(3):
            self.assertFalse(collector.request(0x500))
        self.assertEqual({0x500}, collector.deferred)
        collector.update_known({0x500: SimpleNamespace(cpu_address=0x500, length=2)})
        self.assertFalse(collector.deferred)


class ProbeConvergenceTests(unittest.TestCase):
    def run_harness(self, harness, *, budget=None):
        def validator(*args, decode_request=None, **kwargs):
            for address in harness._current().get('probe_requests', ()):
                decode_request(address, 0x200, 'failed structural witness')
            return lambda _: False
        patches = harness.patches()
        patches['_dispatch_handler_validator'] = validator
        if budget is not None:
            patches['M68kProbeRequests'] = lambda image: M68kProbeRequests(image, max_requests=budget)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.multiple(pipeline, **patches), self.assertRaises(_StopAfterLoop):
                pipeline.analyze_megadrive(root / 'rom.bin', root / 'output', root / 'ghidra')
            return json.loads((root / 'output/m68k/decoder-passes.json').read_text())

    def test_new_request_forces_backend_pass_without_promoting_any_seed(self):
        harness = _M68kHarness([{'probe_requests': (0x280,)}, {'probe_requests': (0x280,)}])
        progress = self.run_harness(harness)
        self.assertEqual(['', ''], harness.plans_seen)
        self.assertEqual(['', '000280\t000400\n'], harness.probe_plans_seen)
        self.assertEqual([set(), set()], harness.interpreter_entrypoints)
        self.assertEqual([0x280], progress['passes'][0]['new_probe_request_addresses'])
        self.assertEqual([], progress['passes'][1]['new_probe_request_addresses'])
        self.assertTrue(progress['converged'])

    def test_invalid_requests_do_not_prevent_convergence(self):
        harness = _M68kHarness([{'probe_requests': (0x281, 0x100, 0x400)}])
        progress = self.run_harness(harness)
        self.assertEqual([''], harness.plans_seen)
        self.assertTrue(progress['converged'])

    def test_budget_exhaustion_reports_incomplete_probing_and_code_fixpoint(self):
        harness = _M68kHarness([{'probe_requests': (0x280, 0x282)}])
        progress = self.run_harness(harness, budget=1)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertTrue(progress['converged'])
        self.assertFalse(progress['candidate_probing_complete'])
        self.assertEqual(1, progress['passes'][-1]['deferred_probe_request_count'])


if __name__ == '__main__':
    unittest.main()
