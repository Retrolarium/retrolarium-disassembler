import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from retrolarium_disassembler.m68k.repair import overlay
from retrolarium_disassembler.ghidra import GhidraArtifacts
from retrolarium_disassembler.m68k.repair.probe_requests import M68kProbeRequests
from m68k.repair.builders import HEADER, row
from megadrive.builders import fact
from retrolarium_disassembler.facts import InstructionReference


class OverlayProbeTests(unittest.TestCase):
    def test_pseudo_absolute_word_targets_use_same_bus_normalization_as_raw(self):
        instruction = fact(0xFF2000, "JSR", "(0x9000).w", flows=(0xFFFF9000,),
            references=(InstructionReference(0xFFFF9000, "READ", 0),))
        normalized = overlay._normalize_bus_targets({0xFF2000: instruction})[0xFF2000]
        self.assertEqual((0xFF9000,), normalized.flows)
        self.assertEqual(0xFF9000, normalized.references[0].address)

    def run_overlay(self, requests, *, budget=4096, raw_collision=False):
        plans, entries, decoded_seen = [], [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.bin"
            source.write_bytes(bytes.fromhex("4E75") + b"\xff" * 62)

            def decode(path, workspace, *args, entry_addresses, probe_requests, **kwargs):
                plans.append(probe_requests.read_text())
                entries.append(entry_addresses)
                facts = workspace / "instructions.tsv"
                facts.write_text(HEADER + row(0x1000, "4E75", "RTS"))
                probes = workspace / "unused-probes.tsv"
                # A valid but unrooted speculative island must not be emitted.
                text = row(0x1020, "FFFF", "ORI.B") if len(plans) > 1 else ""
                if raw_collision:
                    text += row(0x1000, "4E75", "FAKE_PROBE")
                probes.write_text(HEADER + text)
                return GhidraArtifacts(facts, workspace / "report.json", workspace / "log", probes)

            def validator(image, known, decoded, *, decode_request, **kwargs):
                decoded_seen.append(decoded)
                for address in requests:
                    decode_request(address, 0x1000, "failed dispatch witness")
                return lambda _: False

            with patch.object(overlay, "run_m68k_overlay_analysis", decode), \
                    patch.object(overlay, "make_dispatch_handler_validator", validator), \
                    patch.object(overlay, "M68kProbeRequests", lambda image, **kwargs: M68kProbeRequests(image, max_requests=budget, **kwargs)):
                artifacts = overlay.analyze_overlay(source, root / "analysis", root, root,
                    base_address=0x1000, entry_addresses=(0x1000,))
            with artifacts.facts.open() as stream:
                emitted = list(csv.DictReader(stream, delimiter="\t"))
            progress = json.loads((root / "analysis/decoder-passes.json").read_text())
            report = json.loads((root / "analysis/decode-probe-requests.json").read_text())
        return plans, entries, emitted, progress, report, decoded_seen

    def test_early_overlay_request_drives_one_extra_pass_without_becoming_root(self):
        plans, entries, emitted, progress, report, _ = self.run_overlay((0x1020,))
        self.assertEqual(["", "001020\t001040\n"], plans)
        self.assertEqual([(0x1000,), (0x1000,)], entries)
        self.assertEqual(["00001000"], [r["address"] for r in emitted])
        self.assertEqual([0x1020], progress["passes"][0]["new_probe_request_addresses"])
        self.assertEqual([], progress["passes"][1]["new_probe_request_addresses"])
        self.assertEqual(1, progress["passes"][1]["new_probe_fact_count"])
        self.assertTrue(progress["converged"])
        self.assertEqual("hypothesis", report["requests"][0]["stage"])
        self.assertEqual("untrusted", report["requests"][0]["confidence"])

    def test_padding_prefix_outside_module_odd_and_known_requests_are_ignored(self):
        plans, _, _, progress, report, _ = self.run_overlay((0x200, 0xFFE, 0x1000, 0x1021, 0x1040))
        self.assertEqual([""], plans)
        self.assertTrue(progress["converged"])
        self.assertEqual([], report["requests"])

    def test_deferred_budget_work_does_not_prevent_code_fixed_point(self):
        plans, _, _, progress, report, _ = self.run_overlay((0x1020, 0x1022), budget=1)
        self.assertEqual(2, len(plans))
        self.assertTrue(progress["converged"])
        self.assertFalse(progress["candidate_probing_complete"])
        self.assertEqual(1, progress["passes"][-1]["deferred_probe_request_count"])
        self.assertEqual([0x1022], report["deferred_addresses"])
        self.assertEqual(1, report["max_requests"])
        self.assertEqual(2048, report["max_bytes"])

    def test_raw_backend_fact_has_precedence_over_overlapping_probe(self):
        *_, decoded_seen = self.run_overlay((), raw_collision=True)
        self.assertEqual("RTS", decoded_seen[0][0x1000].mnemonic)


if __name__ == "__main__":
    unittest.main()
