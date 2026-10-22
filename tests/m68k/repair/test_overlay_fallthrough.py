"""Overlay repair plans use module addresses without promoting their targets."""

import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from retrolarium_disassembler.m68k.repair import overlay
from retrolarium_disassembler.ghidra import GhidraArtifacts
from m68k.repair.builders import HEADER, row


class OverlayFallthroughTests(unittest.TestCase):
    def test_canonical_repair_drives_next_pass_at_module_load_address(self):
        plans, entries = [], []
        base = 0xFF2000
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.bin"
            source.write_bytes(bytes.fromhex("4e71303c12344e75"))

            def decode(path, workspace, *args, entry_addresses, fallthrough_repairs, **kwargs):
                plans.append(fallthrough_repairs.read_text())
                entries.append(entry_addresses)
                text = row(base, "4e71", "NOP", flow="FALL_THROUGH")
                if "REPAIR" in plans[-1]:
                    text += row(base + 2, "303c1234", "MOVE.W", "#0x1234|D0w", flow="FALL_THROUGH")
                else:
                    text += row(base + 4, "1234", "MOVE.B", "(A4,D0w)|D1b", flow="FALL_THROUGH")
                text += row(base + 6, "4e75", "RTS")
                facts = workspace / "instructions.tsv"
                facts.write_text(HEADER + text)
                probes = workspace / "probes.tsv"
                probes.write_text(HEADER + row(base + 2, "303c1234", "MOVE.W", "#0x1234|D0w", flow="FALL_THROUGH"))
                return GhidraArtifacts(facts, workspace / "report.json", workspace / "log", probes)

            with patch.object(overlay, "run_m68k_overlay_analysis", decode):
                result = overlay.analyze_overlay(
                    source, root / "analysis", root, root, base_address=base, entry_addresses=(base,)
                )
            with result.facts.open() as stream:
                addresses = [int(item["address"], 16) for item in csv.DictReader(stream, delimiter="\t")]
            report = json.loads((root / "analysis/decoder-passes.json").read_text())
            repair_report = json.loads((root / "analysis/fallthrough-repairs.json").read_text())
        self.assertEqual([(base,), (base,)], entries)
        self.assertEqual("", plans[0])
        self.assertIn(f"REPAIR\t{base:06X}\t4e71\t{base + 2:06X}\t303c1234\t{base + 4:06X}:1234", plans[1])
        self.assertEqual([base, base + 2, base + 6], addresses)
        self.assertTrue(report["converged"])
        self.assertEqual([base + 2], report["passes"][0]["new_fallthrough_repair_addresses"])
        self.assertEqual([], report["passes"][1]["new_fallthrough_repair_addresses"])
        self.assertEqual(base, repair_report["load_base"])
        self.assertEqual(1, len(repair_report["repairs"]))


if __name__ == "__main__":
    unittest.main()
