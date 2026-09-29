import csv
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from retrolarium_kit.ghidra import GhidraArtifacts
from retrolarium_kit.m68k_overlay import analyze_overlay, address_view


HEADER = "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\treferences\tflow_type\tsymbol\tfunction\n"


def row(address, raw, mnemonic, operands="", flows="", flow="TERMINATOR"):
    return f"CD_MODULE\tram\t{address:08X}\t{len(bytes.fromhex(raw))}\t{raw}\t{mnemonic}\t{operands}\t{flows}\t\t{flow}\t\t\n"


class OverlayTests(unittest.TestCase):
    def test_rejects_non_file_backed_or_unaligned_entries(self):
        for entries in [(), (0x1001,), (0x1002,), (0x200,)]:
            with self.assertRaises(ValueError):
                address_view(b"\x4e\x75", 0x1000, entries)

    def test_follows_24_bit_bus_target_without_reference_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.bin"
            source.write_bytes(bytes.fromhex("4EF9FF001008FFFF4E75"))
            calls = []

            def decode(path, workspace, *args, entry_addresses, **kwargs):
                calls.append(entry_addresses)
                workspace.mkdir(exist_ok=True)
                facts = workspace / "instructions.tsv"
                text = row(0x1000, "4E F9 FF 00 10 08", "JMP", "(0xff001008).l", "ff001008", "UNCONDITIONAL_JUMP")
                if 0x1008 in entry_addresses:
                    text += row(0x1008, "4E 75", "RTS")
                facts.write_text(HEADER + text)
                probes = workspace / "probes.tsv"
                probes.write_text(HEADER)
                return GhidraArtifacts(facts, workspace / "report.json", workspace / "log", probes)

            with patch("retrolarium_kit.m68k_overlay.run_m68k_overlay_analysis", decode):
                result = analyze_overlay(source, root / "analysis", root, root,
                                         base_address=0x1000, entry_addresses=(0x1000,))
            self.assertEqual([(0x1000,), (0x1000, 0x1008)], calls)
            with result.facts.open() as stream:
                self.assertEqual(2, len(list(csv.DictReader(stream, delimiter="\t"))))

    def test_backend_island_does_not_become_a_trusted_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.bin"
            source.write_bytes(bytes.fromhex("4E75") + b"\xff" * 512 + bytes.fromhex("4E75"))

            def decode(path, workspace, *args, **kwargs):
                workspace.mkdir(exist_ok=True)
                facts = workspace / "instructions.tsv"
                facts.write_text(HEADER + row(0x1000, "4E 75", "RTS") + row(0x1202, "4E 75", "RTS"))
                probes = workspace / "probes.tsv"
                probes.write_text(HEADER)
                return GhidraArtifacts(facts, workspace / "report", workspace / "log", probes)

            with patch("retrolarium_kit.m68k_overlay.run_m68k_overlay_analysis", decode):
                result = analyze_overlay(source, root / "analysis", root, root,
                                         base_address=0x1000, entry_addresses=(0x1000,))
            with result.facts.open() as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(["00001000"], [r["address"] for r in rows])
