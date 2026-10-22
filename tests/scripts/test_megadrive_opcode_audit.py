from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.benchmarks.megadrive_opcode_audit import audit
from megadrive.builders import cartridge


class OpcodeAuditTests(unittest.TestCase):
    def test_reports_emitted_instructions_and_distinguishes_decode_from_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            generated = project / "generated"
            analysis = project / "analysis"
            (generated / "build").mkdir(parents=True)
            (analysis / "m68k").mkdir(parents=True)
            data = bytearray(cartridge(size=0x800))
            data[0x200:0x20A] = bytes.fromhex("4E71 4E75 4E75 4E75 4E75")
            rom = root / "rom.bin"
            rom.write_bytes(data)
            (generated / "rebuilt.bin").write_bytes(data)
            (project / "retrolarium-project.json").write_text(
                json.dumps(
                    {
                        "input": {"sha256": hashlib.sha256(data).hexdigest()},
                        "assets": {"items": []},
                    }
                ),
                encoding="utf-8",
            )
            reference_lines = []
            emitted_lines = []
            for index, address in enumerate(range(0x200, 0x20A, 2)):
                mnemonic = "nop" if index == 0 else "rts" if index < 4 else "dc.w $4E75"
                reference_lines.append(
                    f"{index + 1}/ {address:X} : {data[address : address + 2].hex().upper():<21}{mnemonic}"
                )
                emitted_lines.append(
                    f"{index + 1}/ {address:X} : {data[address : address + 2].hex().upper():<21}{mnemonic if index == 0 else 'dc.w $4E75'}"
                )
            listing = root / "reference.lst"
            listing.write_text("\n".join(reference_lines), encoding="utf-8")
            (generated / "build/retrolarium-main.lst").write_text("\n".join(emitted_lines), encoding="utf-8")
            tsv = "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\tflow_type\tsymbol\tfunction\n"
            records = []
            for address in (0x200, 0x202, 0x204):
                mnemonic = "NOP" if address == 0x200 else "RTS"
                flow = "FALL_THROUGH" if address == 0x200 else "TERMINATOR"
                tsv += f"ROM\tram\t{address:X}\t2\t{data[address : address + 2].hex()}\t{mnemonic}\t\t\t{flow}\t\t\n"
                if address != 0x204:
                    records.append({"physical_offset": address, "length": 2, "mnemonic": mnemonic, "flow_type": flow})
            (analysis / "m68k/instructions.tsv").write_text(tsv, encoding="utf-8")
            (analysis / "m68k/instructions.json").write_text(json.dumps({"instructions": records}), encoding="utf-8")
            (analysis / "m68k/abstract-analysis.json").write_text(
                json.dumps({"decoder_seed_addresses": [0x200]}), encoding="utf-8"
            )
            (analysis / "pointers.json").write_text(json.dumps({"candidates": []}), encoding="utf-8")
            layout = root / "layout.json"
            layout.write_text(
                json.dumps({"modules": [{"file": "example.s", "subsystem": "example", "start": "200", "end": "20A"}]}),
                encoding="utf-8",
            )
            report = audit(rom, generated, listing, layout, root / "report")
            self.assertEqual(4, report["reference_instructions"])
            self.assertEqual(1, report["matching_instructions"])
            self.assertEqual(25.0, report["instruction_recall_percentage"])
            self.assertEqual(
                {"formatter_fallback": 1, "unrooted_backend_decode": 1, "not_decoded": 1}, report["reason_counts"]
            )
            self.assertEqual([0x204, 0x206], report["isolated_return_words_after_return"])
            self.assertEqual(3, sum(g["instruction_count"] for g in report["groups"]))
            self.assertEqual([], report["extra_groups"])


if __name__ == "__main__":
    unittest.main()
