from __future__ import annotations

from dataclasses import replace
import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_emit import emit_project
from retrolarium_kit.megadrive_pointers import detect_pointer_candidates
from retrolarium_kit.megadrive_symbols import generate_symbols
from retrolarium_kit.megadrive_z80 import CrossCpuCopy
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class MegaDriveEmitTests(unittest.TestCase):
    def test_emits_modules_relocatable_tables_and_z80_include(self) -> None:
        data = bytearray(cartridge())
        targets = (0x200, 0x206, 0x23C, 0x23E)
        data[0x240:0x250] = b"".join(
            target.to_bytes(4, "big") for target in targets
        )
        data[0x250:0x258] = b"".join(
            (target - 0x250).to_bytes(2, "big", signed=True)
            for target in targets
        )
        z80_payload = bytes.fromhex("F3 31 FF 1F AF 32 00 40 3C 18 FD")
        data[0x258:0x263] = z80_payload
        image = parse_megadrive(bytes(data))
        entry = replace(
            fact(0x200, "BSR.W", "0x206", flows=(0x206,)),
            flow_type="UNCONDITIONAL_CALL",
            raw=bytes(data[0x200:0x202]),
        )
        items = (
            entry,
            fact(0x206, "RTS", ""),
            fact(0x23C, "BRA.B", "0x23c", flows=(0x23C,)),
            fact(0x23E, "RTE", ""),
        )
        facts = {
            item.cpu_address: replace(
                item, raw=bytes(data[item.cpu_address:item.cpu_address + 2])
            )
            for item in items
        }
        pointers = detect_pointer_candidates(image, facts)
        copy = CrossCpuCopy(
            edge_id="copy",
            schema_id="copy-schema",
            source_cpu_id="m68k",
            source_space="m68k",
            source_start=0x258,
            source_end=0x262,
            target_cpu_id="z80",
            target_space="z80",
            target_start=0,
            target_end=10,
            size=11,
            payload_sha256=__import__("hashlib").sha256(z80_payload).hexdigest(),
            evidence_addresses=(0x200,),
            confidence="proven-static-copy",
        )
        symbols = generate_symbols(image, facts, pointers)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(root, image, facts, pointers, symbols, (copy,))
            source = (root / "src/rom-000200.68k").read_text(encoding="utf-8")

            self.assertEqual(z80_payload, (root / "assets/z80-program00.bin").read_bytes())
            self.assertIn("dc.l    Entry_M68K_000200", source)
            self.assertIn("dc.w    Entry_M68K_000200-Tbl_M68K_000250", source)
            self.assertIn('incbin  "assets/z80-program00.bin"', source)
            self.assertEqual(len(image.data), 0x200 + sum((
                result.instruction_bytes,
                result.pointer_bytes,
                result.asset_bytes - 0x100,
                result.raw_bytes,
            )))


if __name__ == "__main__":
    unittest.main()
