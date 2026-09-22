from __future__ import annotations

from dataclasses import replace
import os
import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.build_toolchains import materialize_build_toolchain
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_emit import _asm_instruction, emit_project
from retrolarium_kit.megadrive_pointers import detect_pointer_candidates
from retrolarium_kit.megadrive_symbols import TechnicalSymbol, generate_symbols
from retrolarium_kit.megadrive_z80 import CrossCpuCopy
from retrolarium_kit.project import _asl_build
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class MegaDriveEmitTests(unittest.TestCase):
    def test_renders_indexed_operands_and_extended_instruction_families(self) -> None:
        symbol = TechnicalSymbol(
            symbol_id="megadrive.m68k.offset.011878",
            name="off_M68K_011878",
            kind="offset",
            cpu_id="m68k",
            address_space="m68k",
            logical_address=0x11878,
            physical_offset=0x11878,
            aliases=(),
            evidence=("data_reference_from_117fe",),
        )
        cases = (
            (0x117FE, "ADD.W", "(0x11878,PC,D1w*0x1)|D5w",
             "DA 7B 10 78", "add.w off_M68K_011878(pc,d1.w),d5",
             {0x11878: symbol}),
            (0x1269C, "MOVE.L", "(0x0,A0,D0w*0x1)|D1",
             "22 30 00 00", "move.l (a0,d0.w),d1", None),
            (0x113F6, "ADDA.L", "D7|A0",
             "D1 C7", "adda.l d7,a0", None),
            (0x116C8, "ABCD", "D1b|D0b",
             "C1 01", "abcd d1,d0", None),
            (0x10EDC, "CMPM.L", "(A0)+|(A1)+",
             "B3 88", "cmpm.l (a0)+,(a1)+", None),
        )
        for address, mnemonic, operands, raw_hex, expected, symbols in cases:
            with self.subTest(address=address):
                raw = bytes.fromhex(raw_hex)
                instruction = replace(
                    fact(address, mnemonic, operands), raw=raw, length=len(raw)
                )
                self.assertEqual(expected, _asm_instruction(instruction, symbols))

    def test_renders_forced_zero_displacement_trap_and_ccr_move(self) -> None:
        cases = (
            (0x11386, "ADDQ.B", "0x1|(0x0,A0)",
             "52 28 00 00", "addq.b #1,0.w(a0)"),
            (0x10E52, "TRAP", "0x0", "4E 40", "trap #0"),
            (0x1169A, "MOVE", "#0x4", "44 FC 00 04", "move #4,ccr"),
        )
        for address, mnemonic, operands, raw_hex, expected in cases:
            with self.subTest(address=address):
                raw = bytes.fromhex(raw_hex)
                instruction = replace(
                    fact(address, mnemonic, operands), raw=raw, length=len(raw)
                )
                self.assertEqual(expected, _asm_instruction(instruction))

    def test_renders_pc_relative_lea_to_known_symbol(self) -> None:
        symbol = TechnicalSymbol(
            symbol_id="megadrive.m68k.offset.000294",
            name="off_M68K_000294",
            kind="offset",
            cpu_id="m68k",
            address_space="m68k",
            logical_address=0x294,
            physical_offset=0x294,
            aliases=(),
            evidence=("data_reference_from_216",),
        )
        instruction = replace(
            fact(0x216, "LEA", "(0x7c,PC)|A5"),
            raw=bytes.fromhex("4B FA 00 7C"), length=4,
        )
        self.assertEqual(
            "lea off_M68K_000294(pc),a5",
            _asm_instruction(instruction, {0x294: symbol}),
        )
        self.assertIsNone(_asm_instruction(instruction))

    def test_renders_flicky_bset_displacement(self) -> None:
        instruction = replace(
            fact(0x16674, "BSET.B", "#0x7|(0x2,A0)"),
            raw=bytes.fromhex("08 E8 00 07 00 02"), length=6,
        )
        self.assertEqual("bset #7,2(a0)", _asm_instruction(instruction))

    def test_branch_and_dbcc_use_existing_target_symbols(self) -> None:
        target = 0x11FB0
        symbol = TechnicalSymbol(
            symbol_id="megadrive.m68k.subroutine.011fb0",
            name="sub_M68K_011FB0",
            kind="subroutine",
            cpu_id="m68k",
            address_space="m68k",
            logical_address=target,
            physical_offset=target,
            aliases=(),
            evidence=("call_from_10084",),
        )
        branch = replace(
            fact(0x10084, "BRA.W", "0x00011fb0"),
            raw=bytes.fromhex("60 00 1F 2A"), length=4,
        )
        dbcc = replace(
            fact(0x11FB4, "DBEQ", "D0w|0x00011fb0"),
            raw=bytes.fromhex("57 C8 FF FA"), length=4,
        )
        self.assertEqual("bra.w sub_M68K_011FB0", _asm_instruction(branch, {target: symbol}))
        self.assertEqual("dbeq d0,sub_M68K_011FB0", _asm_instruction(dbcc, {target: symbol}))
        self.assertEqual("bra.w $011FB0", _asm_instruction(branch))

    def test_pc_indexed_jsr_uses_branch_table_symbol(self) -> None:
        target = 0x10084
        symbol = TechnicalSymbol(
            symbol_id="megadrive.m68k.table.010084",
            name="tbl_M68K_010084",
            kind="table",
            cpu_id="m68k",
            address_space="m68k",
            logical_address=target,
            physical_offset=target,
            aliases=(),
            evidence=("pc_indexed_jsr_from_1007A",),
        )
        call = replace(
            fact(0x1007A, "JSR", "(0x10084,PC,D0w*0x1)"),
            raw=bytes.fromhex("4E BB 00 08"), length=4,
            flow_type="COMPUTED_CALL",
        )
        self.assertEqual(
            "jsr tbl_M68K_010084(pc,d0.w)",
            _asm_instruction(call, {target: symbol}),
        )

    def test_renders_flicky_btst_dbeq_and_movem(self) -> None:
        instructions = (
            (0x106C, "BTST.B", "#0x0|(0x00a11100).l",
             "08 39 00 00 00 A1 11 00", "btst #0,($00A11100).l"),
            (0x1074, "DBEQ", "D0w|0x0000106c",
             "57 C8 FF F6", "dbeq d0,$00106C"),
            (0x1078, "MOVEM.W", "(SP)+|{ D0}",
             "4C 9F 00 01", "movem.w (sp)+,d0"),
            (0x1060, "MOVEM.W", "{ D0w}|-(SP)",
             "48 A7 80 00", "movem.w d0,-(sp)"),
        )
        for address, mnemonic, operands, raw_hex, expected in instructions:
            with self.subTest(address=address):
                raw = bytes.fromhex(raw_hex)
                instruction = replace(
                    fact(address, mnemonic, operands), raw=raw, length=len(raw)
                )
                self.assertEqual(expected, _asm_instruction(instruction))

    def test_ff_tail_uses_org_and_rebuilds_exactly(self) -> None:
        data = bytearray(cartridge(size=0x800))
        data[0x300:] = b"\xFF" * (len(data) - 0x300)
        image = parse_megadrive(bytes(data))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(root, image, {}, (), (), ())
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")
            self.assertEqual(0x501, result.padding_bytes)
            self.assertIn("org     $0007FF", source)
            self.assertNotIn("$FF, $FF, $FF", source)
            if os.name == "nt":
                suite = materialize_build_toolchain(
                    "megadrive", cache_root=root / "toolchains"
                )
                rebuilt = root / "rebuilt.bin"
                _asl_build(
                    {"source": "src/main.s", "object": "build/main.p"},
                    root, rebuilt, suite,
                )
                self.assertEqual(image.data, rebuilt.read_bytes())

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
        facts[0x200] = replace(
            facts[0x200], references=(InstructionReference(0xFFFFC000, "DATA", 0),)
        )
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
        z80_facts = {
            0: replace(fact(0, "DI", ""), length=1, raw=b"\xF3"),
            4: replace(fact(4, "XOR", "A"), length=1, raw=b"\xAF"),
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(
                root, image, facts, pointers, symbols, (copy,),
                (("z80.00", 0, z80_facts),),
            )
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")

            self.assertEqual(z80_payload, (root / "data/z80-program00.bin").read_bytes())
            self.assertIn("dc.l    Entry_M68K_000200", source)
            self.assertIn("dc.w    Entry_M68K_000200-tbl_M68K_000250", source)
            self.assertIn('binclude "build/z80-program00.bin"', source)
            self.assertTrue((root / "src/main.s").is_file())
            self.assertTrue((root / "src/memory/ram.inc").is_file())
            self.assertIn("Ram_FFC000: equ $FFC000", (root / "src/memory/ram.inc").read_text())
            self.assertTrue((root / "src/sound/z80/program00.asm").is_file())
            z80_source = (root / "src/sound/z80/program00.asm").read_text()
            self.assertIn("    di\n", z80_source)
            self.assertIn("    xor a\n", z80_source)
            self.assertEqual(len(image.data), 0x200 + sum((
                result.instruction_bytes,
                result.pointer_bytes,
                result.asset_bytes - 0x100,
                result.raw_bytes,
                result.padding_bytes,
            )))
            if os.name == "nt":
                suite = materialize_build_toolchain(
                    "megadrive", cache_root=root / "toolchains"
                )
                rebuilt = root / "rebuilt.bin"
                (root / "build/z80-program00.bin").write_bytes(b"\0" * len(z80_payload))
                _asl_build(
                    {"source": "src/main.s", "object": "build/main.p",
                     "z80_prebuild": list(result.z80_builds)},
                    root,
                    rebuilt,
                    suite,
                )
                self.assertEqual(
                    z80_payload, (root / "build/z80-program00.bin").read_bytes()
                )
                self.assertEqual(image.data, rebuilt.read_bytes())


if __name__ == "__main__":
    unittest.main()
