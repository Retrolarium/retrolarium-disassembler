from __future__ import annotations

from dataclasses import replace
import hashlib
import os
import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit.build_toolchains import materialize_build_toolchain
from retrolarium_kit.facts import InstructionReference
from retrolarium_kit.megadrive import parse_megadrive
from retrolarium_kit.megadrive_emit import (
    MegaDriveEmitError,
    _asm_instruction,
    _pointer_lines,
    emit_project,
)
from retrolarium_kit.megadrive_pointers import (
    PointerCandidate,
    PointerEntry,
    detect_pointer_candidates,
)
from retrolarium_kit.megadrive_symbols import TechnicalSymbol, generate_symbols
from retrolarium_kit.megadrive_z80 import CrossCpuCopy
from retrolarium_kit.project import _asl_build
from retrolarium_kit.z80_dispatch import Z80DispatchTable
from test_megadrive import cartridge
from test_megadrive_z80 import fact


class MegaDriveEmitTests(unittest.TestCase):
    def test_pointer_to_interior_of_emitted_table_uses_numeric_address(self) -> None:
        data = bytearray(cartridge(size=0x500))
        data[0x220:0x224] = (0x304).to_bytes(4, "big")
        data[0x300:0x308] = (0x400).to_bytes(4, "big") + (0x404).to_bytes(4, "big")
        image = parse_megadrive(bytes(data))

        def candidate(start: int, targets: tuple[int, ...]) -> PointerCandidate:
            return PointerCandidate(
                candidate_id=f"table-{start:x}",
                schema_id="megadrive.u32be.absolute",
                physical_start=start,
                physical_end=start + 4 * len(targets),
                logical_start=start,
                entry_size=4,
                status="accepted",
                score=100,
                entries=tuple(
                    PointerEntry(
                        physical_offset=start + 4 * index,
                        logical_address=start + 4 * index,
                        raw_value=target,
                        target=target,
                    )
                    for index, target in enumerate(targets)
                ),
                evidence=("test",),
                contradictions=(),
            )

        symbol = TechnicalSymbol(
            symbol_id="interior",
            name="loc_M68K_000304",
            kind="location",
            cpu_id="m68k",
            address_space="m68k",
            logical_address=0x304,
            physical_offset=0x304,
            aliases=(),
            evidence=("test",),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emit_project(
                root, image, {},
                (candidate(0x220, (0x304,)), candidate(0x300, (0x400, 0x404))),
                (symbol,), (),
            )
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")
        self.assertIn("dc.l    $000304", source)
        self.assertNotIn("loc_M68K_000304", source)

    def test_emits_counted_ram_copy_offsets_symbolically(self) -> None:
        data = bytearray(cartridge(size=0x800))
        data[0x500:0x506] = bytes.fromhex("02 03 03 00 03 08")
        image = parse_megadrive(bytes(data))
        candidate = PointerCandidate(
            candidate_id="animation",
            schema_id="megadrive.counted-u16be.ram-copy-offset",
            physical_start=0x500,
            physical_end=0x506,
            logical_start=0x500,
            entry_size=2,
            status="accepted",
            score=100,
            entries=tuple(
                PointerEntry(
                    physical_offset=0x502 + index * 2,
                    logical_address=0x502 + index * 2,
                    raw_value=target - 0x300,
                    target=target,
                    base_address=0x300,
                )
                for index, target in enumerate((0x600, 0x608))
            ),
            evidence=("test",),
            contradictions=(),
        )
        symbols = {
            address: TechnicalSymbol(
                symbol_id=f"symbol.{address:x}",
                name=name,
                kind="offset",
                cpu_id="m68k",
                address_space="m68k",
                logical_address=address,
                physical_offset=address,
                aliases=(),
                evidence=("test",),
            )
            for address, name in (
                (0x300, "CopySource"),
                (0x600, "Frame0"),
                (0x608, "Frame1"),
            )
        }

        lines = _pointer_lines(candidate, image, symbols)

        self.assertIn("                dc.b    $02, $03", lines)
        self.assertIn("                dc.w    Frame0-CopySource", lines)
        self.assertIn("                dc.w    Frame1-CopySource", lines)

    def test_emits_counted_ram_trampoline_table_as_symbolic_words(self) -> None:
        data = bytearray(cartridge(size=0x500))
        data[0x220:0x238] = bytes.fromhex(
            "41 FA 00 3E 43 F8 FF 00 30 18 32 FC 4E F9 "
            "72 00 32 18 22 C1 51 C8 FF F4"
        )
        targets = (0x280, 0x290, 0x2A0, 0x2B0)
        data[0x260:0x26A] = (
            (len(targets) - 1).to_bytes(2, "big")
            + b"".join(target.to_bytes(2, "big") for target in targets)
        )
        for target in targets:
            data[target:target + 2] = bytes.fromhex("4E 75")
        image = parse_megadrive(bytes(data))
        facts = {
            target: replace(
                fact(target, "RTS", ""),
                raw=bytes.fromhex("4E 75"),
                flow_type="TERMINATOR",
            )
            for target in targets
        }
        pointers = detect_pointer_candidates(image, facts)
        symbols = generate_symbols(image, facts, pointers)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(root, image, facts, pointers, symbols, ())
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")

        self.assertIn("tbl_M68K_000260:", source)
        self.assertIn("dc.w    $3", source)
        self.assertIn("dc.w    loc_M68K_000280", source)
        self.assertEqual(10, result.pointer_bytes)

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

    def test_rejects_noncanonical_byte_immediate_extension_words(self) -> None:
        cases = (
            ("ORI.B", "#-0x56|D4b", "00 04 C6 AA"),
            ("BCLR.L", "#-0x80|D0", "08 80 02 80"),
            ("CMPI.B", "#-0x80|D0b", "0C 00 04 80"),
        )
        for mnemonic, operands, raw_hex in cases:
            with self.subTest(mnemonic=mnemonic):
                raw = bytes.fromhex(raw_hex)
                instruction = replace(
                    fact(0x200, mnemonic, operands), raw=raw, length=len(raw)
                )
                self.assertIsNone(_asm_instruction(instruction))

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

    def test_branch_into_instruction_interior_uses_numeric_target(self) -> None:
        data = bytearray(cartridge(size=0x500))
        data[0x200:0x208] = bytes.fromhex("60 00 00 04 0C 40 00 00")
        image = parse_megadrive(bytes(data))
        branch = replace(
            fact(0x200, "BRA.W", "0x00000206", flows=(0x206,)),
            raw=bytes.fromhex("60 00 00 04"), length=4,
            flow_type="UNCONDITIONAL_JUMP",
        )
        comparison = replace(
            fact(0x204, "CMPI.W", "#0x0|D0w"),
            raw=bytes.fromhex("0C 40 00 00"), length=4,
        )
        facts = {0x200: branch, 0x204: comparison}
        symbols = generate_symbols(image, facts, ())

        self.assertNotIn(0x206, {item.logical_address for item in symbols})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emit_project(root, image, facts, (), symbols, ())
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")

        self.assertIn("bra.w $000206", source)
        self.assertNotIn("loc_M68K_000206", source)

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

    def test_large_unclassified_span_uses_binary_include(self) -> None:
        image = parse_megadrive(cartridge(size=0x600))
        entry = replace(
            fact(0x200, "RTS", ""),
            raw=image.data[0x200:0x202],
            length=2,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(root, image, {0x200: entry}, (), (), ())
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")
            blobs = [item for item in result.assets if item["kind"] == "opaque_rom"]

            self.assertEqual(1, len(blobs))
            self.assertEqual(0x202, blobs[0]["rom_file_offset"])
            self.assertEqual(0x3FE, blobs[0]["size"])
            self.assertIn('binclude "data/opaque-000202.bin"', source)
            self.assertEqual(
                image.data[0x202:],
                (root / "data/opaque-000202.bin").read_bytes(),
            )
            self.assertEqual(0, result.raw_bytes)

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
            facts[0x200], references=(
                InstructionReference(0x240, "DATA", 0),
                InstructionReference(0x250, "DATA", 0),
                InstructionReference(0xFFFFC000, "DATA", 0),
            )
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

    def test_ambiguous_add_word_immediate_keeps_exact_bytes(self) -> None:
        # D07C 0001 is ADD.W #1,D0; assemblers prefer the ADDI.W twin (0640).
        add = replace(
            fact(0x300, "ADD.W", "#0x1,D0"),
            raw=bytes.fromhex("D0 7C 00 01"),
            length=4,
        )
        self.assertIsNone(_asm_instruction(add))

        data = bytearray(cartridge(size=0x800))
        data[0x300:0x304] = add.raw
        image = parse_megadrive(bytes(data))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = emit_project(root, image, {0x300: add}, (), (), ())
            source = (root / "src/rom-000200.s").read_text(encoding="utf-8")

        self.assertIn("dc.b    $D0, $7C, $00, $01", source)
        self.assertFalse(any(
            line.strip().lower().startswith(("add", "addi"))
            for line in source.splitlines()
        ))
        self.assertEqual(4, result.instruction_bytes)

    def test_emit_project_writes_z80_dispatch_table_words(self) -> None:
        # RET, RET, then a two-entry little-endian table pointing at both.
        payload = bytes.fromhex("C9 C9 00 00 01 00")
        data = bytearray(cartridge(size=0x800))
        data[0x400:0x400 + len(payload)] = payload
        image = parse_megadrive(bytes(data))
        copy = CrossCpuCopy(
            edge_id="copy.z80.00",
            schema_id="test",
            source_cpu_id="m68k",
            source_space="m68k",
            source_start=0x400,
            source_end=0x400 + len(payload) - 1,
            target_cpu_id="z80.00",
            target_space="z80",
            target_start=0x0000,
            target_end=len(payload) - 1,
            size=len(payload),
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            evidence_addresses=(),
            confidence="test",
        )
        z80_facts = {
            address: replace(
                fact(address, "RET", ""), raw=b"\xC9", length=1,
                flow_type="TERMINATOR",
            )
            for address in (0, 1)
        }
        table = Z80DispatchTable(
            logical_start=2,
            logical_end=6,
            dispatch_address=0,
            lookup_address=2,
            targets=(0, 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emit_project(
                root, image, {}, (), (), (copy,),
                (("z80.00", 0, z80_facts),),
                ((table,),),
            )
            source = (root / "src/sound/z80/program00.asm").read_text(
                encoding="utf-8"
            )

        lines = source.splitlines()
        self.assertIn("Z80_Table_0002:", lines)
        self.assertIn("Z80_Loc_0000:", lines)
        self.assertIn("Z80_Loc_0001:", lines)
        start = lines.index("Z80_Table_0002:")
        self.assertEqual(
            ["    dw Z80_Loc_0000", "    dw Z80_Loc_0001"],
            lines[start + 1:start + 3],
        )

    def test_emit_project_rejects_dispatch_tables_without_per_program_shape(
        self,
    ) -> None:
        image = parse_megadrive(cartridge(size=0x800))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(MegaDriveEmitError):
                emit_project(
                    Path(directory), image, {}, (), (), (), (), ((),),
                )


if __name__ == "__main__":
    unittest.main()
