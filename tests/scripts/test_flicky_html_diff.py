from __future__ import annotations

import sys
import json
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from flicky_html_diff import (
    SourceAtAddress,
    _data_or_label,
    _is_difference,
    _operation,
    _status,
    listing_source,
    write_html,
)


class FlickyHtmlDiffTests(unittest.TestCase):
    def test_difference_filter_omits_all_equivalent_statuses(self) -> None:
        for status in (
            "same-source",
            "same-instruction",
            "same-include",
            "same-data",
            "same-bytes",
        ):
            self.assertFalse(_is_difference(status), status)
        for status in (
            "data-structure",
            "raw-fallback",
            "reference-only",
            "generated-only",
        ):
            self.assertTrue(_is_difference(status), status)

    def test_operation_uses_byte_emitting_statement_at_shared_address(self) -> None:
        lines = [
            "                org     $10000",
            "EntryPoint:",
            "                move    #$2700,sr",
        ]

        self.assertEqual("move", _operation(lines))

    def test_same_branch_bytes_ignore_different_label_names(self) -> None:
        reference = SourceAtAddress(
            lines=["NamedLoop:    bra.w   ReferenceTarget"],
            encoded=["60 00 1F 2A"],
        )
        generated = SourceAtAddress(
            lines=["loc_M68K_010084:", "                bra.w loc_M68K_011FB0"],
            encoded=["60 00 1F 2A"],
        )

        self.assertEqual("same-instruction", _status(reference, generated))

    def test_different_instruction_bytes_are_still_reported(self) -> None:
        reference = SourceAtAddress(
            lines=["                bra.w ReferenceTarget"],
            encoded=["60 00 1F 2A"],
        )
        generated = SourceAtAddress(
            lines=["                bra.w loc_M68K_011FB2"],
            encoded=["60 00 1F 2C"],
        )

        self.assertEqual("different-encoding", _status(reference, generated))

    def test_full_rom_report_recognizes_code_hidden_in_binary_include(self) -> None:
        def line(number: int, address: int, encoded: str, source: str) -> str:
            return f"{number}/ {address:X} : {encoded:<21}{source}\n"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "manual"
            generated = root / "project/generated"
            reference.mkdir()
            (generated / "build").mkdir(parents=True)
            rom = bytearray(0x23000)
            rom[0x21000:0x21004] = bytes.fromhex("60 00 00 02")
            rom[0x22000:0x22002] = bytes.fromhex("4E 75")
            rom_path = reference / "game.bin"
            rom_path.write_bytes(rom)
            (generated / "rebuilt.bin").write_bytes(rom)
            ref_listing = reference / "eu.lst"
            gen_listing = generated / "build/main.lst"
            ref_listing.write_text(
                line(1, 0x21000, "6000 0002", "bra.w ManualTarget")
                + line(2, 0x21000, "[4]", "endif")
                + line(3, 0x22000, "4E75", "rts"), encoding="utf-8",
            )
            gen_listing.write_text(
                line(1, 0x21000, "6000 0002", "bra.w loc_M68K_021004")
                + line(2, 0x22000, "", 'binclude "data/opaque.bin"'), encoding="utf-8",
            )
            (generated.parent / "retrolarium-project.json").write_text(
                json.dumps({"assets": {"items": [{
                    "emit": "binclude", "rom_file_offset": 0x22000,
                    "size": 0x10, "path": "generated/data/opaque.bin",
                }]}}), encoding="utf-8",
            )
            output = root / "diff.html"
            kwargs = dict(
                rom=rom_path, reference_listing=ref_listing,
                generated_listing=gen_listing, title="Alien Soldier EU",
            )
            counts = write_html(reference, generated, output, **kwargs)
            self.assertEqual(1, counts["same-instruction"])
            self.assertEqual(1, counts["code-in-include"])
            self.assertNotIn("endif", listing_source(ref_listing)[0x21000].lines)
            counts = write_html(reference, generated, output, differences_only=True, **kwargs)
            html = output.read_text(encoding="utf-8")
            self.assertEqual(1, sum(counts.values()))
            self.assertIn('id="a022000"', html)
            self.assertNotIn('id="a021000"', html)
            self.assertIn("Alien Soldier EU", html)

    def test_opcode_filter_omits_data_differences_but_keeps_extra_code(self) -> None:
        def line(index, address, encoded, source):
            return f"{index}/ {address:X} : {encoded:<21}{source}\n"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "generated"
            generated.mkdir()
            rom = bytes.fromhex("4E75 0039 4E71 6402")
            rom_path = root / "rom.bin"
            rom_path.write_bytes(rom)
            (generated / "rebuilt.bin").write_bytes(rom)
            ref = root / "ref.lst"
            gen = root / "gen.lst"
            ref.write_text(line(1, 0, "4E75", "rts")
                           + line(2, 2, "0039", "dc.w $39")
                           + line(3, 4, "4E71", "dc.w $4E71")
                           + line(4, 6, "6402", "bhs.s Target"), encoding="utf-8")
            gen.write_text(line(1, 0, "4E75", "dc.b $4E,$75")
                           + line(2, 2, "0039", "dc.b $00,$39")
                           + line(3, 4, "4E71", "nop")
                           + line(4, 6, "6402", "bcc.s OtherLabel"), encoding="utf-8")
            output = root / "diff.html"
            counts = write_html(root, generated, output, rom=rom_path,
                                reference_listing=ref, generated_listing=gen,
                                differences_only=True, opcodes_only=True)
            self.assertEqual({"raw-fallback": 1, "generated-only": 1}, dict(counts))
            html = output.read_text(encoding="utf-8")
            self.assertIn('id="a000000"', html)
            self.assertNotIn('id="a000002"', html)
            self.assertIn('id="a000004"', html)
            self.assertNotIn('id="a000006"', html)

    def test_raw_fallback_is_not_semantically_equal(self) -> None:
        reference = SourceAtAddress(
            lines=["                bra.w ReferenceTarget"],
            encoded=["60 00 1F 2A"],
        )
        generated = SourceAtAddress(
            lines=["                dc.b    $60, $00, $1F, $2A"],
            encoded=["60 00 1F 2A"],
        )

        self.assertEqual("raw-fallback", _status(reference, generated))
        for source in ("dc.w $6000,$1F2A", "dc.l $60001F2A"):
            generated.lines = [source]
            self.assertEqual("raw-fallback", _status(reference, generated))

    def test_different_data_width_is_a_structural_difference(self) -> None:
        reference = SourceAtAddress(
            lines=["Sys_FuncTable:    dc.w $39"],
            encoded=["00 39"],
        )
        generated = SourceAtAddress(
            lines=["off_M68K_0022FC:", "                dc.b $00, $39"],
            encoded=["00 39"],
        )

        self.assertEqual("data-structure", _status(reference, generated))

    def test_binary_include_can_hide_data_but_not_reference_code(self) -> None:
        data = SourceAtAddress(lines=["Data_Table:    dc.w 1, 2, 3"])
        code = SourceAtAddress(lines=["Routine:    moveq #0,d0"])
        label = SourceAtAddress(lines=["Data_End:"])

        self.assertTrue(_data_or_label(data))
        self.assertTrue(_data_or_label(label))
        self.assertFalse(_data_or_label(code))


if __name__ == "__main__":
    unittest.main()
