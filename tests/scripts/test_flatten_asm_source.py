from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.references.flatten_asm_source import flatten_source


class FlattenSourceTests(unittest.TestCase):
    def test_explicit_legacy_encoding_applies_to_nested_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.s").write_bytes(b' include "child.s"\n')
            (root / "child.s").write_bytes(b'; f\xfc r\x81\n rts\n')
            with self.assertRaises(UnicodeDecodeError):
                flatten_source(root, "main.s")
            text, origins = flatten_source(root, "main.s", encoding="latin-1")
            self.assertIn('; f\u00fc r\u0081\n rts\n', text)
            self.assertEqual(["child.s", "main.s"], [item["path"] for item in origins])

    def test_labelled_includes_keep_scope_order_and_binary_includes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.s").write_text(
                'Song: include "song.asm" ; label establishes local scope\n'
                "Next: INCLUDE 'song.asm'\n"
                '    binclude "art.bin"\n', encoding="utf-8",
            )
            (root / "song.asm").write_text(
                '.loop: dc.w 1\n    bra.s .loop\n', encoding="utf-8",
            )
            text, origins = flatten_source(root, "main.s")
            self.assertEqual(
                'Song:\n; BEGIN song.asm\n.loop: dc.w 1\n    bra.s .loop\n'
                '; END song.asm\nNext:\n; BEGIN song.asm\n.loop: dc.w 1\n'
                '    bra.s .loop\n; END song.asm\n    binclude "art.bin"\n',
                text,
            )
            self.assertEqual(["song.asm", "song.asm", "main.s"],
                             [item["path"] for item in origins])

    def test_conditions_are_preserved_and_nested_includes_use_source_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "main.s").write_text(
                'if REVISION=1\n include "nested/part.s"\nendif\n', encoding="utf-8",
            )
            (root / "nested/part.s").write_text(' include "values.inc"\n', encoding="utf-8")
            (root / "values.inc").write_text(' dc.w $1234\n', encoding="utf-8")
            text, _ = flatten_source(root, "main.s")
            self.assertIn('if REVISION=1\n; BEGIN nested/part.s\n; BEGIN values.inc\n', text)
            self.assertTrue(text.endswith("endif\n"))

    def test_cycles_and_include_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "src"
            root.mkdir()
            (root / "main.s").write_text(' include "main.s"\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "recursive"):
                flatten_source(root, "main.s")
            (root.parent / "outside.s").write_text("rts\n", encoding="utf-8")
            (root / "main.s").write_text(' include "../outside.s"\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                flatten_source(root, "main.s")

    def test_include_wrapper_macros_expand_literal_arguments_and_internal_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.s").write_text(
                'table macro {INTLABEL},path\n__LABEL__ label *\n'
                ' dc.w (__LABEL___End-__LABEL__)/2\n include path\n__LABEL___End:\n endm\n'
                'Data: table "entries.inc"\n', encoding="utf-8",
            )
            (root / "entries.inc").write_text(' dc.w 1,2\n', encoding="utf-8")
            text, _ = flatten_source(root, "main.s", expand_include_macros=True)
            self.assertIn('Data label *\n dc.w (Data_End-Data)/2\n', text)
            self.assertIn(' dc.w 1,2\n; END entries.inc\nData_End:', text)
            self.assertNotIn('include path', text)
            self.assertNotIn(' table "', text)
            (root / "main.s").write_text(
                'table macro {INTLABEL},path\n include path\n endm\nData: table computed_path\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported include macro invocation"):
                flatten_source(root, "main.s", expand_include_macros=True)


if __name__ == "__main__":
    unittest.main()
