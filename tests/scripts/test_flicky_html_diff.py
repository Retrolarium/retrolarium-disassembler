from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from flicky_html_diff import SourceAtAddress, _data_or_label, _status


class FlickyHtmlDiffTests(unittest.TestCase):
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

        self.assertEqual("same-bytes", _status(reference, generated))

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

    def test_binary_include_can_hide_data_but_not_reference_code(self) -> None:
        data = SourceAtAddress(lines=["Data_Table:    dc.w 1, 2, 3"])
        code = SourceAtAddress(lines=["Routine:    moveq #0,d0"])
        label = SourceAtAddress(lines=["Data_End:"])

        self.assertTrue(_data_or_label(data))
        self.assertTrue(_data_or_label(label))
        self.assertFalse(_data_or_label(code))


if __name__ == "__main__":
    unittest.main()
