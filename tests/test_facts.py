from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_disassembler.facts import FactError, _load_ghidra_facts, unescape_field


COLUMNS = (
    "block",
    "space",
    "address",
    "length",
    "bytes",
    "mnemonic",
    "operands",
    "flows",
    "references",
    "flow_type",
    "symbol",
    "function",
)
AWKWARD = ('"quoted', "tab\there", "two\nlines", "back\\slash", "\\t literal", 'end"', "\\", "\t\\n\n\\\\")


def java_clean(value: str) -> str:
    """ExportInstructionFacts.clean() and ProbeM68kUnusedCode.clean(), in order."""
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "").replace("\n", "\\n")


class FieldEscapeTests(unittest.TestCase):
    def test_unescape_inverts_the_java_cleaning(self) -> None:
        for value in AWKWARD + ("", "plain", "($1234,A0)"):
            with self.subTest(value=value):
                self.assertEqual(value, unescape_field(java_clean(value)))

    def test_an_escape_clean_never_writes_is_refused(self) -> None:
        for value in ("\\x", "trailing\\"):
            with self.subTest(value=value), self.assertRaises(FactError):
                unescape_field(value)


class GhidraFactTsvTests(unittest.TestCase):
    def load(self, rows: list[dict[str, str]]) -> dict:
        lines = ["\t".join(COLUMNS)]
        lines += ["\t".join(row[column] for column in COLUMNS) for row in rows]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instructions.tsv"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
            return _load_ghidra_facts(path, bytes(range(16)), lambda address: address, bank=0, address_label="CPU")

    def row(self, address: int, *, symbol: str = "", operands: str = "", function: str = "") -> dict[str, str]:
        return {
            "block": "ROM",
            "space": "ram",
            "address": f"{address:04X}",
            "length": "1",
            "bytes": f"{address:02X}",
            "mnemonic": "nop",
            "operands": operands,
            "flows": "",
            "references": "",
            "flow_type": "FALL_THROUGH",
            "symbol": symbol,
            "function": function,
        }

    def test_awkward_names_and_operands_survive_the_round_trip(self) -> None:
        rows = []
        for index, value in enumerate(AWKWARD):
            cleaned = java_clean(value)
            rows.append(self.row(index, symbol=cleaned, operands=cleaned + "|" + cleaned, function=cleaned))
        facts = self.load(rows)
        self.assertEqual(len(AWKWARD), len(facts))
        for index, value in enumerate(AWKWARD):
            with self.subTest(value=value):
                self.assertEqual(value, facts[index].backend_symbol)
                self.assertEqual(value, facts[index].backend_function)
                self.assertEqual(value + "|" + value, facts[index].operands)
                self.assertEqual("FALL_THROUGH", facts[index].flow_type)

    def test_a_short_row_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instructions.tsv"
            path.write_text("\t".join(COLUMNS) + "\nROM\tram\t0000\n", encoding="utf-8")
            with self.assertRaisesRegex(FactError, "columns"):
                _load_ghidra_facts(path, bytes(16), lambda address: address, bank=0, address_label="CPU")


if __name__ == "__main__":
    unittest.main()
