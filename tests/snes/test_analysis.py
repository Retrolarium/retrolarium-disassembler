from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_core.snes import (
    LOROM_HEADER_OFFSET,
    cartridge_checksum,
    parse_snes,
)
from retrolarium_disassembler.snes.analysis import (
    OPCODES,
    CpuState,
    analysis_manifest,
    analyze_snes,
    validate_backend_facts,
)
from retrolarium_disassembler.facts import FactError, load_snes_ghidra_facts
from helpers import cartridge


def image_with_code(code: bytes):
    data = bytearray(cartridge("lorom"))
    data[0x1000 : 0x1000 + len(code)] = code
    header = LOROM_HEADER_OFFSET
    data[header + 0x20 : header + 0x40] = bytes(0x20)
    data[header + 0x3C : header + 0x3E] = (0x9000).to_bytes(2, "little")
    data[header + 0x1C : header + 0x20] = bytes(4)
    checksum = (cartridge_checksum(data) + 0x1FE) & 0xFFFF
    data[header + 0x1C : header + 0x1E] = (checksum ^ 0xFFFF).to_bytes(
        2, "little"
    )
    data[header + 0x1E : header + 0x20] = checksum.to_bytes(2, "little")
    return parse_snes(bytes(data))


class SnesAnalysisTests(unittest.TestCase):
    @staticmethod
    def write_facts(path: Path, rows: list[str]) -> None:
        path.write_text(
            "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\t"
            "references\tflow_type\tsymbol\tfunction\n"
            + "\n".join(rows)
            + "\n",
            encoding="utf-8",
        )

    def test_opcode_table_covers_every_w65c816_opcode(self) -> None:
        self.assertEqual(256, len(OPCODES))
        self.assertEqual(("BRK", "imm8"), OPCODES[0x00])
        self.assertEqual(("JSL", "long"), OPCODES[0x22])
        self.assertEqual(("REP", "imm8"), OPCODES[0xC2])
        self.assertEqual(("XCE", "imp"), OPCODES[0xFB])

    def test_tracks_native_transition_widths_calls_and_branch_truth(self) -> None:
        code = bytes.fromhex(
            "78 18 FB C2 30 A9 34 12 A2 78 56 E2 20 A9 12 "
            "20 18 90 22 20 90 00 80 09 C2 20 A9 BC 9A E2 "
            "20 60 6B CB 80 FD 40 40"
        )
        result = analyze_snes(image_with_code(code))
        facts = {item.logical_address: item for item in result.instructions}

        self.assertEqual(3, facts[0x009005].length)
        self.assertEqual(3, facts[0x009008].length)
        self.assertEqual(2, facts[0x00900D].length)
        self.assertEqual((0, 0, 0), (
            facts[0x009005].state_before.e,
            facts[0x009005].state_before.m,
            facts[0x009005].state_before.x,
        ))
        self.assertEqual(0x1000, facts[0x009000].physical_offset)
        self.assertEqual(
            [("call", 0x009020), ("fallthrough", 0x009016)],
            [(flow.kind, flow.target) for flow in facts[0x009012].flows],
        )
        self.assertEqual(
            [("branch", 0x009021)],
            [(flow.kind, flow.target) for flow in facts[0x009016].flows],
        )
        self.assertFalse(
            any(item.kind == "ambiguous-width" for item in result.diagnostics)
        )
        manifest = analysis_manifest(result)
        self.assertEqual("retrolarium.snes.state-analysis", manifest["schema"])

    def test_tracks_pbr_dbr_and_direct_page_evidence(self) -> None:
        code = bytes.fromhex("18 FB 4B AB C2 20 A9 34 12 5B DB")
        result = analyze_snes(
            image_with_code(code),
            [(0x009000, CpuState(1, 1, 1, None, 0, 0, 0))],
        )
        facts = {item.logical_address: item for item in result.instructions}
        self.assertEqual(0, facts[0x009003].state_after.dbr)
        self.assertEqual(0x1234, facts[0x009009].state_after.direct_page)
        self.assertEqual(0, facts[0x009009].state_after.pbr)

    def test_conflicting_widths_stop_before_ambiguous_immediate(self) -> None:
        code = bytes.fromhex("D0 04 C2 20 80 00 A9 34 12 DB")
        result = analyze_snes(
            image_with_code(code),
            [(0x009000, CpuState(0, 1, 1, None, 0, 0, 0))],
        )
        kinds = {item.kind for item in result.diagnostics}
        addresses = {item.logical_address for item in result.instructions}
        self.assertIn("state-conflict", kinds)
        self.assertIn("ambiguous-width", kinds)
        self.assertNotIn(0x009006, addresses)
        self.assertNotIn(0x009008, addresses)

    def test_accepts_only_backend_facts_confirmed_by_state_and_bytes(self) -> None:
        image = image_with_code(bytes.fromhex("EA DB"))
        result = analyze_snes(image)
        with tempfile.TemporaryDirectory() as directory:
            facts_path = Path(directory) / "facts.tsv"
            self.write_facts(
                facts_path,
                [
                    "SNES_ROM\tbus\t9000\t1\tEA\tNOP\t\t\t\tFALL_THROUGH\t\t",
                    "SNES_ROM\tbus\t9001\t1\tDB\tSTP\t\t\t\tTERMINATOR\t\t",
                    "SNES_ROM\tbus\t9002\t1\tFF\tSBC\t\t\t\tFALL_THROUGH\t\t",
                ],
            )
            backend = load_snes_ghidra_facts(
                facts_path, image, physical_bank=0
            )
            accepted = validate_backend_facts(result, backend)
            self.assertEqual({0x1000, 0x1001}, set(accepted))

            self.write_facts(
                facts_path,
                [
                    "SNES_ROM\tbus\t9000\t2\tEA DB\tNOP\t\t\t\tFALL_THROUGH\t\t"
                ],
            )
            backend = load_snes_ghidra_facts(
                facts_path, image, physical_bank=0
            )
            with self.assertRaisesRegex(FactError, "boundary disagrees"):
                validate_backend_facts(result, backend)


if __name__ == "__main__":
    unittest.main()
