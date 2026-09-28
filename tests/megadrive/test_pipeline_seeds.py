from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import json
import sys
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit import megadrive_pipeline as pipeline
from retrolarium_kit.megadrive import parse_megadrive
from test_megadrive_pointers import dispatch_facts, dispatch_image
from test_megadrive_z80 import fact


class _StopAfterAbstractAnalysis(Exception):
    pass


class MegaDrivePipelineSeedTests(unittest.TestCase):
    def test_decoded_but_untrusted_packed_function_gets_a_planned_root(self) -> None:
        payload = bytearray(dispatch_image().data)
        payload[0x202:0x220] = bytes.fromhex("70 01 4E 75") + bytes(26)
        image = parse_megadrive(bytes(payload))
        facts = {
            item.physical_offset: item for item in (
                replace(fact(0x200, "RTS", ""), flow_type="TERMINATOR"),
                fact(0x202, "MOVEQ", "0x1|D0"),
                replace(fact(0x204, "RTS", ""), flow_type="TERMINATOR"),
                replace(fact(0x220, "RTS", ""), flow_type="TERMINATOR"),
            )
        }
        seed = SimpleNamespace(address=0x220, evidence="known entry", kind="test", confidence="high", source_address=None)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with ExitStack() as stack:
                for name, replacement in (
                    ("load_megadrive", {"return_value": image}),
                    ("toolchain_status", {}),
                    ("run_megadrive_analysis", {"return_value": SimpleNamespace(facts=root / "facts.tsv")}),
                    ("load_megadrive_ghidra_facts", {"return_value": facts}),
                    ("discover_initial_decoder_seeds", {"return_value": (seed,)}),
                    ("discover_ram_handler_candidates", {"return_value": ()}),
                    ("detect_pointer_candidates", {"side_effect": _StopAfterAbstractAnalysis}),
                ):
                    stack.enter_context(patch.object(pipeline, name, **replacement))
                with self.assertRaises(_StopAfterAbstractAnalysis):
                    pipeline.analyze_megadrive(root / "rom.bin", root / "out", root / "ghidra")
            analysis = json.loads((root / "out/m68k/abstract-analysis.json").read_text())
        self.assertEqual([0x202], analysis["passes"][0]["new_seed_addresses"])
        self.assertIn(0x202, analysis["decoder_seed_addresses"])
        self.assertNotIn(0x202, analysis["discarded_backend_instruction_addresses"])

    def test_untrusted_but_structural_dispatch_bootstraps_handlers(self) -> None:
        targets = tuple(range(0x400, 0x480, 0x10))
        image = dispatch_image(*targets)
        facts = dispatch_facts()
        facts[0x400] = replace(
            fact(0x400, "RTS", ""), flow_type="TERMINATOR"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with ExitStack() as stack:
                for name, replacement in (
                    ("load_megadrive", {"return_value": image}),
                    ("toolchain_status", {}),
                    ("run_megadrive_analysis", {
                        "return_value": SimpleNamespace(facts=root / "facts.tsv"),
                    }),
                    ("load_megadrive_ghidra_facts", {"return_value": facts}),
                    ("discover_initial_decoder_seeds", {"return_value": ()}),
                    ("discover_ram_handler_candidates", {"return_value": ()}),
                    ("discover_packed_orphan_candidates", {"return_value": ()}),
                    ("retain_trusted_instruction_facts", {"return_value": {}}),
                    ("detect_pointer_candidates", {
                        "side_effect": _StopAfterAbstractAnalysis,
                    }),
                ):
                    stack.enter_context(patch.object(pipeline, name, **replacement))
                with self.assertRaises(_StopAfterAbstractAnalysis):
                    pipeline.analyze_megadrive(
                        root / "rom.bin", root / "out", root / "ghidra"
                    )
            analysis = json.loads(
                (root / "out" / "m68k" / "abstract-analysis.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertTrue(analysis["converged"])
        self.assertEqual(2, len(analysis["passes"]))
        self.assertEqual(
            [0x202, *targets],
            analysis["passes"][0]["new_seed_addresses"],
        )

    def test_dispatch_table_targets_seed_convergence_and_interpreter(
        self,
    ) -> None:
        image = dispatch_image(0x400, 0x410, 0x420)
        first_pass = dispatch_facts()
        second_pass = dict(first_pass)
        for target in (0x400, 0x410, 0x420):
            second_pass[target] = replace(
                fact(target, "RTS", ""), flow_type="TERMINATOR"
            )
        interpreter_entrypoints: list[set[int]] = []
        real_interpret = pipeline.interpret_known_cfg

        def interpret(image, facts, **kwargs):
            interpreter_entrypoints.append(
                set(kwargs.get("additional_entrypoints", ()))
            )
            return real_interpret(image, facts, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with ExitStack() as stack:
                for name, replacement in (
                    ("load_megadrive", {"return_value": image}),
                    ("toolchain_status", {}),
                    ("run_megadrive_analysis", {
                        "return_value": SimpleNamespace(
                            facts=root / "facts.tsv"
                        ),
                    }),
                    ("load_megadrive_ghidra_facts", {
                        "side_effect": [first_pass, second_pass],
                    }),
                    ("discover_initial_decoder_seeds", {"return_value": ()}),
                    ("discover_ram_handler_candidates", {"return_value": ()}),
                    ("discover_packed_orphan_candidates", {"return_value": ()}),
                    ("interpret_known_cfg", {"new": interpret}),
                    ("detect_pointer_candidates", {
                        "side_effect": _StopAfterAbstractAnalysis,
                    }),
                ):
                    stack.enter_context(
                        patch.object(pipeline, name, **replacement)
                    )
                with self.assertRaises(_StopAfterAbstractAnalysis):
                    pipeline.analyze_megadrive(
                        root / "rom.bin", root / "out", root / "ghidra"
                    )
            program_root = root / "out" / "m68k"
            seed_plan = (program_root / "python-seeds.txt").read_text(
                encoding="ascii"
            )
            analysis = json.loads(
                (program_root / "abstract-analysis.json").read_text(
                    encoding="utf-8"
                )
            )

        handlers = {0x400, 0x410, 0x420}
        # Pass one, pass two, then the post-convergence interpretation.
        self.assertEqual(3, len(interpreter_entrypoints))
        self.assertEqual(set(), interpreter_entrypoints[0])
        self.assertTrue(handlers <= interpreter_entrypoints[1])
        self.assertTrue(handlers <= interpreter_entrypoints[2])
        self.assertEqual("000400\n000410\n000420\n", seed_plan)
        self.assertTrue(analysis["converged"])
        self.assertEqual(
            sorted(handlers), analysis["passes"][0]["new_seed_addresses"]
        )
        self.assertEqual([], analysis["passes"][1]["new_seed_addresses"])
        evidence = {
            item["address"]: item for item in analysis["decoder_seed_evidence"]
        }
        self.assertEqual(
            ["indexed_pointer_table_target"], evidence[0x400]["kinds"]
        )
        self.assertEqual([0x202], evidence[0x400]["source_addresses"])
        # The dispatch site alone reaches at most four instructions; the
        # seeded handlers are interpreted too.
        self.assertGreater(
            analysis["control_flow"]["reached_instruction_count"], 4
        )


if __name__ == "__main__":
    unittest.main()
