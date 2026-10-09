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
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "retrolarium-core" / "python"))

from retrolarium_kit import m68k_abstract, megadrive_pipeline as pipeline
from retrolarium_core.megadrive import parse_megadrive
from test_megadrive import cartridge
from test_megadrive_pointers import dispatch_facts, dispatch_image
from test_megadrive_z80 import fact


class _StopAfterAbstractAnalysis(Exception):
    pass


class MegaDrivePipelineSeedTests(unittest.TestCase):
    def setUp(self):
        cursor = patch.object(pipeline, "_discover_cursor_callbacks", return_value=())
        cursor.start()
        self.addCleanup(cursor.stop)
        tail = patch.object(pipeline, "_discover_tail_callbacks", return_value=())
        tail.start()
        self.addCleanup(tail.stop)
        relative = patch.object(pipeline, "_discover_relative_callbacks", return_value=())
        relative.start()
        self.addCleanup(relative.stop)
        states = patch.object(pipeline, "_discover_cleared_states", return_value=())
        states.start()
        self.addCleanup(states.stop)
        for name in ("_discover_absolute_callbacks", "_discover_finite_callbacks"):
            callbacks = patch.object(pipeline, name, return_value=())
            callbacks.start()
            self.addCleanup(callbacks.stop)
        probe = patch.object(pipeline, "_discover_unused_code", return_value=((), ()))
        probe.start()
        self.addCleanup(probe.stop)
        packed = patch.object(pipeline, "_discover_packed_code", return_value=())
        packed.start()
        self.addCleanup(packed.stop)
        # These tests stop at pointer analysis and supply no pseudo backend.
        # Repair feedback has its own convergence and real decoder tests.
        repairs = patch.object(pipeline, "_discover_fallthrough_repairs", return_value=())
        repairs.start()
        self.addCleanup(repairs.stop)
        inline = patch.object(pipeline, "discover_inline_trap_calls", return_value=())
        inline.start()
        self.addCleanup(inline.stop)

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

    def test_called_ram_slot_seeds_handler_but_not_data_pointer(self) -> None:
        payload = bytearray(cartridge(size=0x800))
        payload[0x400:0x402] = bytes.fromhex("4E 75")
        payload[0x600:0x604] = bytes.fromhex("30 29 00 04")
        image = parse_megadrive(bytes(payload))
        # The installer runs in a subroutine, so the caller's state after the
        # call knows nothing about either slot; only the slot proof applies.
        first_pass = {item.physical_offset: item for item in (
            replace(fact(0x200, "BSR.B", "0x230"), flow_type="UNCONDITIONAL_CALL", flows=(0x230,)),
            replace(fact(0x202, "MOVEA.L", "(0xffffc100).w|A0"), length=4),
            replace(fact(0x206, "JSR", "(A0)"), flow_type="COMPUTED_CALL"),
            replace(fact(0x208, "MOVEA.L", "(0xffffc200).w|A1"), length=4),
            fact(0x20C, "MOVE.W", "(A1)|D0w"),
            replace(fact(0x20E, "RTS", ""), flow_type="TERMINATOR"),
            replace(fact(0x230, "MOVE.L", "#0x400|(0xffffc100).w"), length=8),
            replace(fact(0x238, "MOVE.L", "#0x600|(0xffffc200).w"), length=8),
            replace(fact(0x240, "RTS", ""), flow_type="TERMINATOR"),
        )}
        second_pass = {**first_pass, 0x400: replace(fact(0x400, "RTS", ""), flow_type="TERMINATOR")}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with ExitStack() as stack:
                for name, replacement in (
                    ("load_megadrive", {"return_value": image}),
                    ("toolchain_status", {}),
                    ("run_megadrive_analysis", {"return_value": SimpleNamespace(facts=root / "facts.tsv")}),
                    ("load_megadrive_ghidra_facts", {"side_effect": [first_pass, second_pass]}),
                    ("discover_initial_decoder_seeds", {"return_value": ()}),
                    ("detect_pointer_candidates", {"side_effect": _StopAfterAbstractAnalysis}),
                ):
                    stack.enter_context(patch.object(pipeline, name, **replacement))
                with self.assertRaises(_StopAfterAbstractAnalysis):
                    pipeline.analyze_megadrive(root / "rom.bin", root / "out", root / "ghidra")
            analysis = json.loads((root / "out/m68k/abstract-analysis.json").read_text())
        self.assertTrue(analysis["converged"])
        self.assertEqual([0x400], analysis["passes"][0]["new_seed_addresses"])
        self.assertEqual([0x400], analysis["decoder_seed_addresses"])
        evidence = {item["address"]: item for item in analysis["decoder_seed_evidence"]}
        self.assertEqual(["ram_handler"], evidence[0x400]["kinds"])
        self.assertEqual([0x230], evidence[0x400]["source_addresses"])
        candidates = {item["address"]: item for item in analysis["entrypoint_candidates"]}
        self.assertEqual("candidate", candidates[0x600]["confidence"])
        self.assertIn(0x400, analysis["trusted_root_addresses"])

    def test_untrusted_but_structural_dispatch_bootstraps_handlers(self) -> None:
        targets = tuple(range(0x400, 0x480, 0x10))
        payload = bytearray(dispatch_image(*targets).data)
        payload[4:8] = (0x240).to_bytes(4, "big")
        image = parse_megadrive(bytes(payload))
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
        real_interpret = m68k_abstract.interpret_known_cfg

        def interpret(image, facts, **kwargs):
            interpreter_entrypoints.append(
                set(kwargs.get("additional_entrypoints", ()))
            )
            return real_interpret(image, facts, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with ExitStack() as stack:
                stack.enter_context(patch.object(
                    m68k_abstract, "interpret_known_cfg", new=interpret,
                ))
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
        # The converged pass is reused after the loop.
        self.assertEqual(2, len(interpreter_entrypoints))
        self.assertEqual(set(), interpreter_entrypoints[0])
        self.assertTrue(handlers <= interpreter_entrypoints[1])
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
