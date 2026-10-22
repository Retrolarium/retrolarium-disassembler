"""Orchestration contracts for the Mega Drive decoder feedback loops.

Ghidra, ROM loading and the analyzers are replaced at the pipeline module
boundary so the tests observe only what the loop hands to the decoder (seed
plans and backend invocations) and how it terminates.
"""

from __future__ import annotations

from dataclasses import replace
import json
import hashlib
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "retrolarium-core" / "python"))

from retrolarium_disassembler.megadrive import pipeline
from retrolarium_disassembler.ghidra import GhidraArtifacts
from retrolarium_disassembler.m68k.abstract import (
    EntryPointCandidate,
    IndirectEdge,
    InterpretationResult,
    OrphanCandidate,
    TrustedCfg,
)
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.emit import MegaDriveEmitError
from retrolarium_disassembler.m68k.repair.unused import UnusedCodeCandidate
from retrolarium_disassembler.m68k.dispatch.ram import InlineTrapCall
from retrolarium_disassembler.megadrive.z80 import CrossCpuCopy
from retrolarium_disassembler.z80.dispatch import Z80DispatchTable
from megadrive.builders import cartridge
from megadrive.builders import fact
from megadrive.pipeline_harness import _M68kHarness, _StopAfterLoop, _artifacts


def _edge(target: int, confidence: str = "proven") -> IndirectEdge:
    return IndirectEdge(
        source_address=0x200,
        target_address=target,
        mnemonic="jmp",
        evidence=f"edge to {target:06X}",
        confidence=confidence,
    )


def _handler(address: int, confidence: str = "proven") -> EntryPointCandidate:
    return EntryPointCandidate(
        address=address,
        source_address=0x204,
        storage_address=0xFF0000,
        confidence=confidence,
        evidence=f"handler {address:06X}",
    )


def _orphan(address: int, confidence: str = "high") -> OrphanCandidate:
    return OrphanCandidate(
        address=address,
        preceding_address=address - 2,
        following_address=address + 2,
        gap_size=2,
        confidence=confidence,
        evidence=f"orphan {address:06X}",
    )


def _plan_addresses(text: str) -> list[int]:
    return [int(line, 16) for line in text.splitlines() if line]


class M68kConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _analyze(self, harness: _M68kHarness):
        with mock.patch.multiple(pipeline, **harness.patches()):
            return pipeline.analyze_megadrive(self.root / "game.bin", self.root / "out", self.root / "ghidra")

    def test_inline_data_is_planned_before_decoding_continuation(self):
        call = InlineTrapCall(0x200, 0x202, 0x204, 0x300, 0x240)
        harness = _M68kHarness([{"inline": (call,)}, {"inline": (call,)}])
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertTrue(harness.plans_seen[1].startswith("DATA 000202 2\n"))
        self.assertIn("000204\n", harness.plans_seen[1])
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertTrue(progress["converged"])
        self.assertEqual([0x202], progress["passes"][0]["new_inline_data_addresses"])

    def test_subroutine_argument_is_data_and_continuation_skips_it(self):
        call = InlineTrapCall(0x200, 0x204, 0x206, None, 0x300)
        harness = _M68kHarness([{"inline_subroutine": (call,)}, {"inline_subroutine": (call,)}])
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertTrue(harness.plans_seen[1].startswith("DATA 000204 2\n"))
        self.assertIn("000206\n", harness.plans_seen[1])
        self.assertNotIn("000204\n", harness.plans_seen[1])
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertTrue(progress["converged"])

    def test_restored_trap_arguments_replace_stale_planned_code_next_pass(self):
        # Backend restoration exposes a previously erased TRAP. Its argument
        # was an accidental instruction/root on the preceding pass; the new
        # DATA proof must force a rerun even with the continuation already seeded.
        call = InlineTrapCall(0x200, 0x202, 0x204, 0x300, 0x240)
        seeds = tuple(DecoderSeed(a, "test", "proven", "existing plan") for a in (0x200, 0x202, 0x204))
        harness = _M68kHarness([{"inline": (call,)}, {"inline": (call,)}], initial_seeds=seeds)
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertIn("000202\n", harness.plans_seen[0])
        self.assertTrue(harness.plans_seen[1].startswith("DATA 000202 2\n"))
        self.assertNotIn("000202", harness.plans_seen[1].splitlines()[1:])
        self.assertIn("000204", harness.plans_seen[1].splitlines())
        self.assertNotIn(0x202, harness.interpreter_entrypoints[1])
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertEqual([0x202], progress["passes"][0]["new_inline_data_addresses"])
        self.assertTrue(progress["converged"])

    def test_rooted_dispatch_and_cursor_proofs_persist_for_next_decoder_pass(self):
        for key, kind in (
            ("reaching_dispatch", "reaching_word_dispatch"),
            ("cursor_callbacks", "bytecode_cursor_callback"),
            ("tail_callbacks", "tail_allocator_callback"),
        ):
            with self.subTest(proof=kind):
                seed = DecoderSeed(0x300, kind, "proven", "rooted consumer", 0x200)
                harness = _M68kHarness(
                    [
                        {"raw": (0x200, 0x300), "trusted": (0x200,), key: (seed,)},
                        {"raw": (0x200, 0x300), "reached": (0x200, 0x300), key: (seed,)},
                    ]
                )
                with self.assertRaises(_StopAfterLoop):
                    self._analyze(harness)
                self.assertEqual(2, len(harness.plans_seen))
                self.assertNotIn("000300", harness.plans_seen[0])
                self.assertIn("000300", harness.plans_seen[1])
                self.assertIn(0x300, harness.interpreter_entrypoints[1])
                progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
                self.assertTrue(progress["converged"])

    def test_exact_shared_leaf_can_bootstrap_without_predecoded_handlers(self):
        roots = [0x400, 0x420]
        for kind, confidence, expected in (
            ("leaf_word_dispatch", "proven", 2),
            ("pc_word_dispatch", "proven", 2),
            ("inline_word_dispatch", "proven", 2),
            ("leaf_word_dispatch", "high", 1),
            ("indexed_pointer_table_target", "proven", 1),
        ):
            with self.subTest(kind=kind, confidence=confidence):
                seeds = tuple(DecoderSeed(a, kind, confidence, "leaf semantics", 0x300) for a in roots)
                harness = _M68kHarness([{"raw": (0x300,), "raw_dispatch": seeds}, {}])
                with self.assertRaises(_StopAfterLoop):
                    self._analyze(harness)
                self.assertEqual(expected, len(harness.plans_seen))
                if expected == 2:
                    self.assertEqual([0x300, *roots], _plan_addresses(harness.plans_seen[1]))

    def test_new_return_witness_requires_backend_pass_even_for_planned_root(self):
        seed = DecoderSeed(0x206, "normal_return_continuation", "proven", "balanced RTS", 0x200)
        harness = _M68kHarness([{"returning": (seed,)}, {"returning": (seed,)}], initial_seeds=(seed,))
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertEqual("000200 000206\n", (self.root / "out/m68k/normal-return-calls.txt").read_text())
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertEqual([0x200], progress["passes"][0]["new_normal_return_calls"])
        self.assertTrue(progress["converged"])

    def test_perpetual_discovery_raises_after_bounded_passes(self) -> None:
        # Every pass proves a brand-new target, so the loop can never settle.
        harness = _M68kHarness(lambda index: {"edges": (_edge(0x1000 + 2 * index),)})

        with self.assertRaisesRegex(ValueError, "did not converge"):
            self._analyze(harness)

        self.assertEqual(len(harness.plans_seen), pipeline.MAX_ABSTRACT_PASSES)
        self.assertEqual(pipeline.MAX_ABSTRACT_PASSES, 32)
        # Trusted interpretation ran once per pass and never after the loop.
        self.assertEqual(harness.trusted_calls, pipeline.MAX_ABSTRACT_PASSES)
        self.assertFalse((self.root / "out" / "m68k" / "abstract-analysis.json").exists())
        progress = json.loads((self.root / "out" / "m68k" / "decoder-passes.json").read_text())
        self.assertFalse(progress["converged"])
        self.assertEqual(pipeline.MAX_ABSTRACT_PASSES, len(progress["passes"]))
        self.assertTrue(progress["passes"][-1]["new_seed_addresses"])

    def test_discovered_seed_is_planned_before_next_decoder_pass(self) -> None:
        initial = DecoderSeed(0x200, "reset", "proven", "reset vector")
        harness = _M68kHarness(
            [{"edges": (_edge(0x1000),)}, {}],
            initial_seeds=(initial,),
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        self.assertEqual(len(harness.plans_seen), 2)
        self.assertEqual(_plan_addresses(harness.plans_seen[0]), [0x200])
        self.assertEqual(_plan_addresses(harness.plans_seen[1]), [0x200, 0x1000])
        # The interpreter is rooted at exactly the seeds planned so far.
        self.assertEqual(harness.interpreter_entrypoints, [{0x200}, {0x200, 0x1000}])

    def test_dispatch_table_seed_is_planned_before_next_decoder_pass(
        self,
    ) -> None:
        initial = DecoderSeed(0x200, "reset", "proven", "reset vector")
        dispatch = DecoderSeed(0x1400, "dispatch_table_target", "proven", "table entry", 0x210)
        harness = _M68kHarness(
            [{"dispatch": (dispatch, initial)}, {"dispatch": (dispatch,)}],
            initial_seeds=(initial,),
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        # The second pass only rediscovered 0x1400, so the loop settled.
        self.assertEqual(len(harness.plans_seen), 2)
        self.assertEqual(_plan_addresses(harness.plans_seen[0]), [0x200])
        self.assertEqual(_plan_addresses(harness.plans_seen[1]), [0x200, 0x1400])
        # The converged pass is reused after the loop, not recomputed.
        self.assertEqual(harness.trusted_calls, 2)

    def test_validated_unused_function_becomes_a_root_on_next_pass(self):
        candidate = UnusedCodeCandidate(
            address=0x240,
            end=0x250,
            preceding_address=0x23E,
            instruction_count=4,
            instruction_addresses=(0x240, 0x246, 0x24A, 0x24E),
            signatures=("call_known_code", "rts"),
            evidence="validated complete CFG",
        )
        harness = _M68kHarness([{"unused": (candidate,)}, {}])
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual([0x240], _plan_addresses(harness.plans_seen[1]))
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertEqual([0x240], progress["passes"][0]["new_seed_addresses"])
        self.assertEqual(["validated complete CFG"], progress["passes"][0]["new_seed_evidence"][0]["evidence"])

    def test_constructor_callback_uses_rooted_execution_and_survives_reanalysis(self):
        seed = DecoderSeed(
            0x240, "constructor_record_callback", "proven", "counted ROM records share an executed RAM pool", 0x210
        )
        harness = _M68kHarness([{"constructor_callbacks": (seed,)}, {"constructor_callbacks": (seed,)}])
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual(2, len(harness.plans_seen))
        self.assertEqual([0x240], _plan_addresses(harness.plans_seen[1]))
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertTrue(progress["converged"])
        self.assertEqual([seed.evidence], progress["passes"][0]["new_seed_evidence"][0]["evidence"])

    def test_structural_callback_from_raw_is_planned_for_next_pass(self):
        callback = _handler(0x350)
        harness = _M68kHarness(
            [
                {"raw_callbacks": (callback,)},
                {"raw_callbacks": (callback,)},
            ]
        )
        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)
        self.assertEqual([0x350], _plan_addresses(harness.plans_seen[1]))
        progress = json.loads((self.root / "out/m68k/decoder-passes.json").read_text())
        self.assertEqual(["handler 000350"], progress["passes"][0]["new_seed_evidence"][0]["evidence"])

    def test_low_confidence_candidates_are_not_planned(self) -> None:
        harness = _M68kHarness(
            [
                {
                    "edges": (_edge(0x1000, confidence="likely"),),
                    "handlers": (_handler(0x1100, confidence="likely"),),
                    "orphans": (_orphan(0x1200, confidence="medium"),),
                }
            ]
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        self.assertEqual(len(harness.plans_seen), 1)
        self.assertEqual(_plan_addresses(harness.plans_seen[0]), [])

    def test_already_planned_seeds_are_not_duplicated(self) -> None:
        initial = DecoderSeed(0x200, "reset", "proven", "reset vector")
        # Pass 1 rediscovers the initial seed through every channel and finds
        # 0x300 through two channels; pass 2 only repeats known addresses.
        repeated = {
            "edges": (_edge(0x200), _edge(0x300)),
            "handlers": (_handler(0x200), _handler(0x300)),
            "orphans": (_orphan(0x200), _orphan(0x300)),
        }
        harness = _M68kHarness([repeated, repeated], initial_seeds=(initial, initial))

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        # The repeat pass discovered nothing new, so the loop stopped there.
        self.assertEqual(len(harness.plans_seen), 2)
        for plan in harness.plans_seen:
            addresses = _plan_addresses(plan)
            self.assertEqual(len(addresses), len(set(addresses)), plan)
        self.assertEqual(_plan_addresses(harness.plans_seen[0]), [0x200])
        self.assertEqual(_plan_addresses(harness.plans_seen[1]), [0x200, 0x300])

    def test_decoded_but_untrusted_proven_targets_are_planned(self) -> None:
        # 0x300 and 0x340 were decoded inside a backend island; 0x320 is
        # already reached from the planned roots and needs no seed.
        harness = _M68kHarness(
            [
                {
                    "raw": (0x300, 0x320, 0x340),
                    "trusted": (0x320,),
                    "edges": (_edge(0x300), _edge(0x320)),
                    "handlers": (_handler(0x340), _handler(0x320)),
                },
                {},
            ]
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        self.assertEqual([0x300, 0x340], _plan_addresses(harness.plans_seen[1]))
        self.assertEqual([set(), {0x300, 0x340}], harness.interpreter_entrypoints)

    def test_proven_handler_absent_from_raw_facts_is_planned(self) -> None:
        # The backend never decoded 0x380; only the slot proof names it.
        harness = _M68kHarness(
            [
                {
                    "raw": (0x200,),
                    "trusted": (0x200,),
                    "handlers": (_handler(0x380), _handler(0x3C0, confidence="candidate")),
                },
                {
                    "raw": (0x200, 0x380),
                    "reached": (0x200, 0x380),
                    "handlers": (_handler(0x380), _handler(0x3C0, confidence="candidate")),
                },
            ]
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        self.assertEqual(2, len(harness.plans_seen))
        self.assertEqual([0x380], _plan_addresses(harness.plans_seen[1]))
        self.assertEqual([set(), {0x380}], harness.interpreter_entrypoints)
        document = json.loads((self.root / "out/m68k/abstract-analysis.json").read_text())
        evidence = {item["address"]: item for item in document["decoder_seed_evidence"]}
        self.assertEqual(["ram_handler"], evidence[0x380]["kinds"])
        self.assertNotIn(0x3C0, document["decoder_seed_addresses"])

    def test_analysis_persists_the_converged_trusted_root_set(self) -> None:
        harness = _M68kHarness(
            [
                {"edges": (_edge(0x1000),)},
                {"edges": (_edge(0x1000), _edge(0x1040)), "reached": (0x1040,)},
            ]
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        # 0x1040 is proven but already reached, so it is a root not a seed.
        document = json.loads((self.root / "out/m68k/abstract-analysis.json").read_text())
        self.assertEqual([0x1000], document["decoder_seed_addresses"])
        self.assertEqual([0x1000, 0x1040], document["trusted_root_addresses"])


def _flow(address, mnemonic, operands, length, flow_type, flows=()):
    return replace(
        fact(address, mnemonic, operands, flows=flows),
        raw=bytes(length),
        length=length,
        flow_type=flow_type,
    )


class TrustedEmitFactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = parse_megadrive(cartridge(size=0x500))
        entry = _flow(0x200, "RTS", "", 2, "TERMINATOR")
        island = _flow(0x300, "RTS", "", 2, "TERMINATOR")
        self.facts = {item.physical_offset: item for item in (entry, island)}

    def _addresses(self, facts) -> set[int]:
        return {item.cpu_address for item in facts.values()}

    def test_persisted_roots_select_the_analysed_instructions(self) -> None:
        retained = pipeline._trusted_emit_facts(
            self.image,
            self.facts,
            {"trusted_root_addresses": [0x300]},
            {0x200, 0x300},
        )
        self.assertEqual({0x200, 0x300}, self._addresses(retained))

    def test_emit_ignores_raw_structural_roots_absent_from_persisted_set(self) -> None:
        # Old emit recomputed extra roots from raw facts; the island must not
        # be revived when analysis did not trust it.
        retained = pipeline._trusted_emit_facts(
            self.image,
            self.facts,
            {"trusted_root_addresses": []},
            {0x200},
        )
        self.assertEqual({0x200}, self._addresses(retained))

    def test_inconsistent_persisted_roots_are_rejected(self) -> None:
        with self.assertRaises(MegaDriveEmitError):
            pipeline._trusted_emit_facts(
                self.image,
                self.facts,
                {"trusted_root_addresses": []},
                {0x200, 0x300},
            )

    def test_legacy_cache_reuses_the_analysed_instruction_set(self) -> None:
        retained = pipeline._trusted_emit_facts(
            self.image,
            self.facts,
            {"decoder_seed_addresses": []},
            {0x200, 0x300},
        )
        self.assertEqual({0x200, 0x300}, self._addresses(retained))
        with self.assertRaises(MegaDriveEmitError):
            pipeline._trusted_emit_facts(
                self.image,
                self.facts,
                {},
                {0x200, 0x400},
            )


class Z80DispatchConvergenceTests(unittest.TestCase):
    PAYLOAD_START = 0x100
    PAYLOAD_SIZE = 0x80

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.z80_runs: list[Path | None] = []
        self.plans_seen: list[str] = []

    def _copy(self) -> CrossCpuCopy:
        return CrossCpuCopy(
            edge_id="copy.00",
            schema_id="megadrive.z80.copy",
            source_cpu_id="m68k",
            source_space="m68k",
            source_start=self.PAYLOAD_START,
            source_end=self.PAYLOAD_START + self.PAYLOAD_SIZE - 1,
            target_cpu_id="z80",
            target_space="z80",
            target_start=0,
            target_end=self.PAYLOAD_SIZE - 1,
            size=self.PAYLOAD_SIZE,
            payload_sha256=hashlib.sha256(bytes(self.PAYLOAD_SIZE)).hexdigest(),
            evidence_addresses=(0x200,),
            confidence="proven",
        )

    def _run_z80(
        self,
        z80_input,
        z80_root,
        ghidra_home,
        scripts,
        *,
        base_address,
        seed_plan=None,
    ):
        self.z80_runs.append(seed_plan)
        if seed_plan is not None:
            self.plans_seen.append(seed_plan.read_text(encoding="ascii"))
        return _artifacts(z80_root)

    def _write_stub(self, path, *args):
        path.write_text("{}\n", encoding="utf-8")

    def _analyze(self, discover, copies=None):
        m68k = _M68kHarness([{}], stop_after_loop=False)
        patches = m68k.patches()
        patches.update(
            detect_pointer_candidates=lambda image, facts: [],
            write_pointer_report=self._write_stub,
            detect_z80_copies=lambda image, facts: list(copies or (self._copy(),)),
            run_z80_analysis=self._run_z80,
            load_z80_ghidra_facts=lambda path, payload, *, base_address: {},
            z80_im1_handler_seed=lambda facts, start, size: None,
            discover_z80_dispatch_tables=discover,
            generate_symbols=lambda *args: [],
            write_symbol_report=self._write_stub,
        )
        with mock.patch.multiple(pipeline, **patches):
            return pipeline.analyze_megadrive(self.root / "game.bin", self.root / "out", self.root / "ghidra")

    def test_adjacent_uploads_share_one_z80_analysis(self) -> None:
        first = self._copy()
        second = replace(
            first,
            edge_id="copy.01",
            source_start=0x180,
            source_end=0x1FF,
            target_start=0x80,
            target_end=0xFF,
        )
        analysis = self._analyze(
            lambda payload, facts, *, base_address: (),
            copies=(first, second),
        )
        self.assertEqual(2, len(analysis["programs"]))
        self.assertEqual(1, len(self.z80_runs))
        z80_program = analysis["programs"][1]
        self.assertEqual(["copy.00", "copy.01"], z80_program["derived_from"])
        self.assertEqual(0x100, (self.root / "out" / z80_program["analysis_input"]).stat().st_size)
        self.assertEqual(2, analysis["cross_cpu_evidence"]["edge_count"])
        evidence = json.loads((self.root / "out" / "cross-cpu-evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(
            ["z80.00", "z80.00"],
            [edge["target"]["cpu_id"] for edge in evidence["edges"]],
        )

    def test_ever_growing_dispatch_tables_raise_after_bounded_reanalysis(
        self,
    ) -> None:
        calls = []

        def discover(payload, facts, *, base_address):
            # Each reanalysis reveals yet another table.
            calls.append(None)
            start = 0x10 + 4 * len(calls)
            return [
                Z80DispatchTable(
                    logical_start=start,
                    logical_end=start + 2,
                    dispatch_address=0x02,
                    lookup_address=0x08,
                    targets=(0x40,),
                )
            ]

        with self.assertRaisesRegex(ValueError, "did not converge"):
            self._analyze(discover)

        reanalyses = [plan for plan in self.z80_runs if plan is not None]
        self.assertGreaterEqual(len(reanalyses), 1)
        self.assertLessEqual(len(self.z80_runs), 1 + 4)
        self.assertEqual(len(reanalyses), len(self.z80_runs) - 1)

    def test_stable_dispatch_table_is_reanalysed_once_with_its_plan(
        self,
    ) -> None:
        table = Z80DispatchTable(
            logical_start=0x20,
            logical_end=0x24,
            dispatch_address=0x02,
            lookup_address=0x08,
            targets=(0x40, 0x50),
        )

        manifest = self._analyze(lambda payload, facts, *, base_address: [table])

        self.assertEqual(len(self.z80_runs), 2)
        self.assertIsNone(self.z80_runs[0])
        self.assertEqual(
            self.plans_seen[0].splitlines(),
            ["T 0020 0024", "S 0040", "S 0050"],
        )
        dispatch = json.loads(
            (self.root / "out" / "z80" / "program00" / "dispatch-tables.json").read_text(encoding="utf-8")
        )
        self.assertEqual([t["logical_start"] for t in dispatch["tables"]], [0x20])
        self.assertEqual(len(manifest["programs"]), 2)

    def test_changed_dispatch_table_is_rejected(self) -> None:
        tables = iter(
            [
                Z80DispatchTable(0x20, 0x24, 0x02, 0x08, (0x40, 0x50)),
                Z80DispatchTable(0x20, 0x24, 0x02, 0x08, (0x60, 0x50)),
            ]
        )

        with self.assertRaisesRegex(ValueError, "changed at 0x0020"):
            self._analyze(lambda payload, facts, *, base_address: [next(tables)])


if __name__ == "__main__":
    unittest.main()
