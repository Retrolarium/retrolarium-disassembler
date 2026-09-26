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


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_kit import megadrive_pipeline as pipeline
from retrolarium_kit.ghidra import GhidraArtifacts
from retrolarium_kit.m68k_abstract import (
    EntryPointCandidate,
    IndirectEdge,
    InterpretationResult,
    OrphanCandidate,
)
from retrolarium_kit.m68k_seeds import DecoderSeed
from retrolarium_kit.megadrive_z80 import CrossCpuCopy
from retrolarium_kit.z80_dispatch import Z80DispatchTable


class _StopAfterLoop(Exception):
    """Raised by a stub right after the M68K loop to end the run early."""


def _image() -> SimpleNamespace:
    return SimpleNamespace(
        data=bytes(0x400),
        sha256="0" * 64,
        header=SimpleNamespace(rom_start=0),
        actual_rom_end=0x3FF,
    )


def _interpretation(*edges: IndirectEdge) -> InterpretationResult:
    return InterpretationResult(
        reached_addresses=(),
        indirect_edges=tuple(edges),
        branch_decisions=(),
        unresolved_indirect_addresses=(),
        state_updates=0,
        widened_addresses=(),
    )


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


def _artifacts(root: Path) -> GhidraArtifacts:
    root.mkdir(parents=True, exist_ok=True)
    facts = root / "instructions.tsv"
    report = root / "report.json"
    log = root / "ghidra.log"
    facts.write_text("", encoding="utf-8")
    report.write_text(
        json.dumps({"language": "stub", "compiler": "default"}),
        encoding="utf-8",
    )
    log.write_text("", encoding="utf-8")
    return GhidraArtifacts(facts=facts, report=report, log=log)


def _plan_addresses(text: str) -> list[int]:
    return [int(line, 16) for line in text.splitlines() if line]


class _M68kHarness:
    """Scripted per-pass analyzer results plus a recording fake Ghidra."""

    def __init__(
        self,
        passes,
        *,
        initial_seeds=(),
        stop_after_loop: bool = True,
    ) -> None:
        self.passes = passes
        self.initial_seeds = tuple(initial_seeds)
        self.stop_after_loop = stop_after_loop
        self.plans_seen: list[str] = []
        # Entrypoints handed to the interpreter on each decoder pass.
        self.interpreter_entrypoints: list[set[int]] = []
        self.retain_calls = 0
        self._last_facts = None
        self._trusted_facts = None

    def _current(self):
        index = len(self.plans_seen) - 1
        if callable(self.passes):
            return self.passes(index)
        return self.passes[min(index, len(self.passes) - 1)]

    def run_megadrive_analysis(
        self, analysis_input, program_root, ghidra_home, scripts, *, seed_plan
    ):
        # Snapshot what the decoder would read at invocation time.
        self.plans_seen.append(seed_plan.read_text(encoding="ascii"))
        return _artifacts(program_root)

    def interpret_known_cfg(self, image, facts, *, additional_entrypoints):
        # Only the in-loop call sees the raw decoder facts; the post-loop
        # call receives the filtered facts and reports nothing new.
        if facts is not self._last_facts:
            return _interpretation()
        self.interpreter_entrypoints.append(set(additional_entrypoints))
        return _interpretation(*self._current().get("edges", ()))

    def load_facts(self, path, image):
        self._last_facts = {}
        return self._last_facts

    def handlers(self, image, facts):
        if facts is not self._last_facts:
            return []
        return list(self._current().get("handlers", ()))

    def orphans(self, image, facts):
        if facts is not self._last_facts:
            return []
        return list(self._current().get("orphans", ()))

    def retain(self, image, facts, *, additional_entrypoints):
        self.retain_calls += 1
        if self.retain_calls <= len(self.plans_seen):
            # In-loop filtering ahead of dispatch-table discovery.
            self._trusted_facts = {}
            return self._trusted_facts
        # First call beyond the decoder passes is the post-loop filter.
        if self.stop_after_loop:
            raise _StopAfterLoop
        return {}

    def dispatch_seeds(self, image, facts):
        # Dispatch discovery must only ever see this pass's trusted facts.
        if facts is not self._trusted_facts:
            return []
        return list(self._current().get("dispatch", ()))

    def patches(self) -> dict[str, object]:
        return {
            "load_megadrive": lambda rom: _image(),
            "toolchain_status": lambda home: None,
            "discover_initial_decoder_seeds": lambda image: self.initial_seeds,
            "run_megadrive_analysis": self.run_megadrive_analysis,
            "load_megadrive_ghidra_facts": self.load_facts,
            "interpret_known_cfg": self.interpret_known_cfg,
            "discover_ram_handler_candidates": self.handlers,
            "discover_packed_orphan_candidates": self.orphans,
            "retain_trusted_instruction_facts": self.retain,
            "discover_dispatch_table_seeds": self.dispatch_seeds,
        }


class M68kConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _analyze(self, harness: _M68kHarness):
        with mock.patch.multiple(pipeline, **harness.patches()):
            return pipeline.analyze_megadrive(
                self.root / "game.bin", self.root / "out", self.root / "ghidra"
            )

    def test_perpetual_discovery_raises_after_bounded_passes(self) -> None:
        # Every pass proves a brand-new target, so the loop can never settle.
        harness = _M68kHarness(
            lambda index: {"edges": (_edge(0x1000 + 2 * index),)}
        )

        with self.assertRaisesRegex(ValueError, "did not converge"):
            self._analyze(harness)

        self.assertEqual(len(harness.plans_seen), pipeline.MAX_ABSTRACT_PASSES)
        self.assertEqual(pipeline.MAX_ABSTRACT_PASSES, 12)
        # Filtering ran once per pass, never the post-convergence filter.
        self.assertEqual(harness.retain_calls, pipeline.MAX_ABSTRACT_PASSES)
        self.assertFalse(
            (self.root / "out" / "m68k" / "abstract-analysis.json").exists()
        )

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
        self.assertEqual(
            _plan_addresses(harness.plans_seen[1]), [0x200, 0x1000]
        )
        # The interpreter is rooted at exactly the seeds planned so far.
        self.assertEqual(
            harness.interpreter_entrypoints, [{0x200}, {0x200, 0x1000}]
        )

    def test_dispatch_table_seed_is_planned_before_next_decoder_pass(
        self,
    ) -> None:
        initial = DecoderSeed(0x200, "reset", "proven", "reset vector")
        dispatch = DecoderSeed(
            0x1400, "dispatch_table_target", "proven", "table entry", 0x210
        )
        harness = _M68kHarness(
            [{"dispatch": (dispatch, initial)}, {"dispatch": (dispatch,)}],
            initial_seeds=(initial,),
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        # The second pass only rediscovered 0x1400, so the loop settled.
        self.assertEqual(len(harness.plans_seen), 2)
        self.assertEqual(_plan_addresses(harness.plans_seen[0]), [0x200])
        self.assertEqual(
            _plan_addresses(harness.plans_seen[1]), [0x200, 0x1400]
        )
        self.assertEqual(harness.retain_calls, 3)

    def test_low_confidence_candidates_are_not_planned(self) -> None:
        harness = _M68kHarness([
            {
                "edges": (_edge(0x1000, confidence="likely"),),
                "handlers": (_handler(0x1100, confidence="likely"),),
                "orphans": (_orphan(0x1200, confidence="medium"),),
            }
        ])

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
        harness = _M68kHarness(
            [repeated, repeated], initial_seeds=(initial, initial)
        )

        with self.assertRaises(_StopAfterLoop):
            self._analyze(harness)

        # The repeat pass discovered nothing new, so the loop stopped there.
        self.assertEqual(len(harness.plans_seen), 2)
        for plan in harness.plans_seen:
            addresses = _plan_addresses(plan)
            self.assertEqual(len(addresses), len(set(addresses)), plan)
        self.assertEqual(_plan_addresses(harness.plans_seen[0]), [0x200])
        self.assertEqual(
            _plan_addresses(harness.plans_seen[1]), [0x200, 0x300]
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
        self, z80_input, z80_root, ghidra_home, scripts, *,
        base_address, seed_plan=None,
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
            return pipeline.analyze_megadrive(
                self.root / "game.bin", self.root / "out", self.root / "ghidra"
            )

    def test_adjacent_uploads_share_one_z80_analysis(self) -> None:
        first = self._copy()
        second = replace(
            first, edge_id="copy.01", source_start=0x180,
            source_end=0x1FF, target_start=0x80, target_end=0xFF,
        )
        analysis = self._analyze(
            lambda payload, facts, *, base_address: (),
            copies=(first, second),
        )
        self.assertEqual(2, len(analysis["programs"]))
        self.assertEqual(1, len(self.z80_runs))
        z80_program = analysis["programs"][1]
        self.assertEqual(["copy.00", "copy.01"], z80_program["derived_from"])
        self.assertEqual(0x100, (
            self.root / "out" / z80_program["analysis_input"]
        ).stat().st_size)
        self.assertEqual(2, analysis["cross_cpu_evidence"]["edge_count"])
        evidence = json.loads((
            self.root / "out" / "cross-cpu-evidence.json"
        ).read_text(encoding="utf-8"))
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

        manifest = self._analyze(
            lambda payload, facts, *, base_address: [table]
        )

        self.assertEqual(len(self.z80_runs), 2)
        self.assertIsNone(self.z80_runs[0])
        self.assertEqual(
            self.plans_seen[0].splitlines(),
            ["T 0020 0024", "S 0040", "S 0050"],
        )
        dispatch = json.loads(
            (self.root / "out" / "z80" / "program00" / "dispatch-tables.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            [t["logical_start"] for t in dispatch["tables"]], [0x20]
        )
        self.assertEqual(len(manifest["programs"]), 2)

    def test_changed_dispatch_table_is_rejected(self) -> None:
        tables = iter([
            Z80DispatchTable(0x20, 0x24, 0x02, 0x08, (0x40, 0x50)),
            Z80DispatchTable(0x20, 0x24, 0x02, 0x08, (0x60, 0x50)),
        ])

        with self.assertRaisesRegex(ValueError, "changed at 0x0020"):
            self._analyze(lambda payload, facts, *, base_address: [next(tables)])


if __name__ == "__main__":
    unittest.main()
