"""A stubbed Mega Drive pipeline that records what its feedback loops hand to the decoder."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from retrolarium_disassembler.ghidra import GhidraArtifacts
from retrolarium_disassembler.m68k.abstract import IndirectEdge, InterpretationResult, TrustedCfg


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
        self.probe_plans_seen: list[str] = []
        self.repair_plans_seen: list[str] = []
        # Entrypoints handed to the trusted interpreter on each decoder pass.
        self.interpreter_entrypoints: list[set[int]] = []
        self.trusted_calls = 0
        self._last_facts = None
        self._trusted_facts = None

    def _current(self):
        index = len(self.plans_seen) - 1
        if callable(self.passes):
            return self.passes(index)
        return self.passes[min(index, len(self.passes) - 1)]

    def run_megadrive_analysis(
        self, analysis_input, program_root, ghidra_home, scripts, *, seed_plan, probe_orphans=False,
        probe_requests=None, fallthrough_repairs=None,
    ):
        # Snapshot what the decoder would read at invocation time.
        self.plans_seen.append(seed_plan.read_text(encoding="ascii"))
        self.probe_plans_seen.append(probe_requests.read_text(encoding="ascii") if probe_requests else "")
        self.repair_plans_seen.append(fallthrough_repairs.read_text(encoding="ascii") if fallthrough_repairs else "")
        return _artifacts(program_root)

    def interpret_trusted_cfg(self, image, facts, *, entrypoints):
        # Runs once per decoder pass on the raw facts; the converged result
        # of the final pass is reused after the loop.
        assert facts is self._last_facts
        self.trusted_calls += 1
        self.interpreter_entrypoints.append(set(entrypoints))
        current = self._current()
        edges = tuple(current.get("edges", ()))
        self._trusted_facts = {
            address: SimpleNamespace(cpu_address=address)
            for address in current.get("trusted", ())
        }
        return TrustedCfg(
            facts=self._trusted_facts,
            interpretation=_interpretation(*edges),
            roots=frozenset(entrypoints) | {
                edge.target_address for edge in edges
                if edge.confidence == "proven"
            },
            # "reached" marks starts reached from the seeds without adding
            # fake facts, which the post-loop writer cannot serialize.
            entry_reached=frozenset(
                (*current.get("trusted", ()), *current.get("reached", ()))
            ),
            iterations=1,
        )

    def load_facts(self, path, image, **kwargs):
        self._last_facts = {
            address: SimpleNamespace(cpu_address=address)
            for address in self._current().get("raw", ())
        }
        return self._last_facts

    def handlers(self, image, facts):
        # Entry-point handlers are only ever read from trusted facts.
        if facts is not self._trusted_facts:
            return []
        return list(self._current().get("handlers", ()))

    def pointers(self, image, facts):
        # First analyzer after abstract-analysis.json and instructions.json.
        if self.stop_after_loop:
            raise _StopAfterLoop
        return []

    def object_handlers(self, image, facts, *, execution_facts=None):
        if execution_facts is not None:
            assert execution_facts is self._trusted_facts
        if facts is not self._last_facts:
            return []
        return list(self._current().get("raw_callbacks", ()))

    def orphans(self, image, facts):
        if facts is not self._last_facts:
            return []
        return list(self._current().get("orphans", ()))

    def dispatch_seeds(self, image, facts, *, handler_validator=None, entrypoints=()):
        assert set(self.interpreter_entrypoints[-1]) <= set(entrypoints)
        # Raw dispatcher islands are considered separately from trusted code.
        if facts is not self._trusted_facts:
            return list(self._current().get("raw_dispatch", ()))
        return list(self._current().get("dispatch", ()))

    def word_callbacks(self, image, facts, *, execution_facts):
        assert facts is self._last_facts
        assert execution_facts is self._trusted_facts
        return tuple(self._current().get("word_callbacks", ()))

    def constructor_callbacks(self, image, facts, *, execution_facts):
        assert facts is self._last_facts
        assert execution_facts is self._trusted_facts
        return tuple(self._current().get("constructor_callbacks", ()))

    def reaching_dispatch(self, image, facts, *, entrypoints, handler_validator):
        assert facts is self._trusted_facts
        assert set(self.interpreter_entrypoints[-1]) <= set(entrypoints)
        return tuple(self._current().get("reaching_dispatch", ()))

    def cursor_callbacks(self, image, trusted_facts, facts, artifacts, context):
        assert facts is self._last_facts
        assert trusted_facts is self._trusted_facts
        return tuple(self._current().get("cursor_callbacks", ()))

    def tail_callbacks(self, image, trusted_facts, facts, artifacts, context):
        assert facts is self._last_facts
        assert trusted_facts is self._trusted_facts
        return tuple(self._current().get("tail_callbacks", ()))

    def patches(self) -> dict[str, object]:
        return {
            "discover_inline_trap_calls": lambda *args: tuple(self._current().get("inline", ())),
            "discover_inline_subroutine_calls": lambda *args: tuple(self._current().get("inline_subroutine", ())),
            "discover_inline_operand_calls": lambda *args, **kwargs: tuple(self._current().get("inline_operand", ())),
            "discover_link_continuation_seeds": lambda *args: (),
            "discover_returning_call_seeds": lambda *args, **kwargs: tuple(self._current().get("returning", ())),
            "discover_register_callback_seeds": lambda *args, **kwargs: (),
            "discover_callback_abi_seeds": lambda *args, **kwargs: (),
            "discover_constructor_record_seeds": self.constructor_callbacks,
            "discover_reaching_word_dispatch_seeds": self.reaching_dispatch,
            "_discover_cursor_callbacks": self.cursor_callbacks,
            "_discover_tail_callbacks": self.tail_callbacks,
            "_discover_relative_callbacks": lambda *args, **kwargs: (),
            "_discover_cleared_states": lambda *args, **kwargs: (),
            "_discover_absolute_callbacks": lambda *args, **kwargs: (),
            "_discover_finite_callbacks": lambda *args, **kwargs: (),
            "discover_ram_record_dispatch_seeds": lambda *args: (),
            "discover_word_ram_callback_seeds": self.word_callbacks,
            "_discover_packed_code": lambda *args: (),
            "_discover_fallthrough_repairs": lambda *args: (),
            "_discover_unused_code": lambda *args: (tuple(self._current().get("unused", ())), ()),
            "load_megadrive": lambda rom: _image(),
            "toolchain_status": lambda home: None,
            "discover_initial_decoder_seeds": lambda image: self.initial_seeds,
            "run_megadrive_analysis": self.run_megadrive_analysis,
            "load_megadrive_ghidra_facts": self.load_facts,
            "interpret_trusted_cfg": self.interpret_trusted_cfg,
            "discover_ram_handler_candidates": self.handlers,
            "discover_object_field_handler_candidates": self.object_handlers,
            "discover_packed_orphan_candidates": self.orphans,
            "discover_dispatch_table_seeds": self.dispatch_seeds,
            "discover_descriptor_ram_code_seeds": lambda image, facts: (),
            "detect_pointer_candidates": self.pointers,
        }
