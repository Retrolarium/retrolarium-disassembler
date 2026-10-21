"""Retrolarium Disassembler: whole-ROM disassemblies that rebuild byte for byte.

NES (6502/ca65), Mega Drive (68000 + Z80/AS) and SNES (W65C816 + SPC700/ca65)
images are analyzed with headless Ghidra plus the project's own passes, emitted
as modular source projects and verified against the original image. The
package builds on retrolarium_core only; `rldisasm preset`, which turns a
recognized game into a Studio project, additionally needs Retrolarium Kit.
"""

__version__ = "0.5.0"


def _find_core() -> None:
    # An installed disassembler gets retrolarium_core as a dependency; a source
    # checkout finds it beside the disassembler, in the monorepo
    # (retrolarium-core/python) or with the repositories cloned side by side.
    import importlib.util
    import sys
    from pathlib import Path

    if importlib.util.find_spec("retrolarium_core") is not None:
        return
    here = Path(__file__).resolve()
    for root in (here.parents[3], here.parents[3].parent):
        candidate = root / "retrolarium-core" / "python"
        if (candidate / "retrolarium_core").is_dir():
            sys.path.append(str(candidate))
            return


_find_core()


class AnalysisError(ValueError):
    """An analysis that cannot go on: it did not converge, or its own results
    contradict each other. The CLI prints it in one line."""
