"""The disassembler's import rules, checked on the source.

It builds on retrolarium-core alone: only preset.py, which turns a game into a
Studio project, reaches for Retrolarium Kit. The shared modules (facts, the
Ghidra bridge, toolchains, verification, benchmarks) know no platform. Each
platform package keeps to itself, except that the Mega Drive pipeline drives
the 68000 passes and the Z80 dispatch. The 68000 passes take their
instruction helpers from m68k/instructions.py; from megadrive/ they still use
only the ASM68K instruction text and the dispatch-table detectors, by name.
"""

from __future__ import annotations

import ast
from pathlib import Path
import unittest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "retrolarium_disassembler"
PLATFORMS = {"nes", "megadrive", "m68k", "z80", "snes"}
SHARED = {"facts", "ghidra", "toolchain", "verify", "benchmark"}
ALLOWED = {("megadrive", "m68k"), ("megadrive", "z80"), ("m68k", "megadrive")}
# What the 68000 passes may still take from megadrive/ (moving these into
# m68k/ waits for a second 68000 platform, Sega CD or 32X, to shape them).
M68K_FROM_MEGADRIVE = {
    ("retrolarium_disassembler.megadrive.emit", "_asm_instruction"),
    ("retrolarium_disassembler.megadrive.pointers", "_pc_word_dispatch_tables"),
    ("retrolarium_disassembler.megadrive.pointers", "_word_dispatch_tables"),
    ("retrolarium_disassembler.megadrive.pointers", "discover_dispatch_table_seeds"),
    ("retrolarium_disassembler.megadrive.pointers", "can_bootstrap_dispatch_seeds"),
    ("retrolarium_disassembler.megadrive.pointers", "detect_pointer_candidates"),
}


def imports() -> list[tuple[tuple[str, ...], tuple[str, ...], int]]:
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = path.relative_to(PACKAGE).with_suffix("").parts
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
                if node.module == "retrolarium_disassembler":
                    names += [f"{node.module}.{alias.name}" for alias in node.names]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            for name in names:
                found.append((module, tuple(name.split(".")), node.lineno))
    return found


class LayerTests(unittest.TestCase):
    def test_only_the_preset_imports_the_kit(self) -> None:
        importers = sorted({"/".join(module) for module, target, _line in imports() if target[0] == "retrolarium_kit"})
        self.assertEqual(["preset"], importers)

    def test_shared_modules_know_no_platform(self) -> None:
        offenders = [
            f"{'.'.join(module)}:{line} imports {'.'.join(target)}"
            for module, target, line in imports()
            if module[0] in SHARED
            and target[0] == "retrolarium_disassembler"
            and len(target) > 1
            and target[1] in PLATFORMS | {"cli", "preset"}
        ]
        self.assertEqual([], offenders)

    def test_platforms_keep_to_themselves(self) -> None:
        offenders = []
        for module, target, line in imports():
            if module[0] not in PLATFORMS or target[0] != "retrolarium_disassembler" or len(target) < 2:
                continue
            other = target[1]
            if other in {"cli", "preset"} or (
                other in PLATFORMS and other != module[0] and (module[0], other) not in ALLOWED
            ):
                offenders.append(f"{'.'.join(module)}:{line} imports {'.'.join(target)}")
        self.assertEqual([], offenders)

    def test_m68k_takes_only_the_listed_names_from_megadrive(self) -> None:
        offenders = []
        for path in sorted((PACKAGE / "m68k").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    offenders += [
                        f"{path.name}:{node.lineno} imports {alias.name}"
                        for alias in node.names
                        if alias.name.startswith("retrolarium_disassembler.megadrive")
                    ]
                if not (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith("retrolarium_disassembler.megadrive")
                ):
                    continue
                offenders += [
                    f"{path.name}:{node.lineno} imports {node.module}.{alias.name}"
                    for alias in node.names
                    if (node.module, alias.name) not in M68K_FROM_MEGADRIVE
                ]
        self.assertEqual([], offenders)

    def test_the_package_imports_without_the_kit(self) -> None:
        # Everything but the preset loads in an interpreter that cannot see
        # Retrolarium Kit.
        import os
        import subprocess
        import sys

        script = (
            "import importlib, pkgutil, sys\n"
            "class NoKit:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name == 'retrolarium_kit' or name.startswith('retrolarium_kit.'):\n"
            "            raise ImportError('no kit here')\n"
            "sys.meta_path.insert(0, NoKit())\n"
            "import retrolarium_disassembler\n"
            "for info in pkgutil.walk_packages(retrolarium_disassembler.__path__, 'retrolarium_disassembler.'):\n"
            "    if info.name.rsplit('.', 1)[-1] not in ('preset', '__main__'):\n"
            "        importlib.import_module(info.name)\n"
            "print('ok')\n"
        )
        environment = {"PYTHONPATH": str(PACKAGE.parent), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=environment)
        self.assertEqual("ok", result.stdout.strip(), result.stderr)


if __name__ == "__main__":
    unittest.main()
