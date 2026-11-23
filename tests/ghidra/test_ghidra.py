from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from retrolarium_disassembler.ghidra import (
    GhidraError,
    run_launcher,
    run_megadrive_analysis,
    run_nes_analysis,
    run_spc700_analysis,
    run_snes_bank_analysis,
    run_z80_analysis,
)


class GhidraBackendTests(unittest.TestCase):
    def test_nonzero_z80_base_survives_hex_loader_parsing(self) -> None:
        def interpret_loader_address(*args, import_arguments, **kwargs):
            index = import_arguments.index("-loader-baseAddr")
            return int(import_arguments[index + 1], 16)

        with patch("retrolarium_disassembler.ghidra._run_analysis", side_effect=interpret_loader_address):
            decoded_base = run_z80_analysis(
                Path("payload.bin"), Path("output"), Path("ghidra"), Path("scripts"), base_address=0x1C00
            )
        self.assertEqual(0x1C00, decoded_base)

    @staticmethod
    def fake_layout(root: Path) -> tuple[Path, Path, Path]:
        image = root / "probe.bin"
        image.write_bytes(b"probe")
        ghidra_home = root / "ghidra"
        support = ghidra_home / "support"
        support.mkdir(parents=True)
        headless_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        (support / headless_name).write_text("headless", encoding="utf-8")
        scripts = root / "scripts"
        scripts.mkdir()
        return image, ghidra_home, scripts

    def test_nes_vectors_are_seeded_before_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {
                            "language": "6502:LE:16:default",
                            "compiler": "default",
                        }
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_nes_analysis(image, workspace, ghidra_home, scripts)

            command = run.call_args.args[0]
            seed_index = command.index("-preScript")
            self.assertEqual("SeedNesVectors.java", command[seed_index + 1])
            self.assertLess(seed_index, command.index("-postScript"))
            # Without a seed plan the vector script gets no argument.
            self.assertEqual("-postScript", command[seed_index + 2])

    def test_nes_entry_seed_plan_reaches_vector_script(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            seed_plan = root / "entry-seeds.txt"
            seed_plan.write_text("8000\nC123\n", encoding="utf-8")

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps({"language": "6502:LE:16:default", "compiler": "default"}),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_nes_analysis(image, workspace, ghidra_home, scripts, seed_plan=seed_plan)

            command = run.call_args.args[0]
            seed_index = command.index("SeedNesVectors.java")
            self.assertEqual("-preScript", command[seed_index - 1])
            self.assertEqual(str(seed_plan.resolve()), command[seed_index + 1])
            self.assertEqual("-postScript", command[seed_index + 2])

        # The script must consume that single argument as a hex address plan.
        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "retrolarium_disassembler"
            / "ghidra"
            / "scripts"
            / "SeedNesVectors.java"
        ).read_text(encoding="utf-8")
        self.assertIn("getScriptArgs()", source)
        self.assertIn("args.length > 1", source)
        self.assertIn("[0-9A-Fa-f]{1,4}", source)
        self.assertIn("Long.parseLong(line, 16)", source)
        self.assertIn("isExecutable(memory, target)", source)

    def test_script_error_is_fatal_even_when_ghidra_returns_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            result = subprocess.CompletedProcess([], 0, "ERROR REPORT SCRIPT ERROR: seed failed")

            with patch("retrolarium_disassembler.ghidra.run_launcher", return_value=result):
                with self.assertRaisesRegex(GhidraError, "script error"):
                    run_nes_analysis(image, workspace, ghidra_home, scripts)

            self.assertIn("REPORT SCRIPT ERROR", (workspace / "headless.log").read_text())

    def test_megadrive_uses_explicit_raw_68000_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            seed_plan = root / "seeds.txt"
            seed_plan.write_text("", encoding="ascii")

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {
                            "language": "68000:BE:32:default",
                            "compiler": "default",
                        }
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_megadrive_analysis(
                    image,
                    workspace,
                    ghidra_home,
                    scripts,
                    seed_plan=seed_plan,
                )

            command = run.call_args.args[0]
            self.assertEqual(
                ["-loader", "BinaryLoader"],
                command[command.index("-loader") : command.index("-loader") + 2],
            )
            self.assertEqual("68000:BE:32:default", command[command.index("-processor") + 1])
            self.assertEqual("ROM", command[command.index("-loader-blockName") + 1])
            self.assertEqual("0", command[command.index("-loader-baseAddr") + 1])
            self.assertEqual("SeedMegaDriveVectors.java", command[command.index("-preScript") + 1])
            facts_index = command.index("ExportInstructionFacts.java")
            self.assertEqual("ROM", command[facts_index + 2])
            restore_index = command.index("RestoreM68kPlannedSeeds.java")
            self.assertLess(restore_index, facts_index)
            self.assertEqual(str(seed_plan.resolve()), command[restore_index + 1])

    def test_megadrive_passes_python_seed_plan_to_decoder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"
            seed_plan = root / "seeds.txt"
            seed_plan.write_text("000B5A\n", encoding="ascii")
            return_plan = root / "normal-return-calls.txt"
            return_plan.write_text("000B54 000B5A\n", encoding="ascii")

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps(
                        {
                            "language": "68000:BE:32:default",
                            "compiler": "default",
                        }
                    ),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_megadrive_analysis(
                    image,
                    workspace,
                    ghidra_home,
                    scripts,
                    seed_plan=seed_plan,
                )

            command = run.call_args.args[0]
            script_index = command.index("SeedMegaDriveVectors.java")
            repair_index = command.index("RestoreM68kReturningCalls.java")
            repair_indices = [i for i, value in enumerate(command) if value == "RestoreM68kReturningCalls.java"]
            self.assertEqual(2, len(repair_indices))
            self.assertEqual("-preScript", command[repair_indices[0] - 1])
            self.assertEqual("-postScript", command[repair_indices[1] - 1])
            self.assertEqual(str(return_plan.resolve()), command[repair_indices[1] + 1])
            restore_index = command.index("RestoreM68kPlannedSeeds.java")
            self.assertGreater(repair_index, script_index)
            self.assertLess(repair_index, restore_index)
            self.assertLess(restore_index, command.index("ExportInstructionFacts.java"))
            self.assertEqual(str(seed_plan.resolve()), command[restore_index + 1])
            self.assertEqual(str(return_plan.resolve()), command[repair_index + 1])
            self.assertEqual(str(seed_plan.resolve()), command[script_index + 1])

    def test_z80_uses_independent_program_and_address_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            workspace = root / "analysis"

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps({"language": "z80:LE:16:default", "compiler": "default"}),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_z80_analysis(image, workspace, ghidra_home, scripts)

            command = run.call_args.args[0]
            self.assertEqual("z80:LE:16:default", command[command.index("-processor") + 1])
            self.assertEqual("Z80_RAM", command[command.index("-loader-blockName") + 1])
            self.assertEqual("SeedZ80Entry.java", command[command.index("-preScript") + 1])
            facts_index = command.index("ExportInstructionFacts.java")
            self.assertEqual("Z80_RAM", command[facts_index + 2])
            plan = root / "dispatch-seeds.txt"
            plan.write_text("T 0080 0088\nS 00A0\n", encoding="ascii")
            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_z80_analysis(image, workspace, ghidra_home, scripts, seed_plan=plan)
            command = run.call_args.args[0]
            self.assertEqual(
                str(plan.resolve()),
                command[command.index("SeedZ80Entry.java") + 1],
            )

    def test_snes_uses_pinned_24_bit_language_and_context_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)
            context = root / "context.tsv"
            context.write_text("009000\t009001\t1\t1\t1\n", encoding="utf-8")

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps({"language": "65816:LE:24:snes", "compiler": "default"}),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_snes_bank_analysis(
                    image,
                    root / "analysis",
                    ghidra_home,
                    scripts,
                    base_address=0x009000,
                    entry_address=0x009000,
                    context_plan=context,
                )

            command = run.call_args.args[0]
            self.assertEqual("65816:LE:24:snes", command[command.index("-processor") + 1])
            seed = command.index("SeedSnesBank.java")
            self.assertEqual("SNES_ROM", command[seed + 1])
            self.assertEqual("009000", command[seed + 2])
            self.assertEqual(str(context.resolve()), command[seed + 3])

    def test_spc700_uses_independent_program_and_address_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, ghidra_home, scripts = self.fake_layout(root)

            def complete(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                report = Path(command[command.index("InspectProgram.java") + 1])
                facts = Path(command[command.index("ExportInstructionFacts.java") + 1])
                report.write_text(
                    json.dumps({"language": "SPC700:LE:16:default", "compiler": "default"}),
                    encoding="utf-8",
                )
                facts.write_text("facts", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok")

            with patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=complete) as run:
                run_spc700_analysis(
                    image,
                    root / "analysis",
                    ghidra_home,
                    scripts,
                    base_address=0x0200,
                )

            command = run.call_args.args[0]
            self.assertEqual("SPC700:LE:16:default", command[command.index("-processor") + 1])
            self.assertEqual("SPC700_RAM", command[command.index("-loader-blockName") + 1])
            self.assertEqual("0x0200", command[command.index("-loader-baseAddr") + 1])
            self.assertEqual("SeedSpc700Entry.java", command[command.index("-preScript") + 1])
            facts_index = command.index("ExportInstructionFacts.java")
            self.assertEqual("SPC700_RAM", command[facts_index + 2])


class LauncherProcessTreeTests(unittest.TestCase):
    def test_launcher_receives_eof_without_inheriting_the_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_launcher(
                [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"], cwd=Path(directory), timeout=3
            )
            self.assertEqual(0, result.returncode)
            self.assertEqual("''", result.stdout.strip())

    def test_timeout_stops_children_that_hold_the_output_pipe(self) -> None:
        # A Python fixture runs on both hosts, without sh or sleep. On POSIX
        # its parent reaps the child after the group's SIGTERM; it never
        # terminates the child itself. This tests group termination without
        # depending on a container's PID 1 to reap orphaned zombies.
        started: list[subprocess.Popen] = []
        began: list[float] = []
        child_handle = None
        real_popen = subprocess.Popen
        kernel = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.WaitForSingleObject.restype = wintypes.DWORD
            kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel.TerminateProcess.restype = wintypes.BOOL
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle.restype = wintypes.BOOL

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / "child.json"
            launcher = root / "launcher with spaces.py"
            launcher.write_text(
                "import json, os, pathlib, signal, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "def stopped(*args):\n"
                "    child.wait(timeout=3)\n"
                "    raise SystemExit(0)\n"
                "signal.signal(signal.SIGTERM, stopped)\n"
                "ready = pathlib.Path(sys.argv[1])\n"
                "pending = ready.with_suffix('.tmp')\n"
                "pending.write_text(json.dumps({'parent': os.getpid(), 'child': child.pid}))\n"
                "pending.replace(ready)\n"
                "while True: time.sleep(60)\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(launcher), str(ready)]

            def popen(*args, **kwargs):
                nonlocal child_handle
                process = real_popen(*args, **kwargs)
                # Windows also starts taskkill; only track the launcher.
                if args[0] != command:
                    return process
                started.append(process)
                deadline = time.monotonic() + 10
                while not ready.is_file() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.is_file(), "launcher did not start its child")
                holder = json.loads(ready.read_text(encoding="utf-8"))
                self.assertEqual(process.pid, holder["parent"])
                if kernel is not None:
                    # Keep the exact child's process object, avoiding PID reuse.
                    child_handle = kernel.OpenProcess(0x100001, False, holder["child"])
                    self.assertTrue(child_handle, "cannot observe the fixture child")
                began.append(time.monotonic())
                return process

            try:
                with patch("retrolarium_disassembler.ghidra.subprocess.Popen", side_effect=popen):
                    with self.assertRaisesRegex(GhidraError, "did not finish"):
                        run_launcher(command, cwd=root, timeout=1)
                self.assertEqual(1, len(started))
                self.assertLess(time.monotonic() - began[0], 10)
                self.assertIsNotNone(started[0].poll(), "launcher outlived its timeout")
                if kernel is not None:
                    self.assertEqual(0, kernel.WaitForSingleObject(child_handle, 5000), "child outlived its launcher")
                else:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            os.killpg(started[0].pid, 0)
                        except ProcessLookupError:
                            break
                        if time.monotonic() > deadline:
                            self.fail("a process of the launcher's group outlived it")
                        time.sleep(0.05)
            finally:
                if kernel is not None and child_handle:
                    if kernel.WaitForSingleObject(child_handle, 0) == 258:
                        kernel.TerminateProcess(child_handle, 1)
                        kernel.WaitForSingleObject(child_handle, 5000)
                    kernel.CloseHandle(child_handle)
                elif kernel is None and started:
                    import signal

                    try:
                        os.killpg(started[0].pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for process in started:
                    if process.poll() is None:
                        if kernel is not None:
                            subprocess.run(
                                ["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True, timeout=5
                            )
                        process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
