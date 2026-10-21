"""Command-line interface for Retrolarium Disassembler.

Each command imports what it runs, so `rldisasm --help` and a short command do
not pay for loading every analysis pass.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from retrolarium_disassembler import __version__


def _default_tool_root() -> Path:
    """.tools in a source checkout; installed, a folder of the user's (the
    package's own folder may not be writable and goes with a reinstall)."""
    checkout = Path(__file__).resolve().parents[2]
    if (checkout / "pyproject.toml").is_file():
        return checkout / ".tools"
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Retrolarium" / "disassembler"
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / "retrolarium" / "disassembler"


DEFAULT_TOOL_ROOT = _default_tool_root()


def print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


class OutputError(RuntimeError):
    """The output folder would lose something: the input ROM, or edits."""


# Sources a person may have edited in a generated project (assembler output
# and builds are the tools' own).
_SOURCE_SUFFIXES = {".asm", ".s", ".inc", ".cfg", ".68k", ".z80"}


def guard_output(rom: Path, output: Path, replace: bool) -> None:
    """Refuse a run that would write over its own input ROM, or over sources
    of an earlier run edited since (--replace overwrites them)."""
    rom = rom.resolve()
    output = output.resolve()
    if rom.is_relative_to(output) and rom.parent != output:
        raise OutputError(f"the ROM lies inside the output folder ({rom}): choose another output folder")
    generated = output / "generated"
    marks = [path for path in (output / "retrolarium-project.json", output / "manifest.json") if path.is_file()]
    if replace or not generated.is_dir() or not marks:
        return
    written = max(path.stat().st_mtime for path in marks)
    edited = sorted(
        path for path in generated.rglob("*")
        if path.is_file() and path.suffix.lower() in _SOURCE_SUFFIXES
        and "build" not in path.relative_to(generated).parts
        and path.stat().st_mtime > written + 1
    )
    if edited:
        raise OutputError(f"{len(edited)} source file(s) in {generated} changed since the last run "
                          f"(first: {edited[0].relative_to(generated).as_posix()}); --replace overwrites them")


def ghidra_home(args: argparse.Namespace) -> Path:
    home = args.ghidra_home or os.environ.get("RETROLARIUM_GHIDRA_HOME")
    return Path(home) if home else DEFAULT_TOOL_ROOT / "ghidra"


# ---------------------------------------------------------------- NES

def command_nes_inspect(args: argparse.Namespace) -> None:
    from retrolarium_core.ines import load_ines
    from retrolarium_disassembler.nes.pipeline import image_manifest

    print_json(image_manifest(load_ines(args.rom)))


def command_nes_analyze(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.nes.pipeline import analyze_mapper_banks

    print_json(analyze_mapper_banks(args.rom, args.output, ghidra_home(args)))


def command_nes_disassemble(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.nes.pipeline import disassemble_nes

    guard_output(args.rom, args.output, args.replace)
    print_json(disassemble_nes(args.rom, args.output, ghidra_home(args),
                               build_container=args.build_container))


# ---------------------------------------------------------------- Mega Drive

def command_megadrive_inspect(args: argparse.Namespace) -> None:
    from retrolarium_core.megadrive import image_manifest, load_megadrive

    print_json(image_manifest(load_megadrive(args.rom)))


def command_megadrive_analyze(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.megadrive.pipeline import analyze_m68k

    print_json(analyze_m68k(args.rom, args.output, ghidra_home(args)))


def command_megadrive_disassemble(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.megadrive.pipeline import disassemble_megadrive

    guard_output(args.rom, args.output, args.replace)
    print_json(disassemble_megadrive(args.rom, args.output, ghidra_home(args),
                                     build_container=args.build_container))


def command_megadrive_emit(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.megadrive.pipeline import emit_analyzed_megadrive

    guard_output(args.rom, args.output, args.replace)
    print_json(emit_analyzed_megadrive(args.rom, args.output))


# ---------------------------------------------------------------- SNES

def command_snes_inspect(args: argparse.Namespace) -> None:
    from retrolarium_core.snes import image_manifest, load_snes

    print_json(image_manifest(load_snes(args.rom)))


def command_snes_analyze(args: argparse.Namespace) -> None:
    from retrolarium_core.snes import load_snes
    from retrolarium_disassembler.snes.analysis import analysis_manifest, analyze_snes
    from retrolarium_disassembler.snes.pointers import (
        accepted_pointer_tables,
        detect_pointer_candidates,
        write_pointer_report,
    )
    from retrolarium_disassembler.snes.symbols import generate_symbols, write_symbol_report

    image = load_snes(args.rom)
    analysis = analyze_snes(image)
    document = analysis_manifest(analysis)
    pointers = detect_pointer_candidates(image, analysis)
    symbols = generate_symbols(image, analysis, pointers)
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / "state-analysis.json"
    destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_pointer_report(args.output / "pointers.json", image, pointers)
    write_symbol_report(args.output / "symbols.json", image, symbols)
    print_json(
        {
            "schema": document["schema"],
            "schema_version": document["schema_version"],
            "path": str(destination.resolve()),
            "instruction_count": len(document["instructions"]),
            "diagnostic_count": len(document["diagnostics"]),
            "accepted_pointer_tables": len(accepted_pointer_tables(pointers)),
            "symbol_count": len(symbols),
        }
    )


def command_snes_disassemble(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.snes.pipeline import disassemble_snes

    guard_output(args.rom, args.output, args.replace)
    print_json(disassemble_snes(args.rom, args.output, ghidra_home=ghidra_home(args),
                                build_container=args.build_container))


# ---------------------------------------------------------------- shared

def command_verify(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.verify import verify_exact

    print_json(verify_exact(args.original, args.rebuilt))


def command_ghidra_status(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.toolchain import toolchain_status

    print_json(toolchain_status(ghidra_home(args)))


def command_ghidra_install(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.toolchain import install_toolchain

    print_json(install_toolchain(args.tool_root))


def command_benchmark_pointers(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.benchmark import score_pointer_report, write_benchmark

    result = score_pointer_report(args.report, args.oracle)
    if args.output is not None:
        write_benchmark(args.output, result)
    print_json(result)


def command_preset(args: argparse.Namespace) -> None:
    from retrolarium_disassembler.preset import create_game_studio_preset

    print_json(
        create_game_studio_preset(
            args.rom,
            args.output,
            ghidra_home=ghidra_home(args),
            build=not args.no_build,
            build_container=args.build_container,
            toolchain_cache=args.toolchain_cache,
            legacy_castle_excellent_levels=args.legacy_castle_excellent_levels,
            repository=args.repository,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="rldisasm", description=__doc__.split("\n", 1)[0])
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    nes = commands.add_parser("nes", help="NES container and disassembly commands")
    nes_commands = nes.add_subparsers(dest="nes_command", required=True)
    inspect = nes_commands.add_parser("inspect", help="inspect an iNES image")
    inspect.add_argument("rom", type=Path)
    inspect.set_defaults(handler=command_nes_inspect)
    analyze = nes_commands.add_parser(
        "analyze", help="analyze every profiled PRG bank into neutral facts"
    )
    analyze.add_argument("rom", type=Path)
    analyze.add_argument("--output", type=Path, required=True)
    analyze.add_argument("--ghidra-home", type=Path)
    analyze.set_defaults(handler=command_nes_analyze)
    disassemble = nes_commands.add_parser(
        "disassemble", help="analyze profiled NES banks and emit a complete ca65 project"
    )
    disassemble.add_argument("rom", type=Path)
    disassemble.add_argument("--output", type=Path, required=True)
    disassemble.add_argument("--replace", action="store_true", help="overwrite sources edited since the last run")
    disassemble.add_argument("--ghidra-home", type=Path)
    disassemble.add_argument(
        "--build-container",
        help="Docker image containing make, ca65 and ld65; also verifies exact output",
    )
    disassemble.set_defaults(handler=command_nes_disassemble)

    megadrive = commands.add_parser(
        "megadrive", help="Mega Drive cartridge and disassembly commands"
    )
    megadrive_commands = megadrive.add_subparsers(
        dest="megadrive_command", required=True
    )
    megadrive_inspect = megadrive_commands.add_parser(
        "inspect", help="inspect a Mega Drive cartridge image"
    )
    megadrive_inspect.add_argument("rom", type=Path)
    megadrive_inspect.set_defaults(handler=command_megadrive_inspect)
    megadrive_analyze = megadrive_commands.add_parser(
        "analyze", help="analyze cartridge 68000 code into neutral facts"
    )
    megadrive_analyze.add_argument("rom", type=Path)
    megadrive_analyze.add_argument("--output", type=Path, required=True)
    megadrive_analyze.add_argument("--ghidra-home", type=Path)
    megadrive_analyze.set_defaults(handler=command_megadrive_analyze)
    megadrive_disassemble = megadrive_commands.add_parser(
        "disassemble", help="emit a complete exact-first AS (asl) project"
    )
    megadrive_disassemble.add_argument("rom", type=Path)
    megadrive_disassemble.add_argument("--output", type=Path, required=True)
    megadrive_disassemble.add_argument("--replace", action="store_true", help="overwrite sources edited since the last run")
    megadrive_disassemble.add_argument("--ghidra-home", type=Path)
    megadrive_disassemble.add_argument("--build-container")
    megadrive_disassemble.set_defaults(handler=command_megadrive_disassemble)
    megadrive_emit = megadrive_commands.add_parser(
        "emit", help="regenerate sources from verified cached analysis artifacts"
    )
    megadrive_emit.add_argument("rom", type=Path)
    megadrive_emit.add_argument("--output", type=Path, required=True)
    megadrive_emit.add_argument("--replace", action="store_true", help="overwrite sources edited since the last run")
    megadrive_emit.set_defaults(handler=command_megadrive_emit)

    snes = commands.add_parser("snes", help="SNES cartridge commands")
    snes_commands = snes.add_subparsers(dest="snes_command", required=True)
    snes_inspect = snes_commands.add_parser(
        "inspect", help="inspect a plain LoROM or HiROM cartridge image"
    )
    snes_inspect.add_argument("rom", type=Path)
    snes_inspect.set_defaults(handler=command_snes_inspect)
    snes_analyze = snes_commands.add_parser(
        "analyze", help="run independent bank-aware W65C816 state analysis"
    )
    snes_analyze.add_argument("rom", type=Path)
    snes_analyze.add_argument("--output", type=Path, required=True)
    snes_analyze.set_defaults(handler=command_snes_analyze)
    snes_disassemble = snes_commands.add_parser(
        "disassemble", help="emit a modular exact-first ca65 SNES project"
    )
    snes_disassemble.add_argument("rom", type=Path)
    snes_disassemble.add_argument("--output", type=Path, required=True)
    snes_disassemble.add_argument("--replace", action="store_true", help="overwrite sources edited since the last run")
    snes_disassemble.add_argument("--ghidra-home", type=Path)
    snes_disassemble.add_argument("--build-container")
    snes_disassemble.set_defaults(handler=command_snes_disassemble)

    verify = commands.add_parser("verify", help="compare two images byte for byte")
    verify.add_argument("original", type=Path)
    verify.add_argument("rebuilt", type=Path)
    verify.set_defaults(handler=command_verify)

    ghidra = commands.add_parser("ghidra", help="install and inspect the external Ghidra backend")
    ghidra_commands = ghidra.add_subparsers(dest="ghidra_command", required=True)
    install = ghidra_commands.add_parser("install")
    install.add_argument("--tool-root", type=Path, default=DEFAULT_TOOL_ROOT)
    install.set_defaults(handler=command_ghidra_install)
    status = ghidra_commands.add_parser("status")
    status.add_argument("--ghidra-home", type=Path, help="default: RETROLARIUM_GHIDRA_HOME, else the tool root's")
    status.set_defaults(handler=command_ghidra_status)

    benchmark = commands.add_parser(
        "benchmark", help="score blind analysis artifacts against an isolated oracle"
    )
    benchmark_commands = benchmark.add_subparsers(
        dest="benchmark_command", required=True
    )
    pointers = benchmark_commands.add_parser(
        "pointers", help="score accepted pointer tables"
    )
    pointers.add_argument("report", type=Path)
    pointers.add_argument("oracle", type=Path)
    pointers.add_argument("--output", type=Path)
    pointers.set_defaults(handler=command_benchmark_pointers)

    preset = commands.add_parser(
        "preset",
        help="disassemble a Castle Excellent, SMB1, Pac-Man, Solomon's Key or Doraemon ROM "
             "into a Studio project (needs Retrolarium Kit)",
    )
    preset.add_argument("rom", type=Path)
    preset.add_argument("--output", type=Path, required=True)
    preset.add_argument("--ghidra-home", type=Path)
    preset.add_argument("--build-container")
    preset.add_argument("--toolchain-cache", type=Path)
    preset.add_argument("--legacy-castle-excellent-levels", type=Path,
                        help="import a validated legacy Castle Excellent levels JSON")
    preset.add_argument("--repository", type=Path,
                        help="the game's repository, whose profile recognizes the ROM "
                             "(default: the one the ROM lies in)")
    preset.add_argument(
        "--no-build", action="store_true",
        help="create and validate the workspace without building its first artifact",
    )
    preset.set_defaults(handler=command_preset)
    return root


def _expected_errors() -> tuple[type[BaseException], ...]:
    # The error types of everything a command may have loaded; a module that
    # was never imported cannot have raised.
    names = {
        "retrolarium_core.contracts": "ContractError",
        "retrolarium_core.ines": "InesError",
        "retrolarium_core.megadrive": "MegaDriveError",
        "retrolarium_core.snes": "SnesError",
        "retrolarium_disassembler": "AnalysisError",
        "retrolarium_disassembler.cli": "OutputError",
        "retrolarium_disassembler.benchmark": "BenchmarkError",
        "retrolarium_disassembler.facts": "FactError",
        "retrolarium_disassembler.ghidra": "GhidraError",
        "retrolarium_disassembler.toolchain": "ToolchainError",
        "retrolarium_disassembler.nes.ca65": "EmitError",
        "retrolarium_disassembler.nes.pipeline": "PipelineError",
        "retrolarium_disassembler.megadrive.emit": "MegaDriveEmitError",
        "retrolarium_disassembler.snes.analysis": "SnesAnalysisError",
        "retrolarium_disassembler.snes.emit": "SnesEmitError",
        "retrolarium_disassembler.snes.pipeline": "SnesPipelineError",
        "retrolarium_disassembler.verify": "VerificationError",
        "retrolarium_kit.studio.project": "StudioProjectError",
        "retrolarium_kit.core.authoring": "AuthoringError",
    }
    errors: list[type[BaseException]] = [OSError]
    for module, name in names.items():
        loaded = sys.modules.get(module)
        error = getattr(loaded, name, None) if loaded is not None else None
        if isinstance(error, type):
            errors.append(error)
    return tuple(errors)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        args.handler(args)
    except Exception as exc:
        if not isinstance(exc, _expected_errors()):
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
