"""Prepare additional, independently assembled Mega Drive reference sources.

Evaluation only: these sources and symbols must never seed ROM analysis.
Checkouts live in references; generated artifacts remain in ignored build/.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from prepare_sonic_references import export, run, sha256
from sonic_corpus_benchmark import normalise_reference_listing


PROFILES = {
    "altered-beast-ue-rev02": ("smd_alteredbeast", ".", "Altered Beast.asm", "Altered Beast"),
    "spinball-us": ("spindisasm", ".", "spinball.asm", "Sonic Spinball"),
    "mean-bean": ("mean-bean-machine-disassembly", ".", "main.asm", "Dr. Robotnik's Mean Bean Machine"),
    "shining-force-us": ("SF1DISASM", "disasm", "sf1.asm", "Shining Force"),
    "shining-force-2-us": ("SF2DISASM", "disasm", "sf2.asm", "Shining Force II"),
    "kid-chameleon-us": ("kid-chameleon-disasm", ".", "kid.asm", "Kid Chameleon"),
}


def assemble_sn(root: Path, source: Path, output: Path, assembler: Path,
                definitions: dict[str, str], *, at_locals: bool = False) -> None:
    files = [os.path.relpath(p, root).replace("\\", "/")
             for p in (source, output, output.with_suffix(".lst"))]
    defines = " ".join(f"/e {k}={v}" for k, v in definitions.items())
    options = "ae-,m+" if at_locals else "ae-,l.,m+"
    command = (f'"{assembler}" /k /p /o {options} {defines} '
               f'"{files[0]}","{files[1]}",,"{files[2]}"')
    output.unlink(missing_ok=True)
    log = output.with_suffix(".assembly.log")
    run(command, root, log)
    if not output.is_file() or "0 error(s)" not in log.read_text(errors="replace"):
        raise ValueError(f"assembler failed: {log}")


def prepare(name: str, refs: Path, dest: Path, rom_root: Path) -> dict:
    repo, subdir, entry, rom_dir = PROFILES[name]
    checkout = refs / repo
    root = checkout / subdir
    dest.mkdir(parents=True, exist_ok=True)
    record = dict(name=name, repository=repo, entry=entry,
                  scope="M68K instructions explicitly emitted in the reference listing; binary assets excluded",
                  commit=subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip(),
                  url=subprocess.check_output(["git", "-C", str(checkout), "remote", "get-url", "origin"], text=True).strip())
    try:
        definitions = {"VANILLA_BUILD": "1"} if repo == "SF2DISASM" else {}
        record["source_encoding"] = "latin-1" if repo == "kid-chameleon-disasm" else "utf-8-sig"
        if repo == "smd_alteredbeast":
            originals = [p for p in (rom_root / rom_dir).glob("*") if "(UE) (REV02) [!]" in p.name]
            if len(originals) != 1:
                raise ValueError("expected one Altered Beast UE REV02 original")
            run([str(checkout / "tools/splitrom/splitrom.exe"), str(originals[0]), "split.txt"], root, dest / "split.log")
            record["asset_preparation"] = "upstream split.txt; original compressed assets, no recompression"
            for driver in [root / "z80/sounddriver.asm", *sorted((root / "z80/pcm_driver").glob("*.asm"))]:
                run([str(root / "tools/sjasmplus/sjasmplus.exe"), f"--raw={driver.with_suffix('.bin')}", str(driver)],
                    root, dest / (driver.stem + ".assembly.log"))
            for palette in sorted((root / "includes/palettes").glob("*.asm")):
                if not palette.with_suffix(".bin").exists():
                    assemble_sn(root, palette, palette.with_suffix(".bin"), root / "tools/asm68k/asm68k.exe", {})
        if repo in {"SF1DISASM", "SF2DISASM"}:
            game = "sf1" if repo == "SF1DISASM" else "sf2"
            originals = [p for p in (rom_root / rom_dir).glob("*") if "(U) [!]" in p.name]
            if len(originals) != 1:
                raise ValueError(f"expected one US original in {rom_root / rom_dir}")
            run([str(checkout / "tools/splitrom.exe"), str(originals[0]),
                 str(checkout / f"split/{game}splits.txt")], root, dest / "split.log")
            if game == "sf1":
                sound = [(root / "data/sound", root / "sounddriver.asm", root / "data/sound/sounddriver.bin", "$0000-$1fff"),
                         (root / "data/sound/musicbank0", root / "data/sound/musicbank0/musicbank0.asm", root / "data/sound/musicbank0.bin", "$8000-$dfff"),
                         (root / "data/sound/musicbank1", root / "data/sound/musicbank1/musicbank1.asm", root / "data/sound/musicbank1.bin", "$8ae0-$ffff")]
            else:
                sound = [(root / "code/common/tech/sound", root / "code/common/tech/sound/sounddriver.asm", root / "data/sound/sounddriver.bin", "$0000-$1fff"),
                         (root / "data/sound/musicbank0", root / "data/sound/musicbank0/musicbank0.asm", root / "data/sound/musicbank0.bin", "$8000-$ffff"),
                         (root / "data/sound/musicbank1", root / "data/sound/musicbank1/musicbank1.asm", root / "data/sound/musicbank1.bin", "$8000-$ffff")]
            for cwd, source, target, limits in sound:
                obj = dest / (target.stem + ".p")
                run([str(checkout / "tools/asw/asw.exe"), "-o", str(obj), str(source)], cwd, dest / (target.stem + ".assembly.log"))
                run([str(checkout / "tools/asw/p2bin.exe"), str(obj), str(target), "-r", limits], cwd, dest / (target.stem + ".conversion.log"))
        if repo == "kid-chameleon-disasm":
            run([sys.executable, "split.py"], root, dest / "split.log")
        record.update(export(root, entry, dest / "main.s", definitions,
                             encoding=record["source_encoding"]))
        for source, output in [(root / entry, dest / "upstream.bin"), (dest / "main.s", dest / "reference.bin")]:
            if repo == "kid-chameleon-disasm":
                obj = output.with_suffix(".p")
                os.environ["AS_MSGPATH"] = str(root / "build/win/msg")
                run([str(root / "build/win/asw.exe"), "-xx", "-c", "-L", "-A", "-o", str(obj), str(source)], root, output.with_suffix(".assembly.log"))
                run([str(root / "build/win/s2p2bin.exe"), str(obj), str(output), str(source.with_suffix(".h"))], root, output.with_suffix(".conversion.log"))
                shutil.copy2(source.with_suffix(".lst"), output.with_suffix(".lst"))
            else:
                assembler = (checkout / "tools/asm68k.exe" if repo.startswith("SF") else
                             checkout / "tools/asm68k/asm68k.exe" if repo == "smd_alteredbeast" else
                             checkout / "asm68k.exe" if repo == "mean-bean-machine-disassembly" else refs / "chaotix/bin/asm68k.exe")
                assemble_sn(root, source, output, assembler, definitions if source == root / entry else {},
                            at_locals=repo.startswith("SF"))
                if repo.startswith("SF") or repo == "mean-bean-machine-disassembly":
                    fixer = checkout / ("tools/fixheader.exe" if repo.startswith("SF") else "fixheadr.exe")
                    run([str(fixer), str(output)], root, output.with_suffix(".header.log"))
        binary = dest / "reference.bin"
        digest = sha256(binary)
        if digest != sha256(dest / "upstream.bin"):
            raise ValueError("flattened and upstream builds differ")
        candidates = [p for p in (rom_root / rom_dir).glob("*") if p.is_file() and p.suffix.lower() in {".gen", ".bin", ".md"}]
        matches = [str(p) for p in candidates if sha256(p) == digest]
        record.update(binary=str(binary), binary_sha256=digest, binary_bytes=binary.stat().st_size,
                      matches_upstream=True, matching_original_roms=matches,
                      status="verified-original" if matches else "upstream-only")
        if repo == "kid-chameleon-disasm":
            record["matches_repository_rom"] = digest == sha256(root / "kid.bin")
        tool_paths = ([root / "build/win/asw.exe", root / "build/win/s2p2bin.exe"]
                      if repo == "kid-chameleon-disasm" else [assembler])
        record["toolchain"] = [{"path": str(p), "sha256": sha256(p)} for p in tool_paths]
        known, uncertain, provenance = normalise_reference_listing(
            dest / "reference.lst", binary.read_bytes(), dest / "reference-m68k.lst",
            sn=repo != "kid-chameleon-disasm")
        if not known:
            raise ValueError("reference listing contains no recognized M68K instructions")
        record.update(reference_instructions=len(known), uncertain_instruction_addresses=len(uncertain),
                      listing=str(dest / "reference-m68k.lst"),
                      listing_sha256=sha256(dest / "reference-m68k.lst"),
                      listing_provenance=provenance)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        record.update(status="blocked", error=str(exc))
    (dest / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--references", type=Path, default=Path("references"))
    parser.add_argument("--roms", type=Path, default=Path("D:/Games/My Genesis Games"))
    parser.add_argument("--output", type=Path, default=Path("build/extra-references"))
    parser.add_argument("--only", choices=PROFILES, action="append")
    args = parser.parse_args()
    records = []
    for name in args.only or PROFILES:
        result = prepare(name, args.references.resolve(), (args.output / name).resolve(), args.roms.resolve())
        records.append(result)
        print(name, result["status"], result.get("error", ""), flush=True)
    all_records = [json.loads(p.read_text(encoding="utf-8"))
                   for p in sorted(args.output.glob("*/result.json"))]
    (args.output / "manifest.json").write_text(json.dumps({"units": all_records}, indent=2) + "\n", encoding="utf-8")
    return int(any(r["status"] == "blocked" for r in records))


if __name__ == "__main__":
    raise SystemExit(main())
