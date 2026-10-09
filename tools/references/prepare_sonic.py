"""Export Sonic Retro assembly units and optionally prove their binary identity.

Evaluation tooling only. Nothing in this module is input to ROM analysis.
The upstream checkouts supply binary assets, macros and native build tools.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from tools.references.flatten_asm_source import flatten_source


REPOSITORIES = ("s1disasm", "s2disasm", "skdisasm", "chaotix", "scddisasm")
AS_PROFILES = (
    ("sonic1-rev01", "s1disasm", "sonic.asm", "build.lua", "s1built.bin", "",
     ["-p=FF", "-z=0,kosinski,Size_of_DAC_driver_guess,after"]),
    ("sonic2-rev01", "s2disasm", "s2.asm", "build.lua", "s2built.bin", "",
     ["-p=0", "-z=0,saxman-bugged,Size_of_Snd_driver_guess,after"]),
    ("sonic3-usa", "skdisasm", "s3.asm", "buildS3.lua", "s3built.bin", "",
     ["-p=FF", "-z=0,uncompressed,Size_of_Snd_driver_guess,before",
      "-z=1300,uncompressed,Size_of_Snd_driver2_guess,before"]),
    ("sonic-knuckles", "skdisasm", "sonic3k.asm", "buildSK.lua", "skbuilt.bin",
     "Sonic3_Complete=0",
     ["-p=FF", "-z=0,kosinski,Size_of_Snd_driver_guess,before",
      "-z=1300,kosinski,Size_of_Snd_driver2_guess,before"]),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str] | str, cwd: Path, log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as stream:
        result = subprocess.run(command, cwd=cwd, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=180)
    if result.returncode:
        raise RuntimeError(f"build failed ({result.returncode}): {log}")


def export(root: Path, entry: str, output: Path, definitions: dict[str, str],
           *, encoding: str = "utf-8-sig") -> dict:
    text, origins = flatten_source(root, entry, expand_include_macros=True, encoding=encoding)
    prefix = "".join(f"{key} equ {value}\n" for key, value in definitions.items())
    for origin in origins:
        origin["start_line"] += len(definitions)
        origin["end_line"] += len(definitions)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prefix + text, encoding="utf-8", newline="\n")
    output.with_suffix(".source-map.json").write_text(
        json.dumps(origins, indent=2) + "\n", encoding="utf-8",
    )
    # A file with remaining text includes is not a unified reference.
    remaining = re.findall(r"^\s*(?:\S+:\s*)?include\s+.*$", text, re.I | re.M)
    if remaining:
        raise ValueError(f"unexpanded text includes: {remaining[:3]}")
    return {"source": str(output), "source_sha256": sha256(output),
            "lines": len((prefix + text).splitlines()), "include_occurrences": len(origins),
            "unique_source_files": len({item["path"] for item in origins}),
            "asset_root": str(root), "entry": entry, "defines": definitions}


def build_as(root: Path, source: Path, output: Path, tools: Path,
             conversion: list[str] = (), header: bool = False) -> Path:
    obj = output.with_suffix(".p")
    obj.unlink(missing_ok=True)
    command = [str(tools / "asw.exe"), "-xx", "-n", "-q", "-A", "-L", "-U",
               "-i", ".", "-o", str(obj), "-olist", str(output.with_suffix(".lst"))]
    if header:
        command.append("-c")
    run(command + [str(source)], root, output.with_suffix(".assembly.log"))
    if not obj.is_file():
        raise RuntimeError(f"assembler produced no object: {source}")
    command = [str(tools / "p2bin.exe"), *conversion, str(obj), str(output)]
    if header:
        command.append(str(source.with_suffix(".h")))
    run(command, root, output.with_suffix(".conversion.log"))
    return output


def build_sn(root: Path, source: Path, output: Path, tools: Path,
             sh2: bool = False) -> Path:
    output.unlink(missing_ok=True)
    # SN parses the Windows command line itself, not the CRT argv convention.
    # A list would backslash-escape its comma-delimited filename quotes.
    executable = tools / ("asmsh.exe" if sh2 else "asm68k.exe")
    options = "psh2,#+,l.,m+" if sh2 else "ae-,l.,ow+,m+"
    # These legacy tools also have short filename buffers. Keep paths relative.
    filenames = [os.path.relpath(path, root).replace("\\", "/")
                 for path in (source, output, output.with_suffix(".lst"))]
    run(f'"{executable}" /p /o {options} "{filenames[0]}","{filenames[1]}",,"{filenames[2]}"',
        root, output.with_suffix(".assembly.log"))
    # Some old SN executables return zero even after assembly errors.
    log = output.with_suffix(".assembly.log").read_text(encoding="utf-8", errors="replace")
    if not output.is_file() or not re.search(r"\b0 error\(s\)", log):
        raise RuntimeError(f"SN assembler failed: {output.with_suffix('.assembly.log')}")
    return output


def fix_genesis_header(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[0x1A4:0x1A8] = (len(data) - 1).to_bytes(4, "big")
    checksum = sum(int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0x200, len(data), 2)) & 0xFFFF
    data[0x18E:0x190] = checksum.to_bytes(2, "big")
    path.write_bytes(data)


def patch_sonic2_driver_size(path: Path, header: Path) -> None:
    text = header.read_text(encoding="utf-8")
    symbols = {}
    for name in ("comp_z80_size", "movewZ80CompSize"):
        match = re.search(rf"\b{name}\b[^\r\n]*?(0x[0-9A-Fa-f]+)", text)
        if not match:
            raise ValueError(f"missing Sonic 2 postprocessing symbol: {name}")
        symbols[name] = int(match[1], 16)
    data = bytearray(path.read_bytes())
    start = symbols["movewZ80CompSize"] + 2
    data[start:start + 2] = symbols["comp_z80_size"].to_bytes(2, "big")
    path.write_bytes(data)


def proof(record: dict, binary: Path, upstream: Path, roms: dict[str, list[str]]) -> None:
    digest = sha256(binary)
    record.update(binary=str(binary), binary_bytes=binary.stat().st_size,
                  binary_sha256=digest, upstream_binary_sha256=sha256(upstream),
                  matches_upstream=digest == sha256(upstream),
                  matching_original_roms=roms.get(digest, []))
    if not record["matches_upstream"]:
        raise ValueError(f"flattening changed assembled bytes: {binary}")


def cd_units(root: Path) -> list[dict]:
    """Read explicit compilation units from the checked-out native build file."""
    pattern = re.compile(r'^%ASM68K%\s+(.*?)"([^"]+\.asm)",\s*"([^"]+)"', re.I)
    result = []
    for line in (root / "make.bat").read_text(encoding="utf-8-sig").splitlines():
        match = pattern.match(line)
        if match:
            result.append({"entry": match[2].replace("\\", "/"),
                           "defines": dict(re.findall(r"/e\s+(\w+)=(\w+)", match[1])),
                           "target": match[3].replace("\\", "/")})
    if not result:
        raise ValueError("Sonic CD make.bat contains no recognised assembly units")
    return result


def prepare(args: argparse.Namespace) -> dict:
    refs, out = args.references.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    roms: dict[str, list[str]] = {}
    if args.rom_dir:
        for path in args.rom_dir.rglob("*"):
            if (path.is_file() and ("sonic" in path.name.lower() or "chaotix" in path.name.lower())
                    and path.suffix.lower() in {".gen", ".bin", ".md", ".32x"}):
                roms.setdefault(sha256(path), []).append(str(path.resolve()))
    report = {"purpose": "evaluation only; never seed ROM analysis with these references",
              "repositories": {}, "units": [], "limitations": [
                  "Sonic3_Complete=1 changes layout; compare retail S&K and Sonic 3 separately.",
                  "Chaotix contains opaque SH-2 program bytes; only its PWM driver has buildable SH-2 source.",
                  "Chaotix requires 32X bank/address mappings before instruction benchmarking.",
                  "Sonic CD uses independent main/sub CPU overlays. Addresses are scoped to a disc file and CPU.",
                  "Sonic CD original region folders lack the remaining retail disc files; no complete ISO proof.",
                  "Binary assets remain in the checkouts. A unified text source is not a standalone asset bundle.",
              ]}
    report["chaotix_address_mapping"] = {
        "fixed_rom": {"logical_start": "0x880000", "physical_start": "0x0", "size": "0x80000"},
        "selected_bank": {"logical_start": "0x900000", "physical_start": "0x200000", "size": "0x100000"},
        "other_domains": "ROM includes relocated RAM code and SH-2 addresses; these need separate mappings.",
    }
    for repo in REPOSITORIES:
        revision = subprocess.check_output(["git", "-C", str(refs / repo), "rev-parse", "HEAD"], text=True).strip()
        report["repositories"][repo] = {"url": f"https://github.com/sonicretro/{repo}", "commit": revision}

    for name, repo, entry, build, built, define, conversion in AS_PROFILES:
        print(f"Preparing {name}...", flush=True)
        root, dest = refs / repo, out / name
        dest.mkdir(parents=True, exist_ok=True)
        if args.verify:
            run([str(root / "build_tools/lua/lua.exe"), build], root, dest / "upstream.log")
        record = export(root, entry, dest / "main.s", dict([define.split("=", 1)]) if define else {})
        record.update(name=name, repository=repo, cpu="m68000+z80", address_space="cartridge")
        report["units"].append(record)
        if args.verify:
            binary = build_as(root, dest / "main.s", dest / "reference.bin",
                              root / "build_tools/Windows-x86", conversion, repo == "s2disasm")
            if repo == "s2disasm":
                patch_sonic2_driver_size(binary, dest / "main.h")
            fix_genesis_header(binary)
            proof(record, binary, root / built, roms)

    root, dest = refs / "chaotix/src", out / "chaotix"
    tools = refs / "chaotix/bin"
    (root.parent / "out").mkdir(exist_ok=True)
    for name, entry, cpu, target, kind in (
        ("pwm", "mars/pwm_driver.asm", "sh2", "pwm_driver.bin", "sh2"),
        ("z80", "sound/z80/driver.asm", "z80", "z80_driver.bin", "as"),
        ("main", "main.asm", "m68000", "chaotix.32x", "sn"),
    ):
        print(f"Preparing chaotix/{name}...", flush=True)
        unit = dest / name
        source = unit / ("main.asm" if cpu == "z80" else "main.s")
        record = export(root, entry, source, {})
        record.update(name=f"chaotix-{name}", repository="chaotix", cpu=cpu,
                      address_space="32x-banked" if cpu == "m68000" else cpu)
        report["units"].append(record)
        if args.verify:
            upstream = root.parent / "out" / target
            builder = build_as if kind == "as" else build_sn
            options = {"sh2": True} if kind == "sh2" else {}
            builder(root, root / entry, upstream, tools, **options)
            binary = builder(root, source, unit / target, tools, **options)
            proof(record, binary, upstream, roms)

    root, tools = refs / "scddisasm/src", refs / "scddisasm/bin"
    # Generated labels must exist before flattening the units that consume them.
    # Their source generators are independent compilation units, not ROM hints.
    if args.verify:
        for entry, labels in (("DA Garden/Track Titles.asm", "DA Garden/Track Title Labels.inc"),
                              ("Special Stage/Stage Data.asm", "Special Stage/Stage Data Labels.inc")):
            target = out / "sonic-cd" / ("titles" if "Garden" in entry else "stages")
            target.mkdir(parents=True, exist_ok=True)
            binary = os.path.relpath(target / "data.bin", root).replace("\\", "/")
            symbols = os.path.relpath(target / "data.sym", root).replace("\\", "/")
            run(f'"{tools / "asm68k.exe"}" /p /o ae-,l.,ow+ /e REGION={args.cd_region} '
                f'"{entry}","{binary}","{symbols}"', root, target / "upstream.log")
            run([str(tools / "dumpasmsym.exe"), "-m", "asm", str(target / "data.sym"), "-o", str(root / labels)],
                root, target / "labels.log")
            if "Special Stage" in entry:
                shutil.copyfile(target / "data.bin", root / "Special Stage/Stage Data.bin")
        fm = root.parent / "out/misc/fm_driver.bin"
        fm.parent.mkdir(parents=True, exist_ok=True)
        build_as(root, root / "Sound Drivers/FM/_Driver.asm", fm, tools)

    units = [{"entry": "Sound Drivers/FM/_Driver.asm", "defines": {},
              "target": "../out/misc/fm_driver.bin", "cpu": "z80"}, *cd_units(root.parent)]
    for index, unit in enumerate(units):
        name = Path(unit["target"]).stem.lower()
        dest = out / "sonic-cd" / f"{index:02d}-{name}"
        cpu = unit.get("cpu", "m68000")
        definitions = {"REGION": str(args.cd_region), **unit["defines"]}
        print(f"Preparing sonic-cd/{name}...", flush=True)
        source = dest / ("main.asm" if cpu == "z80" else "main.s")
        record = {"name": f"sonic-cd-{name}", "repository": "scddisasm", "entry": unit["entry"]}
        try:
            record = export(root, unit["entry"], source, definitions)
            entry_text = (root / unit["entry"]).read_text(encoding="utf-8-sig")
            role = ("z80" if cpu == "z80" else "sub-cpu" if "_Include/Sub CPU.inc" in entry_text
                    else "main-cpu" if "_Include/Main CPU.inc" in entry_text else "data")
            record.update(name=f"sonic-cd-{name}", repository="scddisasm", cpu=cpu,
                          cpu_role=role, address_space=f"disc-file:{unit['target']}")
            if args.verify:
                # Assemble a wrapper of the split source under the exact same defines.
                wrapper = dest / "upstream.s"
                wrapper.write_text("".join(f"{k} equ {v}\n" for k, v in definitions.items()) +
                                   f' include "{unit["entry"]}"\n', encoding="utf-8")
                builder = build_as if cpu == "z80" else build_sn
                upstream = builder(root, wrapper, dest / "upstream.bin", tools)
                binary = builder(root, source, dest / "reference.bin", tools)
                proof(record, binary, upstream, roms)
                record["matching_bundled_originals"] = [
                    str(path.relative_to(refs / "scddisasm"))
                    for path in (refs / "scddisasm/original").glob("*.bin") if sha256(path) == sha256(binary)
                ]
        except (ValueError, RuntimeError) as error:
            record.update(error=str(error), source=str(source) if source.is_file() else None)
        report["units"].append(record)
    record = export(root, "Main.asm", out / "sonic-cd/disc-container/main.s", {"REGION": str(args.cd_region)})
    record.update(name="sonic-cd-disc-container", repository="scddisasm", cpu="data",
                  address_space="iso", build_status="requires remaining original disc files and filesystem generation")
    report["units"].append(record)
    return report


def write_index(report: dict, output: Path) -> None:
    rows = ["# Sonic Retro reference sources", "",
            "These sources are for evaluation. Binary assets remain in `references`.", "",
            "See `manifest.json` for commits, build profiles, hashes and address domains.", "",
            "| Unit | Unified source | Lines | Verification |", "| --- | --- | ---: | --- |"]
    for unit in report["units"]:
        source = unit.get("source")
        link = f"[source]({Path(source).relative_to(output).as_posix()})" if source else "—"
        status = ("ERROR: " + unit["error"] if "error" in unit else
                  "Exact retail ROM" if unit.get("matching_original_roms") else
                  "Exact bundled original" if unit.get("matching_bundled_originals") else
                  "Same bytes as upstream build" if unit.get("matches_upstream") else
                  unit.get("build_status", "Text exported; build not verified"))
        rows.append(f"| {unit['name']} | {link} | {unit.get('lines', '—')} | {status} |")
    rows.extend(["", "## Limits", "", *[f"- {item}" for item in report["limitations"]], ""])
    (output / "INDEX.md").write_text("\n".join(rows), encoding="utf-8")


def write_lock(report: dict, output: Path, path: Path) -> None:
    """Store portable provenance without vendoring third-party source or ROMs."""
    fields = ("name", "repository", "entry", "defines", "cpu", "cpu_role", "address_space",
              "lines", "source_sha256", "binary_bytes", "binary_sha256",
              "upstream_binary_sha256", "matches_upstream", "build_status", "error")
    units = []
    for record in report["units"]:
        unit = {key: record[key] for key in fields if key in record}
        if record.get("source"):
            unit["source"] = Path(record["source"]).relative_to(output).as_posix()
        unit["matching_original_roms"] = [Path(value).name for value in record.get("matching_original_roms", [])]
        if record.get("matching_bundled_originals"):
            unit["matching_bundled_originals"] = [value.replace("\\", "/")
                                                 for value in record["matching_bundled_originals"]]
        units.append(unit)
    data = {"schema": "retrolarium.sonic-reference-corpus", "schema_version": 1,
            "purpose": report["purpose"], "repositories": report["repositories"],
            "units": units, "limitations": report["limitations"],
            "chaotix_address_mapping": report["chaotix_address_mapping"]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--references", type=Path, default=Path("references"))
    parser.add_argument("--output", type=Path, default=Path("build/sonic-references"))
    parser.add_argument("--rom-dir", type=Path)
    parser.add_argument("--lock", type=Path, help="save a portable snapshot of versions and proof hashes")
    parser.add_argument("--verify", action="store_true", help="run upstream and flattened builds (Windows)")
    parser.add_argument("--cd-region", type=int, choices=(0, 1, 2), default=0, help="0=Japan, 1=USA, 2=Europe")
    args = parser.parse_args()
    if args.verify and os.name != "nt":
        parser.error("native upstream verification currently requires Windows")
    report = prepare(args)
    path = args.output.resolve() / "manifest.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_index(report, args.output.resolve())
    if args.lock:
        write_lock(report, args.output.resolve(), args.lock)
    print(f"Wrote {len(report['units'])} units: {path}", flush=True)
    if any("error" in unit for unit in report["units"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
