"""Scan a GoodSNES set for SNES games compiled from C.

usage: python tools/snes_compiler_scan.py SNESMERGE_DIR OUTPUT_DIR
           [--include-pd] [--limit N] [--only SUBSTRING] [--recompute]

One good dump per game is chosen with the rules of megadrive_compiler_scan.py
(--include-pd also scans every clean public-domain image). The 65816 code is
scanned as raw bytes; no vendor library is needed:

- Call cleanup: share of JSL/JSR calls followed directly by popping the
  pushed arguments (PLX PLX, PLY PLY, PLA PLA, or TSC CLC ADC #n TCS).
  Hand-written code passes arguments in registers and direct page.
- Stack-relative locals: LDA n,S per KB. Compilers address arguments and
  locals on the stack; assembly programmers rarely do.
- Frames: compiler prologues that open a stack or direct-page frame,
  TSC SEC SBC #n TCS and PHD [PHA] TDC [CLC] ADC #-n TCD.
- Tool strings (WDC, SN Systems, 816-tcc, PVSnesLib, ...).

OUTPUT_DIR receives scan.csv and summary.md.
"""
import argparse
import collections
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from megadrive_compiler_scan import BAD_TAGS, GOOD, TOOL_STRINGS, extract, list_archive, region_rank  # noqa: E402

PD_TAG = re.compile(r"\(PD\)", re.I)
EXTENSIONS = (".smc", ".sfc", ".swc", ".fig")
SNES_TOOL_STRINGS = TOOL_STRINGS + [b"Western Design", b"WDC816", b"816-tcc", b"PVSnesLib", b"pvsneslib",
                                    b"tcc__", b"Archimedes", b"Zardoz"]

CALL = re.compile(rb"\x22...|\x20..", re.S)
CLEANUP = re.compile(rb"\xFA\xFA|\x7A\x7A|\x68\x68|(?:\xC2.)?\x3B\x18\x69..\x1B", re.S)
STACK_LOAD = re.compile(rb"\xA3[\x01-\x3F]")
STACK_FRAME = re.compile(rb"\x3B\x38\xE9..\x1B", re.S)
DP_FRAME = re.compile(rb"\x0B\x48?\x7B\x18?\x69.[\x80-\xFF]\x5B|\x0B\x3B\x38?\xE9..\x5B", re.S)


def choose(entries):
    roms = [e for e in entries if e.lower().endswith(EXTENSIONS) and not BAD_TAGS.search(e)]
    verified = [e for e in roms if GOOD in e]
    plain = [e for e in roms if "[" not in e]
    pool = verified or plain
    return min(pool, key=lambda e: (region_rank(e), len(e))) if pool else None


def homebrew(entries):
    return [e for e in entries if e.lower().endswith(EXTENSIONS) and PD_TAG.search(e)
            and not BAD_TAGS.search(PD_TAG.sub("", e))]


def scan(rom):
    calls = cleaned = 0
    for match in CALL.finditer(rom):
        calls += 1
        if CLEANUP.match(rom, match.end()):
            cleaned += 1
    kb = max(1, len(rom) / 1024)
    return {
        "rom_kb": len(rom) // 1024,
        "calls": calls,
        "cleanup_ratio": round(cleaned / calls, 4) if calls else 0.0,
        "stack_loads_per_kb": round(len(STACK_LOAD.findall(rom)) / kb, 2),
        "stack_frames": len(STACK_FRAME.findall(rom)),
        "dp_frames": len(DP_FRAME.findall(rom)),
        "tool_strings": " ".join(sorted({s.decode() for s in SNES_TOOL_STRINGS if s in rom})),
    }


def verdict(row):
    ratio = float(row["cleanup_ratio"])
    loads = float(row["stack_loads_per_kb"])
    frames = int(row["stack_frames"]) + int(row["dp_frames"])
    # Hand-written games score 0 frames almost without exception; compiled
    # ones have hundreds, and stack-argument compilers also pop after calls.
    # Small homebrew programs in padded ROMs dilute the ratio, hence the second rule.
    if (ratio >= 0.05 and (loads >= 2 or frames >= 30)) or (ratio >= 0.025 and loads >= 1.5):
        return "C (stack arguments)"
    if frames >= 150:
        return "C (frame prologues)"
    if ratio >= 0.02 or frames >= 50:
        return "partly C?"
    return "assembly"


VERDICTS = ("C (stack arguments)", "C (frame prologues)", "partly C?", "assembly")


def write_outputs(rows, output):
    with (output / "scan.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    groups = collections.defaultdict(list)
    for row in rows:
        groups[row["verdict"]].append(row)
    lines = ["# SNES compiler scan", "", f"{len(rows)} games scanned.", ""]
    lines += [f"- {key}: {len(groups[key])}" for key in VERDICTS]
    for key in VERDICTS[:-1]:
        lines += ["", f"## {key}", "", "| game | ROM | KB | call cleanup | LDA n,S /KB | stack frames | DP frames | strings |",
                  "|---|---|---:|---:|---:|---:|---:|---|"]
        for row in sorted(groups[key], key=lambda r: -float(r["cleanup_ratio"])):
            lines.append(f"| {row['game']} | {row['rom']} | {row['rom_kb']} | {row['cleanup_ratio']} | "
                         f"{row['stack_loads_per_kb']} | {row['stack_frames']} | {row['dp_frames']} | {row['tool_strings']} |")
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snesmerge")
    parser.add_argument("output")
    parser.add_argument("--include-pd", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--only")
    parser.add_argument("--recompute", action="store_true")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if args.recompute:
        with (output / "scan.csv").open(encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        for row in rows:
            row["verdict"] = verdict(row)
        write_outputs(rows, output)
        print(f"re-classified {len(rows)} games")
        return 0
    archives = sorted(Path(args.snesmerge).glob("*.7z"))
    if args.only:
        archives = [a for a in archives if args.only.lower() in a.name.lower()]
    if args.limit:
        archives = archives[:args.limit]
    rows = []
    for number, archive in enumerate(archives, 1):
        entries = list_archive(archive)
        names = [choose(entries)] + (homebrew(entries) if args.include_pd else [])
        for name in filter(None, names):
            rom = extract(archive, name)
            if len(rom) % 1024 == 512:
                rom = rom[512:]  # copier header
            if len(rom) < 0x8000:
                continue
            row = {"game": archive.stem, "rom": name, "pd": int(bool(PD_TAG.search(name))), **scan(rom)}
            row["verdict"] = verdict(row)
            rows.append(row)
            if row["verdict"] != "assembly":
                print(f"[{number}/{len(archives)}] {row['verdict']:20s} {name}", flush=True)
    if not rows:
        sys.exit("no SNES ROMs found")
    write_outputs(rows, output)
    print(f"done: {len(rows)} games; see {output / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
