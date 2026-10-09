"""Scan a GoodNES set for NES games compiled from C (cc65).

usage: python -m tools.compiler_scan.nes NESMERGE_DIR OUTPUT_DIR --cc65 DIR
           [--include-pd] [--limit N] [--only SUBSTRING] [--recompute]

NESMERGE_DIR holds one .7z per game (GoodNES "NESMerge"). One good dump is
chosen per game with the same rules as megadrive_compiler_scan.py; public
domain releases are skipped unless --include-pd is given; then every clean
PD image is scanned as well (homebrew is where cc65 code is expected). Only the PRG ROM of each iNES image is scanned.

- cc65 runtime: the scanner compiles a probe program with the given cc65
  installation (cl65 -t nes), takes every runtime routine from the link map
  and searches the ROMs for its instruction skeleton with zero-page and
  absolute operands masked, so another linker layout still matches.
- Software stack: cc65 keeps locals and arguments on a stack addressed as
  LDY #n / LDA (sp),Y. "stack_ops" counts that idiom for the most used
  zero-page pointer; "ldy_jsr" is the share of JSRs directly preceded by
  LDY #n (calls to ldaxysp, staxysp, addysp, ...).

OUTPUT_DIR receives scan.csv and summary.md.
"""
import argparse
import collections
import csv
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.compiler_scan.megadrive import BAD_TAGS, GOOD, extract, list_archive, region_rank  # noqa: E402

PD_TAG = re.compile(r"\((?:PD)[^)]*\)", re.I)

# Official 6502 opcodes by addressing mode; operand lengths follow from the mode.
MODES = {}
for _mode, _codes in (
        ("imp", "00 08 18 28 38 40 48 58 60 68 78 88 8A 98 9A A8 AA B8 BA C8 CA D8 E8 EA F8 0A 2A 4A 6A"),
        ("imm", "09 29 49 69 A0 A2 A9 C0 C9 E0 E9"),
        ("zp", "05 06 24 25 26 45 46 65 66 84 85 86 A4 A5 A6 C4 C5 C6 E4 E5 E6"
               " 15 16 35 36 55 56 75 76 94 95 B4 B5 D5 D6 F5 F6 96 B6"
               " 01 21 41 61 81 A1 C1 E1 11 31 51 71 91 B1 D1 F1"),
        ("rel", "10 30 50 70 90 B0 D0 F0"),
        ("abs", "0D 0E 20 2C 2D 2E 4C 4D 4E 6D 6E 8C 8D 8E AC AD AE CC CD CE EC ED EE"
                " 1D 1E 3D 3E 5D 5E 7D 7E 9D BC BD DD DE FD FE 19 39 59 79 99 B9 D9 F9 BE 6C")):
    for _code in _codes.split():
        MODES[int(_code, 16)] = _mode
LENGTH = {"imp": 1, "imm": 2, "zp": 2, "rel": 2, "abs": 3}

PROBE = r"""
#include <string.h>
#include <stdlib.h>
struct obj { int x, y; unsigned char t; long s; };
struct obj objs[8];
unsigned char buf[64];
int f(int a, int b, unsigned char c) { int l[4]; l[c & 3] = a * b; return l[0] / (b | 1) + a % 7 + (a << c) + (b >> 2); }
long g(long a, long b) { return a * b + a / (b | 1) - (a >> 3); }
unsigned char h(unsigned char k) { switch (k) { case 1: return 4; case 2: return 9; case 7: return 1; default: return k + 1; } }
void main(void) {
  int i; unsigned char j; struct obj *p;
  for (i = 0; i < 8; ++i) { p = &objs[i]; p->x = f(i, i + 3, (unsigned char)i); p->s = g(p->x, i); p->t = h((unsigned char)i); }
  memset(buf, 0, sizeof buf); memcpy(buf + 8, objs, 16);
  for (j = 0; j < 10; j++) buf[j] = (unsigned char)rand();
  while (1) { objs[0].y += abs(objs[1].x - objs[2].x); }
}
"""


def skeleton(code, start, end):
    """Regex for code[start:end] with zero-page and absolute operands masked."""
    pattern, pc, count = b"", start, 0
    while pc < end:
        mode = MODES.get(code[pc])
        if mode is None or pc + LENGTH[mode] > len(code):
            break
        size = LENGTH[mode]
        pattern += re.escape(code[pc:pc + 1])
        if mode in ("zp", "abs"):
            pattern += b"." * (size - 1)
        else:
            pattern += re.escape(code[pc + 1:pc + size])
        pc += size
        count += 1
    return pattern, count, pc - start


def cc65_skeletons(cc65_dir):
    """Compile the probe with cc65 and return {routine: compiled skeleton}."""
    cl65 = Path(cc65_dir) / "bin" / "cl65.exe"
    if not cl65.exists():
        cl65 = Path(cc65_dir) / "bin" / "cl65"
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        (work / "probe.c").write_text(PROBE)
        subprocess.run([str(cl65), "-t", "nes", "-O", "-m", "probe.map", "-o", "probe.nes", "probe.c"],
                       cwd=work, check=True, capture_output=True)
        image = (work / "probe.nes").read_bytes()
        text = (work / "probe.map").read_text()
    prg = image[16:16 + image[4] * 16384]
    base = 0x10000 - len(prg)
    block = text.split("Exports list by name:")[1].split("Exports list by value:")[0]
    exports = {name: int(value, 16) for name, value, kind in re.findall(r"(\S+)\s+([0-9A-F]{6})\s+(\w+)", block)
               if kind == "RLA" and base <= int(value, 16) < 0xFFFA and not name.startswith("__")
               and name not in ("_main", "NESfont")}
    bounds = sorted(set(exports.values()))
    result = {}
    for name, address in exports.items():
        following = [b for b in bounds if b > address]
        end = following[0] if following else address + 64
        pattern, count, size = skeleton(prg, address - base, end - base)
        if count >= 5 and size >= 10:
            compiled = re.compile(pattern, re.S)
            if len(compiled.findall(prg)) == 1:  # unique even inside the probe
                result[name] = compiled
    return result


def homebrew(entries):
    """Every clean public-domain image of an archive (they are separate programs)."""
    return [e for e in entries if e.lower().endswith(".nes") and PD_TAG.search(e)
            and not BAD_TAGS.search(PD_TAG.sub("", e))]


def choose(entries):
    roms = [e for e in entries if e.lower().endswith(".nes")]
    keep = [e for e in roms if not BAD_TAGS.search(e)]
    verified = [e for e in keep if GOOD in e]
    plain = [e for e in keep if "[" not in e]
    pool = verified or plain
    return min(pool, key=lambda e: (region_rank(e), len(e))) if pool else None


def prg_rom(image):
    if image[:4] != b"NES\x1a":
        return None
    start = 16 + (512 if image[6] & 4 else 0)
    size = image[4] * 16384 or len(image) - start
    return image[start:start + size]


def scan(prg, skeletons):
    jsr = ldy_jsr = 0
    stack = collections.Counter()
    for i in range(2, len(prg) - 3):
        op = prg[i]
        if op == 0x20 and prg[i + 2] >= 0x80:
            jsr += 1
            if prg[i - 2] == 0xA0:
                ldy_jsr += 1
        elif op in (0xB1, 0x91) and prg[i - 2] == 0xA0:
            stack[prg[i + 1]] += 1
    zp, ops = stack.most_common(1)[0] if stack else (0, 0)
    found = sorted(name for name, pattern in skeletons.items() if pattern.search(prg))
    return {
        "prg_kb": len(prg) // 1024,
        "jsr": jsr,
        "ldy_jsr": round(ldy_jsr / jsr, 3) if jsr else 0.0,
        "stack_zp": f"${zp:02X}",
        "stack_ops_per_kb": round(ops / max(1, len(prg) / 1024), 2),
        "cc65_routines": len(found),
        "cc65_names": " ".join(found),
    }


def verdict(row):
    routines = int(row["cc65_routines"])
    # Commercial ROMs never match more than one routine (a short one, by chance).
    if routines >= 3:
        return "cc65"
    if routines == 2:
        return "cc65 runtime pieces?"
    if float(row["stack_ops_per_kb"]) >= 3 and float(row["ldy_jsr"]) >= 0.15:
        return "C-like stack code?"
    return "assembly"


VERDICTS = ("cc65", "cc65 runtime pieces?", "C-like stack code?", "assembly")


def write_outputs(rows, output):
    with (output / "scan.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    groups = collections.defaultdict(list)
    for row in rows:
        groups[row["verdict"]].append(row)
    lines = ["# NES compiler scan", "", f"{len(rows)} games scanned.", ""]
    lines += [f"- {key}: {len(groups[key])}" for key in VERDICTS]
    for key in VERDICTS[:-1]:
        lines += ["", f"## {key}", "", "| game | ROM | PRG KB | cc65 routines | stack ops/KB | LDY+JSR | names |",
                  "|---|---|---:|---:|---:|---:|---|"]
        for row in sorted(groups[key], key=lambda r: -int(r["cc65_routines"])):
            lines.append(f"| {row['game']} | {row['rom']} | {row['prg_kb']} | {row['cc65_routines']} | "
                         f"{row['stack_ops_per_kb']} | {row['ldy_jsr']} | {row['cc65_names']} |")
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nesmerge")
    parser.add_argument("output")
    parser.add_argument("--cc65")
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
    if not args.cc65:
        sys.exit("--cc65 DIR is required for a scan")
    skeletons = cc65_skeletons(args.cc65)
    print(f"{len(skeletons)} cc65 runtime skeletons", flush=True)
    archives = sorted(Path(args.nesmerge).glob("*.7z"))
    if args.only:
        archives = [a for a in archives if args.only.lower() in a.name.lower()]
    if args.limit:
        archives = archives[:args.limit]
    rows = []
    for number, archive in enumerate(archives, 1):
        entries = list_archive(archive)
        names = [choose(entries)] + (homebrew(entries) if args.include_pd else [])
        for name in filter(None, names):
            prg = prg_rom(extract(archive, name))
            if not prg:
                continue
            row = {"game": archive.stem, "rom": name, "pd": int(bool(PD_TAG.search(name))), **scan(prg, skeletons)}
            row["verdict"] = verdict(row)
            rows.append(row)
            if row["verdict"] != "assembly":
                print(f"[{number}/{len(archives)}] {row['verdict']:20s} {name}", flush=True)
    if not rows:
        sys.exit("no NES ROMs found")
    write_outputs(rows, output)
    print(f"done: {len(rows)} games; see {output / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
