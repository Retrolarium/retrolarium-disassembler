"""Scan a GoodGen set for Mega Drive games compiled from C.

usage: python tools/megadrive_compiler_scan.py GENMERGE_DIR OUTPUT_DIR
           [--sierra-lib DIR] [--limit N] [--only SUBSTRING]

GENMERGE_DIR holds one .7z per game (GoodGen "GenMerge"). For each game one
good dump is chosen: a verified "[!]" dump in the preferred region order,
never a hack, trainer, translation, bad or overdumped image, beta, prototype
or public-domain release. 7-Zip extracts it to memory and the raw 68000 code
is scanned without disassembly:

- C calling convention: LINK A6 frames, UNLK, and the share of absolute
  JSR calls followed directly by an argument cleanup (ADDQ.L #n,SP or
  LEA n(SP),SP). Hand-written Mega Drive code has almost none of these.
- Sierra Systems 68000 C: its inline 32x32 multiply sequence, the runtime
  message "Floating Point Divide by Zero Exception.", and byte windows of
  the vendor libraries (LIBC.68, LIBMSF.68) when --sierra-lib is given.
- Tool strings: Sierra, Microtec, SN Systems/Psy-Q, GCC, Lattice, Aztec, ...

OUTPUT_DIR receives scan.csv (one row per game) and summary.md;
--recompute re-classifies an existing scan.csv without rescanning.
"""
import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path

SEVEN_ZIP = r"C:\Program Files\7-Zip\7z.exe"
REGION_ORDER = ["U", "W", "UE", "JU", "JUE", "E", "J", "UK", "F", "G", "S", "B", "K", "A", "4"]
BAD_TAGS = re.compile(r"\[(?:h|t|T|b|f|o|a|p|x|c)\w*[^\]]*\]|\((?:Beta|Proto|PD|Hack|Sample|Demo|Prototype)[^)]*\)", re.I)
GOOD = "[!]"
# Long, unambiguous markers only: short ones like "GCC" occur by chance in data.
TOOL_STRINGS = [b"Sierra Systems", b"SIERRA SYSTEMS", b"Microtec", b"MICROTEC", b"MCC68K", b"SN Systems",
                b"Psy-Q", b"PSY-Q", b"gcc2_compiled", b"GNU C", b"Lattice", b"Aztec C", b"Introl",
                b"Green Hills", b"Whitesmiths", b"Cross Products", b"SNASM", b"Copyright 1987"]
SIERRA_FP_MESSAGE = b"Floating Point Divide by Zero Exception."
# Sierra's inline long multiply (as emitted for Lib_Rand in Pirates! Gold):
# movea.l d3,a0; move.l d0,d1; move.l d0,d3; mulu d2,d0; swap d1; mulu d2,d1;
# swap d2; mulu d2,d3; add.w d3,d1; swap d0; add.w d1,d0; swap d0; move.l a0,d3
SIERRA_LONG_MULTIPLY = bytes.fromhex("2043 2200 2600 C0C2 4841 C2C2 4842 C6C2 D243 4840 D041 4840 2608".replace(" ", ""))


def region_rank(name):
    match = re.search(r"\(([A-Z0-9]{1,3})\)", name)
    region = match.group(1) if match else ""
    return REGION_ORDER.index(region) if region in REGION_ORDER else len(REGION_ORDER)


def choose(entries):
    """Pick one good dump from an archive listing."""
    roms = [e for e in entries if e.lower().endswith((".bin", ".gen", ".md", ".smd"))
            and "32X" not in e and not BAD_TAGS.search(e)]
    verified = [e for e in roms if GOOD in e]
    plain = [e for e in roms if "[" not in e]
    pool = verified or plain
    return min(pool, key=lambda e: (region_rank(e), len(e))) if pool else None


def list_archive(archive):
    out = subprocess.run([SEVEN_ZIP, "l", "-slt", str(archive)], capture_output=True, text=True,
                         errors="replace").stdout
    return [line[7:] for line in out.splitlines() if line.startswith("Path = ")][1:]


def extract(archive, name):
    return subprocess.run([SEVEN_ZIP, "e", "-so", str(archive), name], capture_output=True).stdout


def deinterleave_smd(data):
    body = data[512:] if len(data) % 16384 == 512 else data
    out = bytearray()
    for block in range(0, len(body), 16384):
        chunk = body[block:block + 16384]
        half = len(chunk) // 2
        for i in range(half):
            out.append(chunk[half + i])
            out.append(chunk[i])
    return bytes(out)


def sierra_windows(lib_dir, width=24):
    windows = set()
    for name in ("LIBC.68", "LIBMSF.68"):
        path = Path(lib_dir) / name
        if not path.exists():
            continue
        data = path.read_bytes()
        for offset in range(0, len(data) - width, 8):
            window = data[offset:offset + width]
            if len(set(window)) >= 10:
                windows.add(window)
    return windows


def scan(rom, windows):
    words = len(rom) // 2
    link = unlk = jsr = cleaned = 0
    for offset in range(0, len(rom) - 8, 2):
        word = (rom[offset] << 8) | rom[offset + 1]
        if word == 0x4E56:
            displacement = (rom[offset + 2] << 8) | rom[offset + 3]
            if displacement == 0 or displacement & 0x8000:
                link += 1
        elif word == 0x4E5E:
            unlk += 1
        elif word == 0x4EB9 and offset + 8 <= len(rom):
            target = int.from_bytes(rom[offset + 2:offset + 6], "big")
            if 0x200 <= target < len(rom) and not target & 1:
                jsr += 1
                following = (rom[offset + 6] << 8) | rom[offset + 7]
                if following & 0xF1FF == 0x508F or following == 0x4FEF:
                    cleaned += 1
    library_hits = 0
    if windows:
        for offset in range(0, len(rom) - 24, 2):
            if rom[offset:offset + 24] in windows:
                library_hits += 1
    tools = sorted({s.decode() for s in TOOL_STRINGS if s in rom})
    return {
        "size": len(rom),
        "link": link, "unlk": unlk, "jsr_abs": jsr, "jsr_cleanup": cleaned,
        "cleanup_ratio": round(cleaned / jsr, 3) if jsr else 0.0,
        "sierra_long_multiply": rom.count(SIERRA_LONG_MULTIPLY),
        "sierra_fp_message": int(SIERRA_FP_MESSAGE in rom),
        "sierra_library_windows": library_hits,
        "tool_strings": " ".join(tools),
    }


def verdict(row):
    num = lambda key: float(row[key])
    sierra = num("sierra_fp_message") > 0 or num("sierra_long_multiply") > 0 or num("sierra_library_windows") >= 20
    c_like = num("link") >= 20 and num("cleanup_ratio") >= 0.15
    if c_like and sierra:
        return "Sierra C"
    if c_like:
        return "C (compiler unknown)"
    if sierra:
        return "mostly assembly + Sierra pieces"
    if num("link") >= 5 and num("cleanup_ratio") >= 0.05:
        return "partly C?"
    return "assembly"


VERDICTS = ("Sierra C", "C (compiler unknown)", "partly C?", "mostly assembly + Sierra pieces", "assembly")


def write_csv(rows, output):
    with (output / "scan.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_summary(rows, output):
    groups = {}
    for row in rows:
        groups.setdefault(row["verdict"], []).append(row)
    lines = ["# Mega Drive compiler scan", "", f"{len(rows)} games scanned.", ""]
    for key in VERDICTS:
        lines.append(f"- {key}: {len(groups.get(key, []))}")
    for key in VERDICTS[:-1]:
        lines += ["", f"## {key}", "", "| game | ROM | LINK | JSR cleanup | Sierra mul | FP msg | lib windows | strings |",
                  "|---|---|---:|---:|---:|---:|---:|---|"]
        for row in sorted(groups.get(key, []), key=lambda r: -int(r["link"])):
            lines.append(f"| {row['game']} | {row['rom']} | {row['link']} | {row['cleanup_ratio']} | "
                         f"{row['sierra_long_multiply']} | {row['sierra_fp_message']} | "
                         f"{row['sierra_library_windows']} | {row['tool_strings']} |")
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("genmerge")
    parser.add_argument("output")
    parser.add_argument("--sierra-lib")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--only")
    parser.add_argument("--recompute", action="store_true",
                        help="re-classify OUTPUT_DIR/scan.csv without rescanning")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if args.recompute:
        with (output / "scan.csv").open(encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        for row in rows:
            row["verdict"] = verdict(row)
        write_csv(rows, output)
        write_summary(rows, output)
        print(f"re-classified {len(rows)} games")
        return 0
    windows = sierra_windows(args.sierra_lib) if args.sierra_lib else set()
    archives = sorted(Path(args.genmerge).glob("*.7z"))
    if args.only:
        archives = [a for a in archives if args.only.lower() in a.name.lower()]
    if args.limit:
        archives = archives[:args.limit]
    rows = []
    for number, archive in enumerate(archives, 1):
        name = choose(list_archive(archive))
        if name is None:
            continue
        rom = extract(archive, name)
        if name.lower().endswith(".smd"):
            rom = deinterleave_smd(rom)
        if len(rom) < 0x200 or b"SEGA" not in rom[0x100:0x120]:
            continue  # not a plain Mega Drive image
        row = {"game": archive.stem, "rom": name, **scan(rom, windows)}
        row["verdict"] = verdict(row)
        rows.append(row)
        if row["verdict"] != "assembly":
            print(f"[{number}/{len(archives)}] {row['verdict']:22s} {name}", flush=True)
    if not rows:
        sys.exit("no Mega Drive ROMs found")
    write_csv(rows, output)
    write_summary(rows, output)
    print(f"done: {len(rows)} games; see {output / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
