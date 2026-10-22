"""Restore the manually documented QuackShot REV01 reference for evaluation.

This adapter restores the upstream's removed checksum loop and retail layout.
Only existing binary includes are extracted from the independently hash-pinned
ROM. M68K code remains assembly text; no mismatching instructions are replaced
with bytes. Neither this source nor its layout is an analyzer input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from tools.references.extra_profiles import as_environment, read_header, run_step
from tools.references.prepare_sonic import export, sha256
from tools.benchmarks.sonic_corpus import normalise_reference_listing
from tools.benchmarks.source import read_listing


PLAN = Path(__file__).with_name("quackshot_rev01.json")
LABEL = re.compile(r"^\s*([A-Za-z_][A-Za-z_0-9]*):")
INCLUDE = re.compile(r'^\s*binclude\s+"([^"]+)"', re.IGNORECASE)
ADDRESS = re.compile(r"_([0-9a-f]{4,6})$", re.IGNORECASE)
NAME = "quackshot-rev01-restored"


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one upstream fragment: {old!r}")
    return text.replace(old, new, 1)


def restore_source(text: str, plan: dict) -> str:
    text = replace_once(text, "    lea  (rom_end).l,a1", "    lea  ($3FFFF).l,a1")
    needle = "    movea.l  #word_18E,a1"
    text = replace_once(
        text,
        needle,
        """    lea ($100000).l,a0
    lea ($13FFFF).l,a1
    move.l a1,d0
restored_crc_second_range:
    add.w (a0)+,d1
    cmp.l a0,d0
    bcc.s restored_crc_second_range
"""
        + needle,
    )
    for old, new in (("$69D00", "$129D00"), ("$70000", "$130000"), ("$78000", "$138000"), ("$7FFFF", "$13FFFF")):
        text = replace_once(text, "    org " + old, "    org " + new)
    addresses = plan["symbol_addresses"]
    output = []
    for line in text.splitlines():
        label = LABEL.match(line)
        if label:
            name = label[1].lower()
            suffix = ADDRESS.search(name)
            at = addresses.get(name)
            if at is None and suffix:
                candidate = int(suffix[1], 16)
                if 0x19F18 <= candidate < plan["rom_size"]:
                    at = candidate
            if at is not None and 0x19F18 <= at < plan["rom_size"]:
                output.append(f"    org ${at:X}")
        output.append(line)
    text = "\n".join(output) + "\n"
    # Retail ROM has an explicitly empty middle bank; other holes are $FF.
    text = replace_once(
        text, "    org $100000\n", "    org $40000\n    rept $C00\n    dc.b [$100]0\n    endm\n    org $100000\n"
    )
    text = replace_once(
        text, '    binclude "src/smps/bank0.bin"\n    align 2, 0', '    binclude "src/smps/bank0.bin"\n    align 2, $FF'
    )
    for start, end, next_at in (
        (0x1C0DC, 0x1C0E8, 0x1C120),
        (0x1029D8, 0x1029E4, 0x102A00),
        (0x13CA6A, 0x13CA70, 0x13CA70),
    ):
        needle = f"    org ${next_at:X}\n"
        text = replace_once(text, needle, f"    org ${start:X}\n    dc.b [{end - start}]0\n" + needle)
    return text


def extract_assets(root: Path, rom: bytes, plan: dict) -> list[dict]:
    extracted = []
    for item in plan["assets"]:
        target = (root / item["path"]).resolve()
        if not target.is_relative_to(root.resolve()) or target.suffix.lower() != ".bin":
            raise ValueError(f"binary include escapes the staged tree or is not binary: {item['path']}")
        start, size = item["offset"], item["size"]
        if start < 0 or size <= 0 or start + size > len(rom):
            raise ValueError(f"binary include range exceeds ROM: {item['path']}")
        data = rom[start : start + size]
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"original binary include hash mismatch: {item['path']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(dict(item))
    return extracted


def assemble(source: Path, binary: Path, root: Path, tools: Path, timeout: int) -> Path:
    obj = binary.with_suffix(".p")
    env = as_environment(tools)
    run_step(
        [str(tools / "asw.exe"), "-maxerrors", "2", "-L", "-i", str(root), "-o", str(obj), str(source)],
        root,
        binary.with_suffix(".assembly.log"),
        env=env,
        timeout=timeout,
    )
    if not obj.is_file():
        raise ValueError("AS did not produce an object")
    run_step(
        [str(tools / "p2bin.exe"), str(obj), str(binary), "-l", "255"],
        root,
        binary.with_suffix(".conversion.log"),
        env=env,
        timeout=timeout,
    )
    listing = binary.with_suffix(".lst")
    if source.with_suffix(".lst") != listing:
        shutil.copy2(source.with_suffix(".lst"), listing)
    return listing


def prepare(checkout: Path, original: Path, output: Path, tools: Path, timeout: int = 1800) -> dict:
    checkout, original, output, tools = (p.resolve() for p in (checkout, original, output, tools))
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    rom = original.read_bytes()
    if len(rom) != plan["rom_size"] or hashlib.sha256(rom).hexdigest() != plan["rom_sha256"]:
        raise ValueError("ROM is not the independently pinned retail REV01; variants are not substituted")
    commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    if commit != plan["upstream_commit"] or sha256(checkout / "qs.s") != plan["entry_sha256"]:
        raise ValueError("upstream source differs from the reviewed restoration plan")
    if any(sha256(checkout / name) != expected for name, expected in plan["source_hashes"].items()):
        raise ValueError("upstream includes differ from the reviewed restoration plan")
    if output.exists():
        raise ValueError("use a fresh output directory to avoid reusing a stale build")
    if output.is_relative_to(checkout):
        raise ValueError("output must not be inside the upstream checkout")
    dest = output / NAME
    root = dest / "restored-tree"
    root.mkdir(parents=True)
    for name in ("qs.s", "qs_structs.inc", "qs_equals.inc", "qs_rams.inc", "qs_externs.inc", "qs_funcs.inc"):
        shutil.copy2(checkout / name, root / name)
    shutil.copytree(checkout / "src", root / "src", ignore=shutil.ignore_patterns("*.lst", "*.p"))
    text = (root / "qs.s").read_text(encoding="utf-8-sig")
    declared = {INCLUDE.match(line)[1] for line in text.splitlines() if INCLUDE.match(line)}
    if declared != {item["path"] for item in plan["assets"]}:
        raise ValueError("upstream binary includes no longer agree with the reviewed asset plan")
    assets = extract_assets(root, rom, plan)
    (dest / "asset-provenance.json").write_text(json.dumps(assets, indent=2) + "\n", encoding="utf-8")
    (root / "qs.s").write_text(restore_source(text, plan), encoding="utf-8")
    record = dict(export(root, "qs.s", dest / "main.s", {}))
    split_listing = assemble(root / "qs.s", dest / "upstream.bin", root, tools, timeout)
    listing = assemble(dest / "main.s", dest / "reference.bin", root, tools, timeout)
    binary = (dest / "reference.bin").read_bytes()
    if binary != rom or (dest / "upstream.bin").read_bytes() != rom:
        raise ValueError("restored split and flattened assemblies must both be byte-identical to the original")
    normalized = dest / "reference-m68k.lst"
    known, uncertain, provenance = normalise_reference_listing(listing, binary, normalized)
    recovered, recovered_open = read_listing(normalized, binary)
    if not known or uncertain or recovered_open or recovered != known:
        raise ValueError("restored reference listing must contain complete, unambiguous instructions")
    header = read_header(binary)
    record.update(
        name=NAME,
        repository="quackshot_src",
        title="QuackShot REV01",
        entry="qs.s",
        family="quackshot-restored",
        commit=commit,
        pinned_commit=commit,
        scope="M68K instructions explicitly emitted in the restored reference; binary includes excluded",
        upstream_binary=str(dest / "upstream.bin"),
        upstream_binary_sha256=sha256(dest / "upstream.bin"),
        binary=str(dest / "reference.bin"),
        binary_sha256=sha256(dest / "reference.bin"),
        binary_bytes=len(binary),
        matches_upstream=True,
        header_checksum_valid=header.checksum_valid,
        matching_original_roms=[str(original)],
        status="verified-original",
        listing=str(normalized),
        listing_sha256=sha256(normalized),
        reference_instructions=len(known),
        uncertain_instruction_addresses=len(uncertain),
        listing_provenance=provenance,
        restoration_plan=str(PLAN),
        restoration_plan_sha256=sha256(PLAN),
        restored_split_listing=str(split_listing),
        toolchain=[{"path": str(tools / name), "sha256": sha256(tools / name)} for name in ("asw.exe", "p2bin.exe")],
        notes=[
            "Evaluation-only restoration of reviewed manual source, not a pristine upstream build.",
            "Retail checksum loop and layout restored; existing binary assets extracted, not recompressed.",
        ],
    )
    (dest / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps({"units": [record]}, indent=2) + "\n", encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=Path("references/quackshot_src"))
    parser.add_argument("--rom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--as-dir", type=Path, default=Path("references/SITDDISASM/tools/asw"))
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    result = prepare(args.checkout, args.rom, args.output, args.as_dir, args.timeout)
    print(
        json.dumps(
            {key: result[key] for key in ("status", "binary_sha256", "reference_instructions", "listing")}, indent=2
        )
    )


if __name__ == "__main__":
    main()
