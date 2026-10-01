"""Second-batch Mega Drive reference profiles and original-ROM identification.

Evaluation only. These profiles reproduce each upstream project's own build
of a known retail original. Nothing here, including header identities,
listings or addresses, is passed to automatic ROM analysis.

Header identities below were read from each project's source header
(serial, checksum word, region field, ROM size). After assembly they are
checked against the produced ROM, so a stale value fails instead of
selecting a different original.
"""
from __future__ import annotations

import ast
import contextlib
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from prepare_sonic_references import export, sha256
from sonic_corpus_benchmark import M68K, normalise_reference_listing
from source_benchmark import read_listing


ROM_SUFFIXES = {".gen", ".bin", ".md"}
MAX_CARTRIDGE_BYTES = 8 * 1024 * 1024
SCOPE = "M68K instructions explicitly emitted in the reference listing; binary assets excluded"


class Unsupported(Exception):
    """A profile that cannot produce a verifiable reference in this batch."""


# ---------------------------------------------------------------------------
# ROM headers and candidate originals


@dataclass(frozen=True)
class Header:
    console: str
    serial: str
    checksum: int
    rom_end: int
    region: str
    computed_checksum: int
    size: int

    @property
    def checksum_valid(self) -> bool:
        return self.checksum == self.computed_checksum


def genesis_checksum(data: bytes) -> int:
    body = data[0x200:]
    if len(body) % 2:
        body += b"\0"
    return sum(struct.unpack(f">{len(body) // 2}H", body)) & 0xFFFF


def read_header(data: bytes) -> Header | None:
    if len(data) < 0x200:
        return None
    text = lambda start, end: data[start:end].decode("latin-1").strip()
    return Header(console=text(0x100, 0x110), serial=text(0x180, 0x18E),
                  checksum=int.from_bytes(data[0x18E:0x190], "big"),
                  rom_end=int.from_bytes(data[0x1A4:0x1A8], "big"),
                  region=text(0x1F0, 0x200), computed_checksum=genesis_checksum(data),
                  size=len(data))


@dataclass(frozen=True)
class Identity:
    """Header fields of the original an upstream profile claims to rebuild."""
    serial: str
    checksum: int
    region: str
    size: int

    def claims(self, header: Header | None) -> bool:
        """The header names the same release; the full hash still decides."""
        return (header is not None and header.serial == self.serial
                and header.region == self.region and header.checksum == self.checksum)

    def differences(self, header: Header | None) -> list[str]:
        if header is None:
            return ["no Mega Drive header"]
        result = []
        for key, actual in (("serial", header.serial), ("region", header.region),
                            ("checksum", header.checksum), ("size", header.size)):
            expected = getattr(self, key)
            if actual != expected:
                shown = (lambda v: f"${v:04X}") if key == "checksum" else (lambda v: repr(v))
                result.append(f"{key} {shown(actual)} != {shown(expected)}")
        return result


@dataclass(frozen=True)
class Candidate:
    path: str
    sha256: str
    sha1: str
    size: int
    header: Header | None
    origin: str

    def summary(self) -> dict:
        header = self.header
        return {"path": self.path, "sha256": self.sha256, "sha1": self.sha1, "bytes": self.size,
                "origin": self.origin,
                **({"serial": header.serial, "region": header.region,
                    "header_checksum": f"${header.checksum:04X}",
                    "header_checksum_valid": header.checksum_valid} if header else {})}


def _candidate(path: Path, origin: str) -> Candidate | None:
    if not path.is_file() or path.suffix.lower() not in ROM_SUFFIXES:
        return None
    if path.stat().st_size > MAX_CARTRIDGE_BYTES:
        return None
    data = path.read_bytes()
    return Candidate(str(path.resolve()), hashlib.sha256(data).hexdigest(),
                     hashlib.sha1(data).hexdigest(), len(data), read_header(data), origin)


def scan_roms(roots: list[Path], inventory: Path | None = None) -> tuple[list[Candidate], list[dict]]:
    """Collect candidate originals. Files are only read, never moved or renamed.

    An inventory entry whose file no longer has the recorded SHA-256 is
    reported and excluded: its provenance is no longer the recorded one.
    """
    found: dict[str, Candidate] = {}
    problems: list[dict] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            candidate = _candidate(path, f"rom-root:{root}")
            if candidate:
                found.setdefault(candidate.path, candidate)
    if inventory is not None:
        for item in json.loads(inventory.read_text(encoding="utf-8")):
            path = Path(item["path"])
            candidate = _candidate(path, f"inventory:{inventory}")
            if candidate is None:
                problems.append({"path": item["path"], "problem": "listed original is missing or not a cartridge file"})
            elif candidate.sha256 != item.get("sha256", "").lower():
                problems.append({"path": item["path"], "problem": "SHA-256 differs from inventory; excluded",
                                 "recorded": item.get("sha256"), "actual": candidate.sha256})
                found.pop(candidate.path, None)
            else:
                found.setdefault(candidate.path, candidate)
    return sorted(found.values(), key=lambda item: item.path), problems


def select_split_input(pool: list[Candidate], identity: Identity) -> Candidate:
    """Pick the one clean original an upstream split script needs.

    Filenames are ignored. The header must name the release, the header
    checksum must match the contents (rejecting most hacks and bad dumps)
    and the size must equal the release size (rejecting overdumps).
    """
    claims = [item for item in pool if identity.claims(item.header)]
    clean = {item.sha256: item for item in claims
             if item.header.checksum_valid and item.size == identity.size}
    if len(clean) == 1:
        return next(iter(clean.values()))
    if not clean:
        rejected = [{"path": item.path, "checksum_valid": item.header.checksum_valid, "bytes": item.size}
                    for item in claims]
        raise ValueError(f"no clean original for {identity.serial} {identity.region}; header matches: {rejected}")
    raise ValueError(f"ambiguous originals for {identity.serial}: {sorted(item.path for item in clean.values())}")


def first_difference(left: bytes, right: bytes) -> dict:
    offset = next((index for index, (a, b) in enumerate(zip(left, right)) if a != b), None)
    if offset is None and len(left) != len(right):
        offset = min(len(left), len(right))
    differing = sum(a != b for a, b in zip(left, right)) + abs(len(left) - len(right))
    return {"first_differing_offset": None if offset is None else f"0x{offset:06X}",
            "differing_bytes": differing}


def classify_build(binary: bytes, identity: Identity | None, pool: list[Candidate]) -> dict:
    """Report which supplied originals the assembled ROM is.

    ``verified-original``: byte-identical to a supplied file.
    ``original-mismatch``: a supplied file names the same release, but the
    build differs; this must be investigated, never accepted.
    ``upstream-only``: no supplied file names this release.
    """
    digest = hashlib.sha256(binary).hexdigest()
    matches = [item for item in pool if item.sha256 == digest]
    claimed = [item for item in pool if identity and identity.claims(item.header)]
    related = [item for item in pool if identity and item.header and item not in matches
               and _product(item.header.serial) == _product(identity.serial)]
    result = {"matching_original_roms": [item.path for item in matches]}
    if matches:
        result["status"] = "verified-original"
    elif claimed:
        result["status"] = "original-mismatch"
        result["mismatched_originals"] = []
        for item in claimed:
            entry = item.summary()
            entry.update(first_difference(binary, Path(item.path).read_bytes()))
            result["mismatched_originals"].append(entry)
    else:
        result["status"] = "upstream-only"
    if related:
        result["related_supplied_roms"] = [
            {**item.summary(), "differences_from_profile": identity.differences(item.header)}
            for item in related if item not in claimed]
    return result


def _product(serial: str) -> str:
    """Product number without the GM prefix, spacing and revision suffix."""
    compact = re.sub(r"[\s-]", "", serial)
    compact = compact[2:] if compact.upper().startswith("GM") else compact
    return compact[:-2] if len(compact) > 2 and compact[-2:].isdigit() else compact


# ---------------------------------------------------------------------------
# Upstream configuration


def parse_simple_yaml(text: str) -> dict:
    """Parse the indentation-only mapping subset used by landstalker build.yaml."""
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent + 1]:
            raise ValueError(f"tab indentation is unsupported at line {number}")
        key, separator, value = line.strip().partition(":")
        if not separator:
            raise ValueError(f"expected 'key: value' at line {number}")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise ValueError(f"bad indentation at line {number}")
        parent = stack[-1][1]
        if key in parent:
            raise ValueError(f"duplicate key {key!r} at line {number}")
        if value.strip():
            parent[key] = value.strip()
        else:
            parent[key] = {}
            stack.append((indent, parent[key]))
    return root


def landstalker_build(root: Path, variant: str) -> dict:
    builds = parse_simple_yaml((root / "build.yaml").read_text(encoding="utf-8-sig"))["Builds"]
    if variant not in builds:
        raise ValueError(f"build.yaml has no {variant} build")
    build = builds[variant]
    if build["Defines"].get("EXPANDED") != "0":
        raise ValueError(f"{variant} is an expanded build; only retail layouts are accepted")
    return {"source": build["Source"], "buildopts": build["Buildopts"], "defines": dict(build["Defines"])}


def _git(checkout: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(checkout), *arguments], text=True).strip()


@contextlib.contextmanager
def option_overrides(root: Path, overrides: dict[str, dict[str, str]], *, checkout: Path | None = None):
    """Temporarily set ``name = value`` options, as the upstream README asks users to.

    Only listed keys may change; each must occur exactly once. The original
    bytes are restored even if assembly fails. A file that already differs
    from the pinned checkout is refused rather than silently rebuilt.
    """
    saved: dict[Path, bytes] = {}
    applied: dict[str, dict] = {}
    try:
        for relative, values in overrides.items():
            path = root / relative
            if checkout is not None:
                status = subprocess.run(["git", "-C", str(checkout), "diff", "--quiet", "--", str(path)])
                if status.returncode:
                    raise ValueError(f"{relative} has local modifications; restore the pinned file first")
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            original = {}
            for key, value in values.items():
                pattern = re.compile(rf"^([ \t]*{re.escape(key)}[ \t]*=[ \t]*)([^\s;]+)", re.M)
                found = pattern.findall(text)
                if len(found) != 1:
                    raise ValueError(f"expected one '{key} =' assignment in {relative}, found {len(found)}")
                original[key] = found[0][1]
                text = pattern.sub(lambda match: match.group(1) + value, text)
            saved[path] = raw
            path.write_bytes(text.encode("utf-8"))
            applied[relative] = {"pinned_sha256": hashlib.sha256(raw).hexdigest(),
                                 "pinned_values": original, "build_values": dict(values),
                                 "build_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
        yield applied
    finally:
        for path, raw in saved.items():
            path.write_bytes(raw)
            if path.read_bytes() != raw:
                raise RuntimeError(f"failed to restore {path}")


# ---------------------------------------------------------------------------
# Profiles


@dataclass(frozen=True)
class Profile:
    name: str
    repository: str
    commit: str
    title: str
    family: str
    entry: str = ""
    subdir: str = "."
    identity: Identity | None = None
    variant: str = ""
    overrides: dict = field(default_factory=dict)
    repository_rom: str | None = None
    notes: tuple[str, ...] = ()
    reason: str = ""


def _ps3(revision: int) -> dict:
    return {"ps3.options.asm": {"bugfixes": "0", "enable_run": "0", "revision": str(revision), "cross_patch": "0"}}


def _ps4(revision: int) -> dict:
    return {"ps4.options.asm": {"bugfixes": "0", "optional_fixes": "0", "dialogue_uncompressed": "0",
                                "revision": str(revision), "restored_enemy": "0",
                                "light_sensitivity_patch": "0"}}


LANDSTALKER = "fb8a9c6c64ec27c05acea75f9556c928d2b9f081"
PROFILES: dict[str, Profile] = {profile.name: profile for profile in (
    Profile("quackshot-rev01-header", "quackshot_src", "90f7be9961c78ca4df2deede0790789aea944f6e",
            "QuackShot", "quackshot-restored", "qs.s",
            identity=Identity("GM 00004054-01", 0xA4B3, "JUE", 0x140000),
            notes=("Reviewed evaluation-only restoration of the manual REV01 source; not a pristine upstream build.",
                   "Retail checksum loop, layout and unchanged binary includes are restored in a staged copy.",
                   "Both split and flattened assemblies must reproduce the independently pinned retail ROM.")),
    *(Profile(f"landstalker-{variant.lower()}", "landstalker_disasm", LANDSTALKER, "Landstalker",
              "landstalker", variant=variant, identity=identity)
      for variant, identity in (
          ("US", Identity("GM MK-1353 -00", 0xF37C, "U", 0x200000)),
          ("JP", Identity("GM 00005517-00", 0x35A6, "J", 0x200000)),
          ("EUR", Identity("GM MK-1353 -00", 0x2482, "E", 0x200000)),
          ("DE", Identity("GM MK-1353 -00", 0xC867, "E", 0x200000)))),
    Profile("shining-in-the-darkness-us", "SITDDISASM", "d790e3c8ac2d9c723266140ea9c6cdabf4a602df",
            "Shining in the Darkness", "sitd", "sitd.asm", "disasm",
            identity=Identity("GM MK-1310  00", 0x2103, "UE", 0x100000),
            notes=("split/sitdsplits.txt extracts the sound driver from the original.",)),
    Profile("phantasy-star-2-ue-rev02", "SEGA_ps2_disasm", "9a83e6afd4e0592a310392fde9c0d43724c7485a",
            "Phantasy Star II", "phantasy-star", "ps2.asm", variant="ps2",
            identity=Identity("GM 00005501-02", 0x3792, "UE", 0xC0000), repository_rom="ps2original.bin"),
    *(Profile(f"phantasy-star-3-{suffix}", "ps3disasm", "b9b7d609ea6bafdee832bb0d574175fb3fe0a7f5",
              "Phantasy Star III", "phantasy-star", "ps3.asm", variant="ps3", identity=identity,
              overrides=_ps3(revision))
      for suffix, revision, identity in (
          ("j", 0, Identity("GM 5503-00", 0x19D2, "J", 0xC0000)),
          ("ue", 1, Identity("GM 1303-01", 0x3A33, "UE", 0xC0000)),
          ("b", 2, Identity("GM MK-1303 -00", 0x983B, "F", 0xC0000)))),
    *(Profile(f"phantasy-star-4-{suffix}", "ps4disasm", "8a658314850904c6888969f90177779845133a7e",
              "Phantasy Star IV", "phantasy-star", "ps4.asm", variant="ps4", identity=identity,
              overrides=_ps4(revision))
      for suffix, revision, identity in (
          ("j", 0, Identity("GM G-5524  -00", 0x7667, "J", 0x300000)),
          ("us", 1, Identity("GM MK-1307 -00", 0x05CB, "4", 0x300000)))),
    Profile("aerobiz-supersonic-us", "aerobiz-disasm", "9dcbfb68c9c4148882242773dd3782e470ae9fb7",
            "Aerobiz Supersonic", "vasm", "disasm/aerobiz.asm",
            identity=Identity("GM T-76136 -00", 0x4620, "U", 0x100000),
            notes=("tools/vasmm68k_mot upstream is a symlink outside the repository; pass --vasm.",)),
    Profile("toejam-earl-rev02", "tje-disasm", "cd85d2e6e4f3256e0ab3f5328de1fea63b80ae75",
            "ToeJam & Earl", "unsupported",
            reason=("Upstream builds with m68k-linux-gnu gcc/cpp/objcopy, z80-unknown-coff binutils, a pygame "
                    "resource extractor and src/genesis.ld. This batch has no GNU as listing reader "
                    "or linker-map address model, so no instruction reference can be proven.")),
    Profile("shining-force-cd", "SFCDDISASM", "a38205770212ec83c6e216de52ca89a841f892c6",
            "Shining Force CD", "unsupported",
            reason=("Sega CD ISO, not a cartridge. The source covers only the ISO system area; both CPU "
                    "initial programs and all files are incbin from a split of the MK-4656 disc. A "
                    "Japanese disc is a different release and is never compared against it.")),
)}
# Known ToeJam & Earl revisions, from the upstream README (SHA-1).
TJE_SHA1 = {"85e8d0a4fac591b25b77c35680ac4175976f251b": "REV02 (upstream target)",
            "7f82d8b57fff88bdca5d8aff85b01e231dc1239a": "REV00 (not targeted upstream)"}


# ---------------------------------------------------------------------------
# Build steps


def run_step(command: list[str] | str, cwd: Path, log: Path, *, env: dict | None = None,
             timeout: int = 1800) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as stream:
        result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                                env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"build step failed ({result.returncode}): {log}")


def require(*paths: Path) -> None:
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"missing upstream file or tool: {missing}")


def as_environment(messages: Path) -> dict:
    return {**os.environ, "AS_MSGPATH": str(messages), "USEANSI": "n"}


def assemble_sn(assembler: Path, root: Path, source: Path, output: Path, switches: str,
                timeout: int) -> Path:
    """SN ASM68K parses its own command line; keep comma syntax and short relative paths."""
    files = [os.path.relpath(path, root).replace("\\", "/")
             for path in (source, output, output.with_suffix(".lst"))]
    output.unlink(missing_ok=True)
    log = output.with_suffix(".assembly.log")
    run_step(f'"{assembler}" {switches} "{files[0]}","{files[1]}",,"{files[2]}"', root, log, timeout=timeout)
    if not output.is_file() or not re.search(r"\b0 error\(s\)", log.read_text(errors="replace")):
        raise RuntimeError(f"ASM68K failed: {log}")
    return output


def export_unified(root: Path, entry: str, output: Path, definitions: dict, record: dict) -> None:
    """Flatten text includes. Undecodable UTF-8 falls back to byte-preserving Latin-1;
    the reference rebuild then proves the re-encoded text still assembles identically."""
    try:
        record.update(export(root, entry, output, definitions))
        record["source_encoding"] = "utf-8-sig"
    except UnicodeDecodeError:
        record.update(export(root, entry, output, definitions, encoding="latin-1"))
        record["source_encoding"] = "latin-1 (UTF-8 decode failed)"
        # Legacy AS interprets character literals as bytes (e.g. CHARSET).
        # Preserve their encoding, not just the appearance of comments.
        output.write_bytes(output.read_text(encoding="utf-8").encode("latin-1"))
        record["source_sha256"] = sha256(output)
        record["output_encoding"] = "latin-1"


@dataclass
class Build:
    upstream: Path
    reference: Path
    listing: Path
    listing_kind: str
    tools: list[Path]


@dataclass
class Context:
    refs: Path
    checkout: Path
    root: Path
    dest: Path
    pool: list[Candidate]
    settings: dict
    record: dict

    @property
    def timeout(self) -> int:
        return int(self.settings.get("timeout", 1800))


def build_landstalker(profile: Profile, ctx: Context) -> Build:
    root, dest = ctx.root, ctx.dest
    build = landstalker_build(root, profile.variant)
    asm68k = root / "tools/build/asm68k.exe"
    asw, p2bin = root / "tools/build/asw/asw.exe", root / "tools/build/asw/p2bin.exe"
    fixer = root / "tools/build/fix_checksum.py"
    require(asm68k, asw, p2bin, fixer)
    env = as_environment(asw.parent)
    expanded = build["defines"]["EXPANDED"]
    # build.bat: two Z80 sound banks and the Cube driver, then the M68K ROM.
    for source, obj, binary, limits in (("code/audio/soundbank3.asm", "soundbank3.p", "soundbank3.bin", "0x8000-0xdfff"),
                                        ("code/audio/soundbank4.asm", "soundbank4.p", "soundbank4.bin", "0x8000-0xffff"),
                                        ("code/audio/main.asm", "cube.p", "cube.bin", "0x0000-0x1f7f")):
        run_step([str(asw), source, "-o", obj, "-D", f"EXPANDED={expanded}"], root,
                 dest / f"{Path(binary).stem}.assembly.log", env=env, timeout=ctx.timeout)
        run_step([str(p2bin), obj, binary, "-l", "0xff", "-r", limits, "-k"], root,
                 dest / f"{Path(binary).stem}.conversion.log", env=env, timeout=ctx.timeout)
    ctx.record.update(build_yaml=build, asset_preparation="upstream Z80 banks and driver built with bundled AS")
    export_unified(root, build["source"], dest / "main.s", build["defines"], ctx.record)
    wrapper = dest / "upstream-options.s"
    wrapper.write_text("".join(f"{key} equ {value}\n" for key, value in build["defines"].items())
                       + f' include "{build["source"]}"\n', encoding="utf-8")
    assemble_sn(asm68k, root, wrapper, dest / "upstream.bin", build["buildopts"], ctx.timeout)
    # m+ only expands macro bodies in the listing; byte identity with upstream.bin proves it.
    assemble_sn(asm68k, root, dest / "main.s", dest / "reference.bin", f"{build['buildopts']},m+", ctx.timeout)
    for binary in (dest / "upstream.bin", dest / "reference.bin"):
        run_step([sys.executable, str(fixer), str(binary)], root, binary.with_suffix(".header.log"), timeout=ctx.timeout)
    return Build(dest / "upstream.bin", dest / "reference.bin", dest / "reference.lst", "sn", [asm68k, asw, p2bin, fixer])


def build_sitd(profile: Profile, ctx: Context) -> Build:
    checkout, root, dest = ctx.checkout, ctx.root, ctx.dest
    asm68k, splitter, fixer = checkout / "tools/ASM68K.EXE", checkout / "tools/splitrom.exe", checkout / "tools/fixheader.exe"
    require(asm68k, splitter, fixer, checkout / "split/sitdsplits.txt")
    original = select_split_input(ctx.pool, profile.identity)
    ctx.record["split_input"] = original.summary()
    run_step([str(splitter), original.path, str(checkout / "split/sitdsplits.txt")], root, dest / "split.log",
             timeout=ctx.timeout)
    ctx.record["asset_preparation"] = "upstream split/sitdsplits.txt from the selected original"
    export_unified(root, profile.entry, dest / "main.s", {}, ctx.record)
    tools = [asm68k, splitter, fixer]
    if "musicbank.bin" in (dest / "main.s").read_text(encoding="utf-8"):
        # build.bat also assembles the Z80 music bank; only needed if the ROM includes it.
        asw, p2bin = checkout / "tools/asw/asw.exe", checkout / "tools/asw/p2bin.exe"
        require(asw, p2bin)
        bank = root / "data/sound/musicbank"
        run_step([str(asw), "-x", "-E", "errors.log", "musicbank.asm"], bank, dest / "musicbank.assembly.log",
                 env=as_environment(asw.parent), timeout=ctx.timeout)
        run_step([str(p2bin), "musicbank.p", "../musicbank.bin", "-k", "-r", "$8000-$dfff"], bank,
                 dest / "musicbank.conversion.log", env=as_environment(asw.parent), timeout=ctx.timeout)
        tools += [asw, p2bin]
    else:
        ctx.record["z80_music_bank"] = "build.bat assembles it, but sitd.asm does not include musicbank.bin"
    for source, output in ((root / profile.entry, dest / "upstream.bin"), (dest / "main.s", dest / "reference.bin")):
        assemble_sn(asm68k, root, source, output, "/k /m /o ae- /p", ctx.timeout)
        run_step([str(fixer), str(output)], root, output.with_suffix(".header.log"), timeout=ctx.timeout)
    return Build(dest / "upstream.bin", dest / "reference.bin", dest / "reference.lst", "sn", tools)


def build_phantasy_star(profile: Profile, ctx: Context) -> Build:
    root, dest, game = ctx.root, ctx.dest, profile.variant
    asw, p2bin, fixer = root / "AS/win32/asw.exe", root / f"AS/win32/{game}p2bin.exe", root / "fixheader.exe"
    require(asw, p2bin, fixer)
    env = as_environment(root / "AS/win32")
    export_unified(root, profile.entry, dest / "main.s", {}, ctx.record)
    for source, output in ((root / profile.entry, dest / "upstream.bin"), (dest / "main.s", dest / "reference.bin")):
        obj = output.with_suffix(".p")
        errors = source.with_suffix(".log")
        for stale in (obj, output, errors, root / errors.name, source.with_suffix(".h"), source.with_suffix(".lst")):
            stale.unlink(missing_ok=True)
        # build.bat: asw -xx -c -E -A -L, <game>p2bin <p> <bin> <h>, fixheader.
        run_step([str(asw), "-xx", "-c", "-E", "-A", "-L", "-o", str(obj), str(source)], root,
                 output.with_suffix(".assembly.log"), env=env, timeout=ctx.timeout)
        for log in {errors, root / errors.name}:
            if log.is_file() and log.stat().st_size:
                raise RuntimeError(f"AS reported errors or warnings: {log}")
        require(obj)
        run_step([str(p2bin), str(obj), str(output), str(source.with_suffix(".h"))], root,
                 output.with_suffix(".conversion.log"), env=env, timeout=ctx.timeout)
        require(output)
        shutil.copy2(source.with_suffix(".lst"), output.with_suffix(".lst"))
        run_step([str(fixer), str(output)], root, output.with_suffix(".header.log"), timeout=ctx.timeout)
    return Build(dest / "upstream.bin", dest / "reference.bin", dest / "reference.lst", "as", [asw, p2bin, fixer])


class Kens:
    """The KENS compressors bundled with quackshot_src, called as assemble.py does."""

    def __init__(self, directory: Path):
        if os.name != "nt":
            raise ValueError("KENS compressors are Windows DLLs; run on Windows")
        self.suffix = "_x64" if platform.architecture()[0] == "64bit" else "_x86"
        self.directory = directory

    def compress(self, kind: str, source: Path, target: Path) -> None:
        library = self.directory / f"{kind}{self.suffix}.dll"
        require(library, source)
        # A bundled native compressor can exit() the host process. Keep failures
        # isolated so the corpus records a blocked profile and continues.
        script = """import ctypes, sys
function = ctypes.CDLL(sys.argv[1]).Comp
function.restype = ctypes.c_long
function.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
arguments = [sys.argv[2].encode('mbcs'), sys.argv[3].encode('mbcs')]
if sys.argv[4] != 'Nemesis':
    function.argtypes.append(ctypes.c_bool)
    arguments.append(False)
sys.exit(0 if function(*arguments) == 0 else 1)
"""
        target.unlink(missing_ok=True)
        child = subprocess.run([sys.executable, "-c", script, str(library), str(source), str(target), kind],
                               capture_output=True, timeout=120)
        if child.returncode != 0 or not target.is_file():
            raise RuntimeError(f"KENS {kind} compression failed (exit {child.returncode:#x}): {source}")


def nemesis_cli_compress(tool: Path, source: Path, target: Path) -> None:
    """Optional clownnemesis CLI; prove decompression before using the asset."""
    require(tool, source)
    target.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="nemesis-check-", dir=target.parent) as directory:
        restored = Path(directory) / "restored.bin"
        for command in ([str(tool), "-ca", str(source), str(target)],
                        [str(tool), "-d", str(target), str(restored)]):
            result = subprocess.run(command, capture_output=True, timeout=120)
            if result.returncode:
                raise RuntimeError(f"Nemesis CLI failed ({result.returncode}): {source}")
        if not restored.is_file() or restored.read_bytes() != source.read_bytes():
            raise RuntimeError(f"Nemesis CLI round-trip mismatch: {source}")


def quackshot_name(text: str, table: dict[str, int]) -> bytes:
    """level_names.py txt2bin: UTF-8 text to tile words, unknown characters as spaces."""
    return b"".join(struct.pack(">H", 0x2000 + table.get(char, table[" "]))
                    for char in text.rstrip("\r\n"))


def quackshot_font_table(root: Path) -> dict[str, int]:
    """Read the FONT_A2I literal without executing upstream code."""
    tree = ast.parse((root / "font_chars.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(target, "id", None) == "FONT_A2I" for target in node.targets):
            return dict(ast.literal_eval(node.value))
    raise ValueError("font_chars.py has no FONT_A2I table")


def build_quackshot(profile: Profile, ctx: Context) -> Build:
    root, dest = ctx.root, ctx.dest
    toolchain = Path(ctx.settings.get("quackshot_as") or ctx.refs / "SITDDISASM/tools/asw")
    asw, p2bin = toolchain / "asw.exe", toolchain / "p2bin.exe"
    require(asw, p2bin)
    env = as_environment(toolchain)
    kens = Kens(root / "kens")
    nemesis_tool = ctx.settings.get("nemesis_tool")

    def nemesis(source, target):
        if nemesis_tool:
            nemesis_cli_compress(Path(nemesis_tool), source, target)
        else:
            kens.compress("Nemesis", source, target)
    before = {path: sha256(root / path) for path in ("src/levels/kosinski_params.bin",) if (root / path).is_file()}
    # assemble.py order: level params, enemy tiles, font, level names, dialogs, main.
    def kosinski_unit(directory: str, stem: str) -> None:
        cwd = root / directory
        run_step([str(asw), "-maxerrors", "2", f"{stem}_dec.s"], cwd, dest / f"{stem}.assembly.log",
                 env=env, timeout=ctx.timeout)
        run_step([str(p2bin), f"{stem}_dec.p", f"{stem}_dec.bin"], cwd, dest / f"{stem}.conversion.log",
                 env=env, timeout=ctx.timeout)
        kens.compress("Kosinski", cwd / f"{stem}_dec.bin", cwd / f"{stem}.bin")
    kosinski_unit("src/levels", "kosinski_params")
    for enemy in sorted(path for path in (root / "src/enemies").iterdir() if path.is_dir()):
        if (enemy / "nemesis_tiles_dec.bin").is_file():
            nemesis(enemy / "nemesis_tiles_dec.bin", enemy / "nemesis_tiles.bin")
    nemesis(root / "src/fonts/nemesis_main_dec.bin", root / "src/fonts/nemesis_main.bin")
    table = quackshot_font_table(root)
    levels = root / "src/levels"
    names = [levels / name / "name" for name in sorted(os.listdir(levels))
             if (levels / name).is_dir() and "00" <= name[:2] <= "99" and name[2:3] == "_"]
    names += [root / "src/main_menu/room1_name", root / "src/main_menu/room2_name"]
    for stem in names:
        stem.with_suffix(".bin").write_bytes(
            quackshot_name(stem.with_suffix(".txt").read_bytes().decode("utf-8"), table))
    kosinski_unit("src/dialogs", "kosinski_dialogs")
    ctx.record["asset_preparation"] = ("assemble.py steps reimplemented for Python 3: AS sub-units, bundled KENS "
                                       "Kosinski DLL, level_names txt2bin; Nemesis via "
                                       + ("explicit clownnemesis CLI (-ca), all assets round-trip checked"
                                          if nemesis_tool else "bundled KENS DLL"))
    ctx.record["regenerated_tracked_files"] = {
        path: {"before": digest, "after": sha256(root / path)} for path, digest in before.items()}
    export_unified(root, profile.entry, dest / "main.s", {}, ctx.record)
    for source, output in ((root / profile.entry, dest / "upstream.bin"), (dest / "main.s", dest / "reference.bin")):
        obj = output.with_suffix(".p")
        obj.unlink(missing_ok=True)
        source.with_suffix(".lst").unlink(missing_ok=True)
        run_step([str(asw), "-maxerrors", "2", "-L", "-i", ".", "-o", str(obj), str(source)], root,
                 output.with_suffix(".assembly.log"), env=env, timeout=ctx.timeout)
        require(obj)
        run_step([str(p2bin), str(obj), str(output)], root, output.with_suffix(".conversion.log"),
                 env=env, timeout=ctx.timeout)
        require(output)
        shutil.copy2(source.with_suffix(".lst"), output.with_suffix(".lst"))
    return Build(dest / "upstream.bin", dest / "reference.bin", dest / "reference.lst", "as",
                 [asw, p2bin, *([Path(nemesis_tool)] if nemesis_tool else []),
                  *sorted((root / "kens").glob(f"*{kens.suffix}.dll"))])


def vasm_absolute_pc_labels(text: str) -> tuple[str, int]:
    """Retain upstream's absolute PC targets using a relocatable ROM-base label.

    vasm treats a numeric PC operand as a displacement. This source dialect
    instead prints the absolute target. No ROM bytes participate in translation.
    """
    pattern = re.compile(r"(\$[0-9a-f]+)(\s*\(\s*pc\s*[,\)])", re.IGNORECASE)
    lines, count = [], 0
    for line in text.splitlines(keepends=True):
        code, separator, comment = line.partition(";")
        changed = 0
        if _vasm_statement(code)[1].split(".", 1)[0] in M68K:
            code, changed = pattern.subn(r"(__rl_rom_base+\1)\2", code)
        count += changed
        lines.append(code + separator + comment)
    return "".join(lines), count


def build_vasm(profile: Profile, ctx: Context) -> Build:
    root, dest = ctx.root, ctx.dest
    vasm = ctx.settings.get("vasm")
    if not vasm:
        raise ValueError("upstream tools/vasmm68k_mot is a symlink outside the repository; pass --vasm PATH")
    vasm = Path(vasm)
    require(vasm)
    flags = ["-Fbin", "-m68000", "-no-opt", "-spaces", "-quiet"]  # Makefile ASMFLAGS
    export_unified(root, profile.entry, dest / "main.s", {}, ctx.record)
    # Keep the original checkout untouched. Assemble its include tree through
    # the same documented syntax adapter used for the flattened source.
    compatible = dest / "upstream-vasm"
    shutil.copytree(root / "disasm", compatible / "disasm", dirs_exist_ok=True)
    changes = {}
    for source in (compatible / "disasm").rglob("*.asm"):
        translated, count = vasm_absolute_pc_labels(source.read_text(encoding="utf-8"))
        if count:
            source.write_text(translated, encoding="utf-8", newline="\n")
            changes[source.relative_to(compatible).as_posix()] = count
    entry = compatible / profile.entry
    entry.write_text("__rl_rom_base:\n" + entry.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    main = dest / "main.s"
    translated, count = vasm_absolute_pc_labels(main.read_text(encoding="utf-8"))
    main.write_text("__rl_rom_base:\n" + translated, encoding="utf-8", newline="\n")
    mapping_path = main.with_suffix(".source-map.json")
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    for item in mapping:
        item["start_line"] += 1
        item["end_line"] += 1
    mapping_path.write_text(json.dumps(mapping, indent=2) + "\n", encoding="utf-8", newline="\n")
    ctx.record["lines"] += 1
    ctx.record.update(source_sha256=sha256(main), assembler_compatibility={
        "kind": "numeric absolute PC targets expressed relative to ROM-base label",
        "upstream_files": changes, "flattened_operands": count,
        "rom_bytes_used_in_translation": False})
    for output in (dest / "upstream.bin", dest / "reference.bin"):
        output.unlink(missing_ok=True)
    run_step([str(vasm), *flags, "-o", str(dest / "upstream.bin"), profile.entry], compatible,
             dest / "upstream.assembly.log", timeout=ctx.timeout)
    run_step([str(vasm), *flags, "-L", str(dest / "reference.vasm.lst"), "-o", str(dest / "reference.bin"),
              str(dest / "main.s")], root, dest / "reference.assembly.log", timeout=ctx.timeout)
    require(dest / "upstream.bin", dest / "reference.bin", dest / "reference.vasm.lst")
    return Build(dest / "upstream.bin", dest / "reference.bin", dest / "reference.vasm.lst", "vasm", [vasm])


def build_quackshot_restored(profile: Profile, ctx: Context) -> Build:
    # Import at execution time: the standalone evaluation adapter reuses the
    # header and assembler helpers in this module, not the ROM analyzer.
    from prepare_quackshot_reference import PLAN, assemble, prepare

    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    originals = [item for item in ctx.pool if item.sha256 == plan["rom_sha256"]]
    if not originals:
        raise ValueError("QuackShot restoration requires the hash-pinned retail REV01 ROM")
    tools = Path(ctx.settings.get("quackshot_as") or ctx.refs / "SITDDISASM/tools/asw")
    prepared = prepare(ctx.checkout, Path(originals[0].path), ctx.dest / "restoration", tools, ctx.timeout)
    stage = Path(prepared["asset_root"])
    export_unified(stage, profile.entry, ctx.dest / "main.s", {}, ctx.record)
    upstream = ctx.dest / "upstream.bin"
    shutil.copy2(prepared["upstream_binary"], upstream)
    listing = assemble(ctx.dest / "main.s", ctx.dest / "reference.bin", stage, tools, ctx.timeout)
    for key in ("restoration_plan", "restoration_plan_sha256", "restored_split_listing"):
        ctx.record[key] = prepared[key]
    ctx.record["asset_preparation"] = "Original binary includes extracted using the pinned retail layout; no recompression"
    shutil.copy2(Path(prepared["source"]).parent / "asset-provenance.json", ctx.dest / "asset-provenance.json")
    return Build(upstream, ctx.dest / "reference.bin", listing, "as", [tools / "asw.exe", tools / "p2bin.exe"])


FAMILIES = {"landstalker": build_landstalker, "sitd": build_sitd, "phantasy-star": build_phantasy_star,
            "quackshot": build_quackshot, "quackshot-restored": build_quackshot_restored, "vasm": build_vasm}


# ---------------------------------------------------------------------------
# vasm listings


VASM_SOURCE = re.compile(r"^F(\d+):(\d+)(.*)$")
VASM_BYTES = re.compile(r"^\s+S(\d+):([0-9A-Fa-f]{8}):\s+((?:[0-9A-Fa-f]{2}\s*)+)$")
VASM_DIRECTIVES = {"dc", "ds", "dcb", "blk", "include", "incbin", "equ", "set", "org", "even", "cnop", "align",
                   "section", "rept", "endr", "macro", "endm", "if", "ifd", "ifnd", "ifeq", "ifne", "else",
                   "endif", "end", "rs", "rsreset", "rsset", "xdef", "xref", "public", "opt", "list", "nolist"}


def _vasm_statement(text: str) -> tuple[str | None, str, str]:
    code = text.split(";", 1)[0]
    if code.lstrip().startswith("*"):
        return None, "", ""
    tokens = code.split(None, 2)
    known = lambda token: token.split(".", 1)[0].lower() in M68K | VASM_DIRECTIVES
    label = None
    if tokens and tokens[0].endswith(":"):
        label = tokens[0][:-1]
        tokens = code.split(None, 3)[1:]
    elif len(tokens) > 1 and not known(tokens[0]) and known(tokens[1]):
        label = tokens[0]
        tokens = tokens[1:]
    if not tokens:
        return label, "", ""
    return label, tokens[0].lower(), " ".join(tokens[1:])


def write_normalised_listing(found: dict[int, bytes], sources: dict[int, str], labels: dict[int, str],
                             boundaries: set[int], rom: bytes, output: Path) -> None:
    """Write the common AS-style listing read by source_benchmark.read_listing."""
    interiors = bytearray(len(rom))
    for address, raw in found.items():
        interiors[address + 1:address + len(raw)] = b"\x01" * (len(raw) - 1)
        boundaries.add(address + len(raw))
    rows = []
    for address in sorted(boundaries | found.keys() | labels.keys()):
        if not 0 <= address < len(rom) - 1:
            continue
        if address in labels:
            rows.append(f"{len(rows) + 1:8d}/{address:8X} : {'':21}{labels[address]}:")
        if address not in found and (address not in boundaries or interiors[address]):
            continue
        raw, source = (found[address], sources[address]) if address in found else (
            rom[address:address + 2], f" dc.w ${int.from_bytes(rom[address:address + 2], 'big'):04X} ; listing boundary")
        encoded = " ".join(raw[i:i + 2].hex().upper() for i in range(0, min(len(raw), 6), 2))
        rows.append(f"{len(rows) + 1:8d}/{address:8X} : {encoded:<21}{source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")


def normalise_vasm_listing(listing: Path, rom: bytes, output: Path) -> tuple[dict[int, bytes], frozenset[int], dict]:
    """Read vasm's default inline listing or Fnn/Snn source/byte rows.

    Every statement's bytes must be contiguous and equal the proven ROM.
    Only one section is accepted: -Fbin concatenates sections, and a
    section-relative address would otherwise be misread as a ROM offset.
    """
    statements: list[dict] = []
    for line in listing.read_text(encoding="utf-8", errors="replace").splitlines():
        # Default vasm listing: section:address hexbytes TAB line: source,
        # followed by section:address hexbytes continuation rows.
        column, tab, source_text = line.partition("\t")
        numbered = re.fullmatch(r"\s*\d+: ?(.*)", source_text) if tab else None
        if numbered:
            statements.append({"text": numbered[1], "chunks": []})
        inline = re.fullmatch(r"([0-9a-fA-F]{2}):([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*", column)
        if inline and statements:
            statements[-1]["chunks"].append((int(inline[1], 16), int(inline[2], 16), bytes.fromhex(inline[3])))
        if numbered or inline:
            continue
        source = VASM_SOURCE.match(line)
        if source:
            statements.append({"text": source[3], "chunks": []})
            continue
        chunk = VASM_BYTES.match(line)
        if chunk and statements:
            statements[-1]["chunks"].append((int(chunk[1]), int(chunk[2], 16), bytes.fromhex("".join(chunk[3].split()))))
    sections = {section for statement in statements for section, _, _ in statement["chunks"]}
    if len(sections) > 1:
        raise ValueError(f"vasm listing uses several sections {sorted(sections)}; no ROM mapping is defined")
    found: dict[int, bytes] = {}
    sources: dict[int, str] = {}
    labels: dict[int, str] = {}
    boundaries: set[int] = set()
    pending_labels: list[str] = []
    for statement in statements:
        label, operation, operands = _vasm_statement(statement["text"])
        if label:
            pending_labels.append(label)
        if not statement["chunks"]:
            continue
        start = statement["chunks"][0][1]
        raw = b""
        for _, address, data in statement["chunks"]:
            if address != start + len(raw):
                raise ValueError(f"non-contiguous vasm bytes in one statement at {address:#x}")
            raw += data
        if rom[start:start + len(raw)] != raw:
            raise ValueError(f"vasm listing disagrees with the proven ROM at {start:#x}")
        for name in pending_labels:
            labels.setdefault(start, name)
        pending_labels = []
        boundaries.update((start, start + len(raw)))
        if operation.split(".", 1)[0] in M68K:
            if len(raw) % 2 or not 2 <= len(raw) <= 10:
                raise ValueError(f"vasm instruction length {len(raw)} is impossible for 68000 at {start:#x}")
            if found.get(start, raw) != raw:
                raise ValueError(f"conflicting vasm instructions at {start:#x}")
            found[start] = raw
            sources[start] = f" {operation} {operands}".rstrip()
    if not found:
        raise ValueError("vasm listing contains no recognised M68K instructions (unsupported listing format?)")
    write_normalised_listing(found, sources, labels, boundaries, rom, output)
    return found, frozenset(), {"reference_instructions": len(found), "open_ended_lengths": 0,
                                "listing_format": "vasm", "unmapped_samples": []}


# ---------------------------------------------------------------------------
# Sega CD identity


SEGA_CD_SYNC = bytes.fromhex("00FFFFFFFFFFFFFFFFFFFF00")


def inspect_sega_cd_image(path: Path) -> dict:
    """Read the system-area identity of an ISO (2048) or raw (2352) Sega CD track."""
    with path.open("rb") as stream:
        head = stream.read(0x930)
    if head[:16] == b"SEGADISCSYSTEM  ":
        layout, base = "iso-2048", 0
    elif head[:12] == SEGA_CD_SYNC and head[0x10:0x20] == b"SEGADISCSYSTEM  ":
        layout, base = "raw-2352", 0x10
    else:
        raise ValueError("not a Sega CD data track (no SEGADISCSYSTEM system area)")
    text = lambda start, end: head[base + start:base + end].decode("latin-1").strip()
    return {"path": str(path), "layout": layout, "bytes": path.stat().st_size,
            "console": text(0x100, 0x110), "title": text(0x150, 0x180),
            "serial": text(0x180, 0x190), "region": text(0x1F0, 0x200)}


SFCD_IDENTITY = {"serial": "GM MK-4656 -00", "region": "E"}  # sfcdiso-01.asm system area


def sega_cd_applicability(image: dict) -> dict:
    same = all(image.get(key) == value for key, value in SFCD_IDENTITY.items())
    return {"disc_identity": image, "source_identity": SFCD_IDENTITY, "same_release": same,
            "comparison_valid": False,
            "reason": ("same system-area identity; a full ISO build and CD pipeline are still required"
                       if same else "different release; upstream offsets and incbin splits do not apply")}


# ---------------------------------------------------------------------------
# Driver


def prepare_profile(name: str, refs: Path, dest: Path, pool: list[Candidate], settings: dict) -> dict:
    profile = PROFILES[name]
    checkout = refs / profile.repository
    root = checkout / profile.subdir
    dest.mkdir(parents=True, exist_ok=True)
    record = {"name": name, "repository": profile.repository, "entry": profile.entry, "title": profile.title,
              "family": profile.family, "scope": SCOPE, "pinned_commit": profile.commit,
              "identity": ({**asdict(profile.identity), "checksum": f"${profile.identity.checksum:04X}"}
                           if profile.identity else None),
              "notes": list(profile.notes)}
    try:
        if profile.family == "unsupported":
            record.update(unsupported_details(profile, pool, settings))
            raise Unsupported(profile.reason)
        record["commit"] = _git(checkout, "rev-parse", "HEAD")
        record["url"] = _git(checkout, "remote", "get-url", "origin")
        if record["commit"] != profile.commit:
            raise ValueError(f"checkout is at {record['commit']}, profile is pinned to {profile.commit}")
        ctx = Context(refs, checkout, root, dest, pool, settings, record)
        with option_overrides(root, profile.overrides, checkout=checkout) as applied:
            if applied:
                record["source_overrides"] = applied
            built = FAMILIES[profile.family](profile, ctx)
        finish(profile, ctx, built)
    except Unsupported as exc:
        record.update(status="unsupported", error=str(exc))
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        record.update(status="blocked", error=str(exc))
    (dest / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def unsupported_details(profile: Profile, pool: list[Candidate], settings: dict) -> dict:
    details: dict = {}
    if profile.repository == "tje-disasm":
        details["supplied_revisions"] = [{**item.summary(), "upstream_readme_revision": TJE_SHA1[item.sha1]}
                                         for item in pool if item.sha1 in TJE_SHA1]
    if profile.repository == "SFCDDISASM":
        image = settings.get("sega_cd_image")
        if image:
            details["applicability"] = sega_cd_applicability(inspect_sega_cd_image(Path(image)))
        else:
            details["applicability"] = {"comparison_valid": False,
                                        "reason": "no Sega CD image supplied; the ROM inventory has none"}
    return details


def finish(profile: Profile, ctx: Context, built: Build) -> None:
    record, dest = ctx.record, ctx.dest
    digest = sha256(built.reference)
    record.update(upstream_binary=str(built.upstream), upstream_binary_sha256=sha256(built.upstream))
    if digest != record["upstream_binary_sha256"]:
        raise ValueError("flattened and upstream builds differ")
    binary = built.reference.read_bytes()
    header = read_header(binary)
    if profile.identity and profile.identity.differences(header):
        raise ValueError(f"assembled header disagrees with profile identity: {profile.identity.differences(header)}")
    record.update(binary=str(built.reference), binary_sha256=digest, binary_bytes=len(binary),
                  matches_upstream=True, header_checksum_valid=bool(header and header.checksum_valid))
    record.update(classify_build(binary, profile.identity, ctx.pool))
    if profile.repository_rom:
        record["matches_repository_rom"] = digest == sha256(ctx.root / profile.repository_rom)
    record["toolchain"] = [{"path": str(path), "sha256": sha256(path)} for path in built.tools]
    normalized = dest / "reference-m68k.lst"
    if built.listing_kind == "vasm":
        known, uncertain, provenance = normalise_vasm_listing(built.listing, binary, normalized)
    else:
        if built.listing != dest / "reference.lst":
            shutil.copy2(built.listing, dest / "reference.lst")
        known, uncertain, provenance = normalise_reference_listing(
            dest / "reference.lst", binary, normalized, sn=built.listing_kind == "sn")
    if not known:
        raise ValueError("reference listing contains no recognized M68K instructions")
    recovered, recovered_open = read_listing(normalized, binary)
    if recovered != known or recovered_open:
        raise ValueError("normalized listing does not round-trip complete instruction encodings")
    record.update(reference_instructions=len(known), uncertain_instruction_addresses=len(uncertain),
                  listing=str(normalized), listing_sha256=sha256(normalized), listing_provenance=provenance)
    if record["status"] == "original-mismatch":
        record["error"] = "assembled ROM differs from a supplied original with the same header identity"


def confirm_existing(dest: Path, pool: list[Candidate], roots: list[str]) -> dict:
    """Re-check an already prepared reference against newly supplied originals.

    Nothing is rebuilt: the stored reference.bin must still have the recorded
    hash, and a supplied ROM must be byte-identical to it.
    """
    record = json.loads((dest / "result.json").read_text(encoding="utf-8"))
    binary = dest / "reference.bin"
    if not binary.is_file() or sha256(binary) != record.get("binary_sha256"):
        raise ValueError(f"{binary} is missing or no longer has the recorded SHA-256")
    listing = dest / "reference-m68k.lst"
    if record.get("listing_sha256") and sha256(listing) != record["listing_sha256"]:
        raise ValueError(f"{listing} no longer has the recorded SHA-256")
    matches = [item.path for item in pool if item.sha256 == record["binary_sha256"]]
    record["independent_confirmation"] = {
        "method": "SHA-256 of the existing reference.bin against supplied originals; no rebuild",
        "rom_roots": roots, "matching_roms": matches}
    if matches:
        record["matching_original_roms"] = sorted(set(record.get("matching_original_roms", [])) | set(matches))
        record["status"] = "verified-original"
    (dest / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record
