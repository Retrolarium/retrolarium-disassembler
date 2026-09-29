"""Extract a Sega CD CHD into CUE/BIN tracks, a Mode 1 ISO, and disc files."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess


SYNC = b"\0" + b"\xFF" * 10 + b"\0"


def mode1_raw_to_iso(track: Path, output: Path) -> int:
    """Copy 2048 user bytes from each validated 2352-byte Mode 1 sector."""
    sectors = 0
    with track.open("rb") as source, output.open("wb") as target:
        while sector := source.read(2352):
            if len(sector) != 2352 or sector[:12] != SYNC or sector[15] != 1:
                raise ValueError(f"invalid Mode 1 sector {sectors} in {track}")
            target.write(sector[16:2064])
            sectors += 1
    if not sectors:
        raise ValueError("data track is empty")
    return sectors


def data_track_from_cue(cue: Path) -> Path:
    selected: Path | None = None
    for line in cue.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'^FILE\s+"([^"]+)"\s+BINARY', line.strip(), re.I)
        if match:
            selected = cue.parent / Path(match[1]).name
        if re.match(r"^TRACK\s+01\s+MODE1/2352$", line.strip(), re.I):
            if selected is None or not selected.is_file():
                raise ValueError("CUE data track file is missing")
            return selected
    raise ValueError("CUE has no first MODE1/2352 track")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("chd", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chdman", type=Path, help="path to MAME chdman.exe")
    parser.add_argument("--sevenzip", type=Path, help="path to 7z.exe")
    parser.add_argument("--force", action="store_true", help="replace a previous extraction")
    args = parser.parse_args()
    chd = args.chd.resolve()
    if not chd.is_file():
        parser.error(f"CHD not found: {chd}")
    chdman = args.chdman or Path(shutil.which("chdman") or "")
    if not chdman.is_file():
        parser.error("chdman not found; pass --chdman")
    sevenzip = args.sevenzip or Path(shutil.which("7z") or r"C:\Program Files\7-Zip\7z.exe")
    if not sevenzip.is_file():
        parser.error("7z not found; pass --sevenzip")
    output = args.output.resolve()
    cue = output / "disc.cue"
    iso = output / "disc.iso"
    if not args.force and (cue.exists() or iso.exists()):
        parser.error(f"extraction already exists in {output}; use --force to replace it")
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(chdman.resolve()), "verify", "-i", str(chd)], check=True)
    command = [str(chdman.resolve()), "extractcd", "-i", str(chd),
               "-o", str(cue), "-ob", str(output / "disc-track%t.bin"), "-sb"]
    if args.force:
        command.append("-f")
    subprocess.run(command, check=True)
    sectors = mode1_raw_to_iso(data_track_from_cue(cue), iso)
    files = output / "disc-files"
    files.mkdir(exist_ok=True)
    subprocess.run([str(sevenzip.resolve()), "x", "-y", f"-o{files}", str(iso)], check=True)
    print(f"Extracted {sectors} data sectors and {len(list(files.rglob('*')))} disc entries to {output}")


if __name__ == "__main__":
    main()
