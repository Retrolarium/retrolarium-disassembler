"""Repack verified upstream archives as source-only processor bundles.

Only processor language text and its license/credits are retained. Test ROMs,
loaders, artwork, spreadsheets and executable build wrappers are excluded.
Input archives must match upstream size and SHA-256 recorded in the lock.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "src/retrolarium_disassembler/toolchains/disassembly.lock.json"
SUFFIXES = frozenset({".slaspec", ".sinc", ".cspec", ".ldefs", ".pspec", ".opinion", ".md"})


def package(source: Path, destination: Path, expected: dict) -> None:
    payload = source.read_bytes()
    if len(payload) != expected["size"] or hashlib.sha256(payload).hexdigest() != expected["sha256"]:
        raise ValueError(f"upstream archive does not match the lock: {source}")
    root = expected["source_directory"]
    with (
        zipfile.ZipFile(source) as incoming,
        zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as outgoing,
    ):
        for member in sorted(incoming.infolist(), key=lambda item: item.filename):
            path = PurePosixPath(member.filename)
            if member.is_dir() or ".." in path.parts or path.is_absolute():
                continue
            if path == PurePosixPath(root, "LICENSE") or (
                path.is_relative_to(PurePosixPath(root, "data/languages")) and path.suffix in SUFFIXES
            ):
                info = zipfile.ZipInfo(member.filename, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                outgoing.writestr(info, incoming.read(member), compresslevel=9)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, required=True)
    options = parser.parse_args()
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    folder = LOCK.parent / "backends"
    folder.mkdir(exist_ok=True)
    for key in ("snes_backend", "spc700_backend"):
        entry = lock[key]
        upstream = entry.get("upstream_archive") or {
            field: entry[field] for field in ("archive", "url", "size", "sha256", "source_directory")
        }
        destination = folder / (Path(upstream["archive"]).stem + "-languages.zip")
        package(options.archives / upstream["archive"], destination, upstream)
        entry["upstream_archive"] = upstream
        entry.update(
            archive=destination.name,
            url="package:toolchains/backends/" + destination.name,
            size=destination.stat().st_size,
            sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
        )
    LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
