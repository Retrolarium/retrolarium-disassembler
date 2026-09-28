"""Expand assembly source includes into one comparison-only text file."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


INCLUDE = re.compile(r'^\s*include\s+"([^"]+)"\s*(?:;.*)?$', re.I)


def flatten_source(reference: Path, entry: str) -> tuple[str, list[dict[str, object]]]:
    """Expand text includes in source order without evaluating assembler profiles."""
    root = reference.resolve()
    output: list[str] = []
    origins: list[dict[str, object]] = []
    active: set[Path] = set()

    def visit(relative: str, parent: Path | None = None) -> None:
        rooted = root / relative
        path = (rooted if rooted.is_file() or parent is None
                else parent / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"missing or unsafe source include: {relative}")
        if path in active:
            raise ValueError(f"recursive source include: {relative}")
        active.add(path)
        name = path.relative_to(root).as_posix()
        start = len(output) + 1
        raw = path.read_bytes()
        for line in raw.decode("utf-8-sig").splitlines():
            match = INCLUDE.match(line)
            if match:
                child = match.group(1).replace("\\", "/")
                candidate = root / child
                resolved = (candidate if candidate.is_file() else path.parent / child).resolve()
                child_name = resolved.relative_to(root).as_posix() if resolved.is_relative_to(root) else child
                output.append(f"; BEGIN {child_name}")
                visit(child, path.parent)
                output.append(f"; END {child_name}")
            else:
                output.append(line)
        origins.append({
            "path": name,
            "start_line": start,
            "end_line": len(output),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        active.remove(path)

    visit(entry)
    return "\n".join(output) + "\n", origins


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--entry", default="src/main.s")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--define", action="append", default=[], metavar="NAME=VALUE",
        help="define an assembler profile in the flattened file itself",
    )
    args = parser.parse_args()
    flattened, origins = flatten_source(args.reference, args.entry)
    definitions = []
    for assignment in args.define:
        match = re.fullmatch(r"([A-Za-z_][\w]*)=([^\r\n;]+)", assignment)
        if match is None:
            parser.error(f"invalid --define assignment: {assignment!r}")
        definitions.append(f"{match.group(1)} equ {match.group(2)}")
    if definitions:
        flattened = "\n".join(definitions) + "\n" + flattened
        for origin in origins:
            origin["start_line"] += len(definitions)
            origin["end_line"] += len(definitions)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(flattened, encoding="utf-8", newline="\n")
    source_map = output.with_suffix(".source-map.json")
    source_map.write_text(
        json.dumps(origins, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({
        "output": str(output),
        "source_map": str(source_map),
        "source_files": len(origins),
        "lines": len(flattened.splitlines()),
    }, indent=2))


if __name__ == "__main__":
    main()
