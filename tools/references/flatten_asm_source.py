"""Expand assembly source includes into one comparison-only text file."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


INCLUDE = re.compile(
    r'''^\s*(?:(?P<label>[^\s:;"']+:)\s*)?include\s+'''
    r'''(?P<quote>["'])(?P<path>.*?)(?P=quote)\s*(?:;.*)?$''',
    re.I,
)


def flatten_source(
    reference: Path, entry: str, *, expand_include_macros: bool = False,
    encoding: str = "utf-8-sig",
) -> tuple[str, list[dict[str, object]]]:
    """Expand text includes in source order without evaluating assembler profiles."""
    root = reference.resolve()
    output: list[str] = []
    origins: list[dict[str, object]] = []
    active: set[Path] = set()
    include_macros: dict[str, tuple[str, list[str]]] = {}

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
        def emit(line: str) -> None:
            match = INCLUDE.match(line)
            if match:
                # Keep the label before the included body: it can establish the
                # scope of local labels or mark the start of a mapping/song.
                if match.group("label"):
                    output.append(match.group("label"))
                child = match.group("path").replace("\\", "/")
                candidate = root / child
                resolved = (candidate if candidate.is_file() else path.parent / child).resolve()
                child_name = resolved.relative_to(root).as_posix() if resolved.is_relative_to(root) else child
                output.append(f"; BEGIN {child_name}")
                visit(child, path.parent)
                output.append(f"; END {child_name}")
            else:
                output.append(line)

        lines = raw.decode(encoding).splitlines()
        index = 0
        while index < len(lines):
            line = lines[index]
            index += 1
            # A narrow, explicit macro form used for labelled include wrappers.
            # Leave general macro expansion and all conditionals to the assembler.
            declaration = re.match(
                r"^\s*(\w+)\s+macro\s+\{INTLABEL\}\s*,\s*(\w+)\s*(?:;.*)?$",
                line, re.I,
            ) if expand_include_macros else None
            if declaration:
                end = next((i for i in range(index, len(lines))
                            if re.match(r"^\s*endm\s*(?:;.*)?$", lines[i], re.I)), None)
                body = lines[index:end] if end is not None else []
                parameter = declaration[2]
                dynamic_include = re.compile(rf"^\s*include\s+{re.escape(parameter)}\s*(?:;.*)?$", re.I)
                if any(dynamic_include.match(item) for item in body):
                    if any(re.search(r"\bmacro\b", item.split(";", 1)[0], re.I) for item in body):
                        raise ValueError(f"nested include macro is unsupported: {declaration[1]}")
                    if any(re.search(rf"\b{re.escape(parameter)}\b", item.split(";", 1)[0])
                           and not dynamic_include.match(item) for item in body):
                        raise ValueError(f"include macro uses its parameter as code: {declaration[1]}")
                    include_macros[declaration[1].lower()] = (parameter, body)
                    output.append(f"; Inlined include wrapper: {declaration[1]}")
                    index = end + 1
                    continue
            invocation = re.match(
                r'''^\s*([\w.$]+):?\s+(\w+)\s+(["'])(.*?)\3\s*(?:;.*)?$''', line,
            ) if include_macros else None
            if invocation and invocation[2].lower() in include_macros:
                parameter, body = include_macros[invocation[2].lower()]
                output.append(f"; BEGIN {invocation[2]} {invocation[1]}")
                for item in body:
                    if re.match(rf"^\s*include\s+{re.escape(parameter)}\s*(?:;.*)?$", item, re.I):
                        emit(f' include "{invocation[4]}"')
                    else:
                        emit(item.replace("__LABEL__", invocation[1]))
                output.append(f"; END {invocation[2]} {invocation[1]}")
                continue
            # Refuse unknown arguments rather than silently removing their macro.
            if include_macros and re.search(
                r"\b(?:" + "|".join(map(re.escape, include_macros)) + r")\b", line.split(";", 1)[0], re.I,
            ):
                raise ValueError(f"unsupported include macro invocation: {line}")
            emit(line)
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
    parser.add_argument("--expand-include-macros", action="store_true",
                        help="inline {INTLABEL},path wrappers with literal include arguments")
    parser.add_argument(
        "--define", action="append", default=[], metavar="NAME=VALUE",
        help="define an assembler profile in the flattened file itself",
    )
    args = parser.parse_args()
    flattened, origins = flatten_source(args.reference, args.entry,
                                        expand_include_macros=args.expand_include_macros)
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
