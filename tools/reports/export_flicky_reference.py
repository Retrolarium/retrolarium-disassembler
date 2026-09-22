"""Place comparison-only Flicky source beside the generated ROM modules."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


LAYOUT_INCLUDE = re.compile(
    r'^\s*include\s+"([^"]+\.s)"\s*;\s*\$([0-9a-f]{6})-\$([0-9a-f]{6})\s*$',
    re.I,
)
SOURCE_INCLUDE = re.compile(r'^\s*include\s+"([^"]+\.s)"', re.I)
MODULE_STARTS = (0x200, 0x10000)
ROM_END = 0x1FFFF


def _source_lines(source_root: Path, relative: str, active: set[str]) -> list[str]:
    path = (source_root / relative).resolve()
    if not path.is_relative_to(source_root.resolve()) or not path.is_file():
        raise ValueError(f"missing or invalid source include: {relative}")
    if relative in active:
        raise ValueError(f"recursive source include: {relative}")
    active.add(relative)
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        nested = SOURCE_INCLUDE.match(line)
        if nested:
            child = nested.group(1)
            lines.append(f"; BEGIN src/{child}")
            lines.extend(_source_lines(source_root, child, active))
            lines.append(f"; END src/{child}")
        else:
            lines.append(line)
    active.remove(relative)
    return lines


def export_reference(reference: Path, generated: Path) -> tuple[Path, ...]:
    source_root = reference / "src"
    main = source_root / "main.s"
    layout: list[tuple[str, int, int]] = []
    for line in main.read_text(encoding="utf-8").splitlines():
        match = LAYOUT_INCLUDE.match(line)
        if match:
            layout.append((match.group(1), int(match.group(2), 16),
                           int(match.group(3), 16)))
    if not layout or layout[0][1] != 0 or layout[-1][2] != ROM_END:
        raise ValueError("Flicky source layout does not cover the expected ROM")
    for previous, current in zip(layout, layout[1:]):
        if previous[2] + 1 != current[1]:
            raise ValueError("Flicky source modules are not contiguous")

    grouped: dict[int, list[str]] = {start: [] for start in MODULE_STARTS}
    for relative, start, end in layout:
        if end < MODULE_STARTS[0]:
            continue
        module = max(address for address in MODULE_STARTS if address <= max(start, 0x200))
        next_start = next((address for address in MODULE_STARTS if address > module),
                          ROM_END + 1)
        if end >= next_start:
            raise ValueError(f"source include crosses a ROM module boundary: {relative}")
        lines = _source_lines(source_root, relative, set())
        if start < 0x200:
            if relative != "system/startup.s":
                raise ValueError("unexpected source before $000200")
            anchor = next((index for index, line in enumerate(lines)
                           if line.strip() == "Sys_ErrorTrap:"), None)
            if anchor is None:
                raise ValueError("missing $000200 source anchor Sys_ErrorTrap")
            lines = lines[anchor:]
        grouped[module].extend((f"; BEGIN src/{relative}", *lines,
                                f"; END src/{relative}", ""))

    output: list[Path] = []
    for start in MODULE_STARTS:
        rom_module = generated / "src" / f"rom-{start:06x}.s"
        if not rom_module.is_file():
            raise ValueError(f"missing generated ROM module: {rom_module}")
        path = rom_module.with_name(f"rom-{start:06x}.reference.s")
        next_start = next((address for address in MODULE_STARTS if address > start),
                          ROM_END + 1)
        content = [
            f"; Flicky reference source, ROM ${start:06X}-${next_start - 1:06X}",
            "; Comparison only: concatenated from flicky_src/src/main.s in ROM order.",
            "",
            *grouped[start],
        ]
        path.write_text("\n".join(content).rstrip() + "\n",
                        encoding="utf-8", newline="\n")
        output.append(path)
    return tuple(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    args = parser.parse_args()
    for path in export_reference(args.reference, args.generated):
        print(path)


if __name__ == "__main__":
    main()
