"""Generate a standalone Flicky source comparison aligned by ROM address."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
from html import escape
import json
from pathlib import Path
import re


LISTING_LINE = re.compile(r"^(?:\(\d+\))?\s*\d+/\s*([0-9A-Fa-f]+)\s+: (.*)$")
LABEL = re.compile(r"^[A-Za-z_][\w.]*:\s*(.*)$")
DIRECTIVES = {"binclude", "dc", "ds", "equ", "org", "cpu", "page",
              "supmode", "padding", "align", "cnop", "set", "if", "else",
              "endif", "rept", "endr", "macro", "endm", "even", "db", "dw"}
ROM_NAME = "Flicky (UE) [!].bin"
EQUIVALENT_STATUSES = {
    "same-source",
    "same-instruction",
    "same-include",
    "same-data",
    "same-bytes",
}


@dataclass
class SourceAtAddress:
    lines: list[str] = field(default_factory=list)
    encoded: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BinaryInclude:
    start: int
    end: int
    path: str


def binary_includes(generated: Path) -> tuple[BinaryInclude, ...]:
    manifest = generated.parent / "retrolarium-project.json"
    if not manifest.is_file():
        return ()
    project = json.loads(manifest.read_text(encoding="utf-8"))
    items = project.get("assets", {}).get("items", [])
    includes = []
    for item in items:
        if item.get("emit") != "binclude":
            continue
        start = item.get("rom_file_offset")
        size = item.get("size")
        path = item.get("path")
        if not isinstance(start, int) or not isinstance(size, int) or not isinstance(path, str):
            continue
        if start < 0x200 or size <= 0:
            continue
        includes.append(BinaryInclude(start, start + size, path))
    return tuple(sorted(includes, key=lambda item: item.start))


def listing_source(path: Path) -> dict[int, SourceAtAddress]:
    if not path.is_file():
        raise ValueError(f"missing assembler listing: {path}")
    result: dict[int, SourceAtAddress] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = LISTING_LINE.match(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if not 0x200 <= address <= 0x1FFFF:
            continue
        payload = match.group(2)
        if len(payload) < 20:
            continue
        source = payload[20:].rstrip()
        code = source.strip()
        if not code or code.startswith(";") or code.lower().startswith("include "):
            continue
        record = result.setdefault(address, SourceAtAddress())
        record.lines.append(source)
        encoded = payload[:20].strip()
        if encoded and re.fullmatch(r"[0-9A-Fa-f ]+", encoded):
            record.encoded.append(encoded)
    return result


def _operation(lines: list[str]) -> str:
    operation = ""
    for line in lines:
        code = line.split(";", 1)[0].strip()
        label = LABEL.match(code)
        if label:
            code = label.group(1).strip()
        if code:
            # A listing address can contain location directives, aliases and
            # the byte-emitting statement.  The assembler prints that
            # statement last (for example: org, label, move), so it is the
            # operation that describes the encoded bytes at this address.
            operation = code.split(None, 1)[0].lower()
    return operation


def _encoded_bytes(record: SourceAtAddress) -> str:
    return re.sub(r"\s+", "", "".join(record.encoded)).lower()


def _same_instruction(
    reference: SourceAtAddress, generated: SourceAtAddress
) -> bool:
    original = _operation(reference.lines)
    produced = _operation(generated.lines)
    if not original or not produced:
        return False
    original_base = original.split(".", 1)[0]
    produced_base = produced.split(".", 1)[0]
    if original_base in DIRECTIVES or produced_base in DIRECTIVES:
        return False
    encoded = _encoded_bytes(reference)
    return (
        original_base == produced_base
        and bool(encoded)
        and encoded == _encoded_bytes(generated)
    )


def _data_or_label(record: SourceAtAddress) -> bool:
    operation = _operation(record.lines)
    return not operation or operation.split(".", 1)[0] in DIRECTIVES


def _directive_kind(operation: str) -> str | None:
    aliases = {
        "db": "dc.b",
        "dw": "dc.w",
    }
    operation = aliases.get(operation, operation)
    if operation.split(".", 1)[0] not in DIRECTIVES:
        return None
    return operation


def _status(reference: SourceAtAddress, generated: SourceAtAddress) -> str:
    if not reference.lines:
        return "generated-only"
    if not generated.lines:
        return "reference-only"
    normalized = lambda lines: tuple(re.sub(r"\s+", "", item.split(";", 1)[0]).lower()
                                     for item in lines)
    if normalized(reference.lines) == normalized(generated.lines):
        return "same-source"
    if _same_instruction(reference, generated):
        return "same-instruction"
    original = _operation(reference.lines)
    produced = _operation(generated.lines)
    if original.split(".", 1)[0] not in DIRECTIVES and produced in {"dc.b", "db"}:
        return "raw-fallback"
    original_directive = _directive_kind(original)
    produced_directive = _directive_kind(produced)
    if (
        original_directive is not None
        and produced_directive is not None
        and original_directive != produced_directive
    ):
        return "data-structure"
    return "same-bytes"


def _is_difference(status: str) -> bool:
    return status not in EQUIVALENT_STATUSES


def _cell(record: SourceAtAddress) -> str:
    if not record.lines:
        return '<span class="empty">—</span>'
    encoded = " / ".join(record.encoded)
    byte_line = f'<div class="bytes">{escape(encoded)}</div>' if encoded else ""
    return byte_line + "<pre>" + escape("\n".join(record.lines)) + "</pre>"


def write_html(
    reference: Path,
    generated: Path,
    output: Path,
    *,
    differences_only: bool = False,
) -> Counter[str]:
    reference_rom = (reference / ROM_NAME).read_bytes()
    generated_rom = (generated / "rebuilt.bin").read_bytes()
    if reference_rom != generated_rom:
        raise ValueError("reference and generated ROMs differ; build and verify first")
    original = listing_source(reference / "build" / "main.lst")
    produced = listing_source(generated / "build" / "retrolarium-main.lst")
    includes = binary_includes(generated)
    addresses = sorted(original.keys() | produced.keys())
    if not addresses:
        raise ValueError("no ROM source lines found in assembler listings")
    counts: Counter[str] = Counter()
    rows: list[str] = []
    visible_addresses: list[int] = []
    for address in addresses:
        ref = original.get(address, SourceAtAddress())
        gen = produced.get(address, SourceAtAddress())
        include = next(
            (item for item in includes if item.start <= address < item.end),
            None,
        )
        if include is not None and ref.lines and _data_or_label(ref):
            status = "same-include"
            if not gen.lines:
                relative = address - include.start
                gen = SourceAtAddress(
                    lines=[
                        f'; covered by binclude "{include.path}" + 0x{relative:X}'
                    ]
                )
        else:
            status = _status(ref, gen)
        if differences_only and not _is_difference(status):
            continue
        counts[status] += 1
        visible_addresses.append(address)
        rows.append(
            f'<tr id="a{address:06X}" class="{status}">'
            f'<th scope="row"><a href="#a{address:06X}">${address:06X}</a></th>'
            f'<td>{_cell(ref)}</td><td>{_cell(gen)}</td></tr>'
        )
    summary = " · ".join(f"{name}: {counts[key]}" for key, name in (
        ("same-source", "same text"),
        ("same-instruction", "same instruction"),
        ("same-include", "same data in a binclude"),
        ("same-data", "same ROM data"),
        ("same-bytes", "same bytes, different text"),
        ("data-structure", "different data structure"),
        ("raw-fallback", "instruction left as dc.b"),
        ("reference-only", "reference only"),
        ("generated-only", "kit only"),
    ))
    report_title = (
        "Flicky — source differences only"
        if differences_only
        else "Flicky — source comparison"
    )
    report_note = (
        "Only addresses with a different data structure, "
        "unrecognised instructions or a line on one side only are shown."
        if differences_only
        else "Every address of the listings is shown."
    )
    navigation = "".join(
        f'<a href="#a{target:06X}">{label}</a>'
        for start, end, label in (
            (0x200, 0x10000, "$000200–$00FFFF"),
            (0x10000, 0x20000, "$010000–$01FFFF"),
        )
        if (target := next(
            (address for address in visible_addresses if start <= address < end),
            None,
        )) is not None
    )
    page = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(report_title)}</title>
<style>
body{{margin:0;background:#f5f7fa;color:#17202a;font-family:system-ui,sans-serif}}
header{{position:sticky;top:0;z-index:2;background:white;padding:12px 18px;border-bottom:1px solid #ccd5df}}
h1{{font-size:20px;margin:0 0 6px}}p{{margin:5px 0}}nav,.controls{{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:8px}}
input,select,button{{font:inherit;padding:4px 7px}}main{{padding:12px 18px}}
table{{border-collapse:collapse;width:100%;table-layout:fixed;background:white}}
thead th{{position:sticky;top:142px;z-index:1;background:#e8eef5;text-align:left}}
th,td{{border:1px solid #d9e0e8;vertical-align:top;padding:5px 8px}}th:first-child{{width:90px}}
td{{width:calc((100% - 90px)/2);overflow-wrap:anywhere}}tbody tr:nth-child(even){{background:#fafbfd}}
tr.raw-fallback{{background:#fff0e4}}tr.reference-only{{background:#fcecec}}
tr.generated-only{{background:#e9f4ff}}
tr.same-source,tr.same-instruction,tr.same-include,tr.same-data,tr.same-bytes{{background:#eff9ed}}tr.data-structure{{background:#fff0d6}}tr:target{{outline:3px solid #2368bb;outline-offset:-3px}}
pre{{margin:0;font:12px/1.45 Consolas,'Courier New',monospace;white-space:pre-wrap;tab-size:4}}
.bytes{{color:#657283;font:11px/1.3 Consolas,monospace;margin-bottom:3px}}
.empty{{color:#8793a1}}.legend{{font-size:12px;color:#546273}}
</style></head><body>
<header><h1>{escape(report_title)}</h1>
<p class="legend">Reference: flicky_src · Kit: the generated project · both ROMs verified byte for byte. Aligned by the assembler listings; comments omitted. {escape(report_note)}</p>
<p class="legend">{escape(summary)}</p>
<nav>{navigation}</nav>
<div class="controls"><label>Show <select id="filter"><option value="all">everything</option><option value="changes">differences</option><option value="raw">dc.b instead of an instruction</option><option value="missing">a line on one side only</option></select></label>
<label>Address <input id="address" placeholder="010084" size="8" maxlength="6"></label><button id="jump">Go</button><span id="visible"></span></div></header>
<main><table><thead><tr><th>Address</th><th>Reference flicky_src</th><th>Retrolarium Kit</th></tr></thead><tbody>{chr(10).join(rows)}</tbody></table></main>
<script>
const rows=[...document.querySelectorAll('tbody tr')],filter=document.getElementById('filter'),visible=document.getElementById('visible');
function applyFilter(){{let count=0;for(const row of rows){{const show=filter.value==='all'||
  (filter.value==='changes'&&!row.classList.contains('same-source')&&!row.classList.contains('same-instruction')&&!row.classList.contains('same-include')&&!row.classList.contains('same-data')&&!row.classList.contains('same-bytes'))||
  (filter.value==='raw'&&row.classList.contains('raw-fallback'))||
  (filter.value==='missing'&&(row.classList.contains('reference-only')||row.classList.contains('generated-only')));
  row.hidden=!show;if(show)count++}}visible.textContent=`Lines: ${{count}}`}}
filter.addEventListener('change',applyFilter);
function jump(){{const address=document.getElementById('address').value.replace(/^\\$/,'').toUpperCase().padStart(6,'0');
  const row=document.getElementById('a'+address);if(row){{filter.value='all';applyFilter();row.scrollIntoView({{block:'center'}});location.hash=row.id}}}}
document.getElementById('jump').addEventListener('click',jump);
document.getElementById('address').addEventListener('keydown',e=>{{if(e.key==='Enter')jump()}});
applyFilter();
</script></body></html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8", newline="\n")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--differences-only",
        action="store_true",
        help="omit rows considered equivalent by the source comparator",
    )
    args = parser.parse_args()
    counts = write_html(
        args.reference,
        args.generated,
        args.output,
        differences_only=args.differences_only,
    )
    print(f"{args.output}: {sum(counts.values())} ROM addresses")


if __name__ == "__main__":
    main()
