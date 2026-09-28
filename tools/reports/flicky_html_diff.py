"""Generate a standalone Mega Drive source comparison aligned by ROM address."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass, field
from html import escape
import json
from pathlib import Path
import re

from source_benchmark import read_listing


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


def listing_source(
    path: Path, *, max_address: int | None = None
) -> dict[int, SourceAtAddress]:
    if not path.is_file():
        raise ValueError(f"missing assembler listing: {path}")
    result: dict[int, SourceAtAddress] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = LISTING_LINE.match(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if address < 0 or (max_address is not None and address > max_address):
            continue
        payload = match.group(2)
        if len(payload) < 20:
            continue
        source = payload[20:].rstrip()
        code = source.strip()
        if not code or code.startswith(";") or code.lower().startswith("include "):
            continue
        label = LABEL.match(code.split(";", 1)[0])
        operation = _operation([source])
        # Assembler conditionals and equates have an address but emit no ROM
        # bytes. They must not replace the instruction at the same address.
        encoded = payload[:20].strip()
        has_bytes = bool(encoded and re.fullmatch(r"[0-9A-Fa-f ]+", encoded))
        if not has_bytes and operation not in {"binclude", "org"}:
            if label is None or operation:
                continue
        record = result.setdefault(address, SourceAtAddress())
        record.lines.append(source)
        if has_bytes:
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
    original_bytes = _encoded_bytes(reference)
    produced_bytes = _encoded_bytes(generated)
    if original_bytes and produced_bytes and original_bytes != produced_bytes:
        return "data-structure" if original_directive else "different-encoding"
    normalized = lambda lines: tuple(re.sub(r"\s+", "", item.split(";", 1)[0]).lower()
                                     for item in lines)
    if normalized(reference.lines) == normalized(generated.lines):
        return "same-source"
    if _same_instruction(reference, generated):
        return "same-instruction"
    if original_directive is None and produced_directive is None and original != produced:
        return "different-instruction"
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
    opcodes_only: bool = False,
    rom: Path | None = None,
    reference_listing: Path | None = None,
    generated_listing: Path | None = None,
    title: str = "Flicky",
) -> Counter[str]:
    reference_rom = (rom or reference / ROM_NAME).read_bytes()
    generated_rom = (generated / "rebuilt.bin").read_bytes()
    if reference_rom != generated_rom:
        raise ValueError("reference and generated ROMs differ; build and verify first")
    reference_listing = reference_listing or reference / "build" / "main.lst"
    generated_listing = generated_listing or generated / "build" / "retrolarium-main.lst"
    original = listing_source(reference_listing, max_address=len(reference_rom) - 1)
    produced = listing_source(generated_listing, max_address=len(reference_rom) - 1)
    # Replace six-byte listing prefixes with recovered complete instructions.
    instruction_addresses = []
    for records, listing in ((original, reference_listing), (produced, generated_listing)):
        instructions, _ = read_listing(listing, reference_rom)
        instruction_addresses.append(set(instructions))
        for address, raw in instructions.items():
            if address in records:
                records[address].encoded = [raw.hex(" ").upper()]
    includes = binary_includes(generated)
    include_starts = [item.start for item in includes]
    addresses = sorted(original.keys() | produced.keys())
    if not addresses:
        raise ValueError("no ROM source lines found in assembler listings")
    counts: Counter[str] = Counter()
    rows: list[str] = []
    visible_addresses: list[int] = []
    visible_statuses: list[str] = []
    opcode_addresses = instruction_addresses[0] | instruction_addresses[1]
    for address in addresses:
        if opcodes_only and address not in opcode_addresses:
            continue
        ref = original.get(address, SourceAtAddress())
        gen = produced.get(address, SourceAtAddress())
        include_index = bisect_right(include_starts, address) - 1
        include = includes[include_index] if include_index >= 0 else None
        if include is not None and address >= include.end:
            include = None
        if include is not None and ref.lines:
            status = "same-include" if _data_or_label(ref) else "code-in-include"
            if not gen.lines:
                relative = address - include.start
                gen = SourceAtAddress(
                    lines=[
                        f'; covered by binclude "{include.path}" + 0x{relative:X}'
                    ]
                )
        else:
            status = _status(ref, gen)
        if (opcodes_only and address in instruction_addresses[1]
                and address not in instruction_addresses[0]):
            # Same bytes do not make a mnemonic equivalent to reference data.
            status = "generated-only"
        if differences_only and not _is_difference(status):
            continue
        counts[status] += 1
        visible_addresses.append(address)
        visible_statuses.append(status)
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
        ("code-in-include", "code hidden in a binclude"),
        ("different-encoding", "different length or bytes"),
        ("different-instruction", "different instruction"),
        ("reference-only", "reference only"),
        ("generated-only", "kit only"),
    ))
    report_title = (
        f"{title} — source differences only"
        if differences_only
        else f"{title} — source comparison"
    )
    report_note = (
        "Only addresses with a different data structure, "
        "unrecognised instructions or a line on one side only are shown."
        if differences_only
        else "Every address of the listings is shown."
    )
    if opcodes_only:
        report_title += " — opcodes"
        report_note += " Lines with only data and labels are left out; extra instructions are shown."
    navigation = "".join(
        f'<a href="#a{target:06X}">{label}</a>'
        for start, end, label in (
            (start, min(start + 0x10000, len(reference_rom)),
             f"${start:06X}–${min(start + 0x10000, len(reference_rom)) - 1:06X}")
            for start in range(0, len(reference_rom), 0x10000)
        )
        if (target := next(
            (address for address in visible_addresses if start <= address < end),
            None,
        )) is not None
    )
    row_data = json.dumps(
        list(zip(visible_addresses, visible_statuses, rows)), ensure_ascii=False
    ).replace("<", "\\u003c")
    script = r"""
const records=JSON.parse(document.getElementById('row-data').textContent);
const filter=document.getElementById('filter'),visible=document.getElementById('visible');
const tbody=document.querySelector('tbody'),previous=document.getElementById('previous'),next=document.getElementById('next');
const pageSize=500;let active=records,page=0;
function showPage(){const start=page*pageSize;tbody.innerHTML=active.slice(start,start+pageSize).map(r=>r[2]).join('');
  previous.disabled=page===0;next.disabled=start+pageSize>=active.length;
  visible.textContent=`Lines: ${active.length}; showing ${active.length?start+1:0}–${Math.min(start+pageSize,active.length)}`}
function applyFilter(){active=records.filter(r=>filter.value==='all'||
  (filter.value==='changes'&&!r[1].startsWith('same-'))||
  (filter.value==='raw'&&['raw-fallback','code-in-include'].includes(r[1]))||
  (filter.value==='missing'&&['reference-only','generated-only'].includes(r[1])));page=0;showPage()}
filter.addEventListener('change',applyFilter);
previous.addEventListener('click',()=>{if(page>0){page--;showPage();document.querySelector('main').scrollIntoView()}});
next.addEventListener('click',()=>{if((page+1)*pageSize<active.length){page++;showPage();document.querySelector('main').scrollIntoView()}});
function goAddress(value){const address=parseInt(value.replace(/^\$/,''),16);if(!Number.isFinite(address)||!records.length)return;
  filter.value='all';active=records;let low=0,high=records.length;
  while(low<high){const mid=(low+high)>>1;if(records[mid][0]<address)low=mid+1;else high=mid}
  const index=Math.min(low,records.length-1);page=Math.floor(index/pageSize);showPage();
  const id='a'+records[index][0].toString(16).toUpperCase().padStart(6,'0'),row=document.getElementById(id);
  if(row){history.replaceState(null,'','#'+id);row.scrollIntoView({block:'center'})}}
document.getElementById('jump').addEventListener('click',()=>goAddress(document.getElementById('address').value));
document.getElementById('address').addEventListener('keydown',e=>{if(e.key==='Enter')goAddress(e.target.value)});
document.querySelector('nav').addEventListener('click',e=>{const link=e.target.closest('a');if(link){e.preventDefault();goAddress(link.hash.slice(2))}});
new ResizeObserver(entries=>document.documentElement.style.setProperty('--header-height',entries[0].target.offsetHeight+'px')).observe(document.querySelector('header'));
showPage();if(location.hash.startsWith('#a'))goAddress(location.hash.slice(2));
"""
    page = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(report_title)}</title>
<style>
body{{margin:0;background:#f5f7fa;color:#17202a;font-family:system-ui,sans-serif}}
header{{position:sticky;top:0;z-index:2;background:white;padding:12px 18px;border-bottom:1px solid #ccd5df}}
h1{{font-size:20px;margin:0 0 6px}}p{{margin:5px 0}}nav,.controls{{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:8px}}
input,select,button{{font:inherit;padding:4px 7px}}main{{padding:12px 18px}}
table{{border-collapse:collapse;width:100%;table-layout:fixed;background:white}}
thead th{{position:sticky;top:var(--header-height,142px);z-index:1;background:#e8eef5;text-align:left}}
th,td{{border:1px solid #d9e0e8;vertical-align:top;padding:5px 8px}}th:first-child{{width:90px}}
td{{width:calc((100% - 90px)/2);overflow-wrap:anywhere}}tbody tr:nth-child(even){{background:#fafbfd}}
tr.raw-fallback,tr.code-in-include{{background:#fff0e4}}tr.reference-only,tr.different-encoding,tr.different-instruction{{background:#fcecec}}
tr.generated-only{{background:#e9f4ff}}
tr.same-source,tr.same-instruction,tr.same-include,tr.same-data,tr.same-bytes{{background:#eff9ed}}tr.data-structure{{background:#fff0d6}}tr:target{{outline:3px solid #2368bb;outline-offset:-3px}}
pre{{margin:0;font:12px/1.45 Consolas,'Courier New',monospace;white-space:pre-wrap;tab-size:4}}
.bytes{{color:#657283;font:11px/1.3 Consolas,monospace;margin-bottom:3px}}
.empty{{color:#8793a1}}.legend{{font-size:12px;color:#546273}}
</style></head><body>
<header><h1>{escape(report_title)}</h1>
<p class="legend">Reference: {escape(reference.name)} · Kit: the generated project · both ROMs verified byte for byte. Aligned by the assembler listings. {escape(report_note)}</p>
<p class="legend">{escape(summary)}</p>
<nav>{navigation}</nav>
<div class="controls"><label>Show <select id="filter"><option value="all">everything</option><option value="changes">differences</option><option value="raw">undecoded code</option><option value="missing">a line on one side only</option></select></label>
<label>Address <input id="address" placeholder="01AA32" size="8" maxlength="6"></label><button id="jump">Go</button><button id="previous">← Back</button><button id="next">Next →</button><span id="visible"></span></div></header>
<main><table><thead><tr><th>Address</th><th>Reference {escape(reference.name)}</th><th>Retrolarium Kit</th></tr></thead><tbody>{chr(10).join(rows[:500])}</tbody></table></main>
<script type="application/json" id="row-data">{row_data}</script>
<script>{script}</script></body></html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8", newline="\n")
    return counts


def main(default_title: str = "Flicky") -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rom", type=Path, help="reference ROM (must match rebuilt.bin)")
    parser.add_argument("--reference-listing", type=Path)
    parser.add_argument("--generated-listing", type=Path)
    parser.add_argument("--title", default=default_title)
    parser.add_argument("--opcodes-only", action="store_true",
                        help="include only instruction addresses, retaining missing and extra code")
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
        opcodes_only=args.opcodes_only,
        rom=args.rom,
        reference_listing=args.reference_listing,
        generated_listing=args.generated_listing,
        title=args.title,
    )
    print(f"{args.output}: {sum(counts.values())} ROM addresses")


if __name__ == "__main__":
    main()
