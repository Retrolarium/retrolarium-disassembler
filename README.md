# Retrolarium Disassembler

Retrolarium Disassembler turns a ROM image into a complete, modular source
project that rebuilds byte for byte. The NES pipeline turns a profiled iNES
image into a ca65 project; mapper profiles describe the physical-to-logical
projections used for independent bank analysis and source emission. Analysis
runs headless Ghidra with pinned versions plus the disassembler's own passes,
and the result is always verified against the original image.

The Mega Drive pipeline parses cartridge headers and checksums, analyzes the
68000 and statically recovered Z80 payloads as independent Ghidra Programs,
emits a complete modular ASM68K project, and proves an exact rebuild. Stable
symbols, big-endian/relative pointer candidates and cross-CPU copy evidence are
published through a versioned project manifest.

The SNES pipeline now reaches the same integration boundary. Its versioned image
component parses plain LoROM/HiROM containers, optional copier headers, mirrored
checksums, native/emulation vectors and ROM/WRAM/SRAM bus windows. A
project-owned ca65 probe builds the same W65C816 state and pointer cases as both
LoROM and HiROM. Statically proven APU uploads are extracted and analyzed as
independent SPC700 Programs; ExROM layouts and enhancement chips are rejected in
v1.

The generated source is deliberately conservative: Ghidra-recognized official
6502 instructions become assembly, accepted pointer tables and interrupt vectors
become symbolic entries, and every unclassified or unsupported byte remains
explicit `.byte` data. The iNES header, trainer and CHR payload are separate
binary assets. A whole-ROM `.incbin` fallback is never used.

The disassembler builds on `retrolarium-core` only (container parsers, the
disassembly manifest contract). Generated projects are built, verified and
launched by [Retrolarium Kit](https://github.com/Retrolarium/retrolarium-kit)
(`rltool project ...`), whose bundled assemblers need no Docker.
`rldisasm preset`, which turns a recognized game into a ready-to-open Studio
project, is the one command that needs the kit installed
(`retrolarium-disassembler[studio]`).

## Layout

```text
src/retrolarium_disassembler/
  cli.py            rldisasm; every command imports what it runs
  preset.py         ROM -> Studio project (the only module that imports the kit)
  facts.py          neutral instruction facts shared by every CPU
  benchmark.py      pointer-table scoring against an isolated oracle
  toolchain.py      pinned Ghidra + language installs (toolchains/*.lock.json)
  ghidra/           headless Ghidra bridge and its Java scripts (scripts/)
  nes/              iNES bank analysis, pointers, ca65 emitter
  megadrive/        68000 + Z80 pipeline, ASM68K emitter, pointers, symbols
  m68k/             68000 passes: dispatch/, callbacks/, frames/, records/, repair/
  z80/              Z80 dispatch tables
  snes/             W65C816 analysis, SPC700 uploads, ca65 emitter
tests/              python -m unittest discover -s tests; folders mirror the
                    package, scripts/ covers tools/, builders.py files hold
                    the shared test images and facts
tools/              python -m tools.<group>.<name>, from this folder:
  references/       preparing the reference disassemblies (evaluation only)
  benchmarks/       scoring ROM-only disassembly against them
  reports/          HTML and Markdown source comparisons
  compiler_scan/    compiler traces in ROM sets
fixtures/           open test games, synthetic probes and their Docker images
docs/               pipeline contracts, corpus baselines and reviews
```

## Current NES boundary

- iNES 1.0 containers;
- inspect/projection profiles for mapper 0 (NROM), 3 (CNROM) and 66
  (GNROM/GxROM);
- independent headless analysis of every canonical PRG bank through generated
  mapper-0 views, with bank-qualified neutral instruction facts;
- exact disassembly and rebuild for mapper 0, 3 and 66;
- headless Ghidra 12.1.3 plus GhidraNes v20260531;
- complete physical PRG coverage and overlap checks;
- stable technical labels for functions and control-flow targets;
- explainable `u16le` and adjacent split-low/high pointer candidates;
- conservative pointer promotion with evidence, contradictions and overlap
  checks;
- exact ca65/ld65 rebuild verification in the fixture Docker image.

NES 2.0 and unprofiled mappers are rejected explicitly. Overlapping PRG windows
are analyzed independently and emitted as ordered ca65 segments with
bank-qualified symbols.

## Quick start

Run the source-checkout launcher from the repository root. Python 3.11+, Java 21
and Docker are required for the complete verified path.

```powershell
python fixtures/scripts/build_fixtures.py toolchain nes
python fixtures/scripts/build_fixtures.py build `
  nes.honkeypong nes.rhde nes.cnrom_probe nes.gnrom_probe
python rldisasm.py ghidra install
python rldisasm.py nes disassemble `
  fixtures/nes/bin/HonkeyPong.nes `
  --output build/honkey-disassembly
rltool project build `
  build/honkey-disassembly/manifest.json
rltool project verify `
  build/honkey-disassembly/manifest.json
```

`ghidra install` downloads the versions recorded in
`src/retrolarium_disassembler/toolchains/disassembly.lock.json`, verifies the
archive sizes and SHA-256 values, rejects unsafe ZIP members and installs into
the ignored `.tools/` directory. An existing compatible install can be selected
with `--ghidra-home` or `RETROLARIUM_GHIDRA_HOME`. The same command installs the
pinned MIT W65C816 and SPC700 languages as `Retrolarium65816` and
`RetrolariumSPC700`, compiles them with Ghidra's SLEIGH compiler and preserves
their upstream licenses; it does not install the upstream SNES cartridge loader.

### Mega Drive / Genesis

```powershell
python fixtures/scripts/build_fixtures.py toolchain megadrive
python fixtures/scripts/build_fixtures.py build `
  megadrive.dualcpu_probe megadrive.5stars megadrive.dragons_castle `
  megadrive.miniplanets
python rldisasm.py megadrive disassemble `
  fixtures/megadrive/bin/megadrive-dualcpu-probe.bin `
  --output build/megadrive-disassembly
rltool project build `
  build/megadrive-disassembly/retrolarium-project.json
rltool project verify `
  build/megadrive-disassembly/retrolarium-project.json
rltool project launch `
  build/megadrive-disassembly/retrolarium-project.json `
  --mame path/to/mame.exe --machine genesis --seconds 2
```

Mega Drive source is emitted below `generated/src/`, with `main.s` as the
address-ordered translation-unit index, `.s` files for the 68000, `data/` for
binary inputs, and technical work-RAM/hardware definitions under `src/memory/`.
Proven Z80 uploads also produce rebuildable `src/sound/z80/programNN.asm` units;
`project build` assembles them before the 68000 ROM. ROM-derived instructions
with supported operand forms are emitted as mnemonics; the remaining recognized
instructions retain their original bytes and disassembly comments.
`project verify` checks the rebuilt ROM against the input byte for byte.
Generated `loc_`, `sub_`, `tbl_`, and `off_` symbols use IDA-style lower-case
prefixes. Long `$FF` padding runs use `org` and are counted separately as
`padding_bytes` in the project coverage report. Technical references whose
targets fall inside such a run are suppressed, so immediate constants mistaken
for data addresses cannot split one padding range into artificial tables.
Unclassified ROM spans of at least 256 bytes are emitted as `data/opaque-*.bin`
files when they contain no analyzed instructions, accepted pointer tables,
existing assets, or internal technical symbols. A later analysis result
automatically splits an opaque include when it finds code or structure inside
it.

The Mega Drive analysis builds its complete decoder seed plan in Python. The
first pass validates cartridge vectors, ROM-to-RAM code-copy loops, PC-indexed
`bra.s`/`bra.w` and dense `bra.w` dispatch tables, and counted RAM trampoline
builders. It then runs a Python abstract interpreter over the known 68000
control-flow graph. The interpreter propagates constants, small value sets,
ranges, registers, flags, and selected memory writes, then feeds proven indirect
branch targets back to Ghidra for decoding. Analysis repeats until no new
targets, inline-data bounds, decode requests or instruction repairs are found. A
32-pass safety limit fails the operation instead of emitting a partially applied
seed plan. `analysis/m68k/abstract-analysis.json` records each seed's kind,
confidence, and evidence together with reached states, indirect edges, widening
points, unresolved jumps, RAM handler candidates, and packed orphan candidates.
`analysis/m68k/python-seeds.txt` is the decoder entry-point plan. Speculative
decode requests and canonical boundary repairs have separate plans and never
become independent roots. The Ghidra pre-script labels cartridge vectors and
applies the seed plan; it does not discover targets. Packed orphan recovery only
considers short gaps between known instructions after a terminal flow, rejects
existing data/read targets, and requires either a compact gap or a return opcode
before known code resumes. After convergence, the Kit retains backend-decoded
instructions only when they are reachable from a cartridge vector, direct call,
proven decoder seed, proven indirect target, or an accepted structural code-use
hypothesis. A backend function label alone is insufficient. This removes
isolated instruction-shaped data without using reference source. The discarded
addresses are recorded in `analysis/m68k/abstract-analysis.json`. The bounded
probe and repair protocols record their protections and audit files beside it.
The interpreter updates `X/N/Z/V/C` for modeled move, logical, arithmetic,
compare, test, and bit-test operations. It records each conditional branch as
true, false, or unknown in the abstract report while retaining both CFG edges;
known flags therefore add evidence without hiding alternate game states.

Generic pointer scans are advisory until code or data references the table
start. Unreferenced sequences whose values merely happen to land on instruction
starts remain `candidate` entries in `analysis/pointers.json` and are emitted as
raw data. Schema-proven structures such as cartridge vectors and counted RAM
trampoline tables can be accepted without that reference. Referenced `u32be`
arrays are also accepted as data-pointer tables when code reads them with an
indexed `move.l` and every entry points forward beyond the table. References to
aligned addresses inside one scanned run split it into the separate tables
actually selected by the program. Numeric longword tables whose values precede
the table remain candidates.

Counted animation layouts are recovered through their complete data path. The
analysis requires a proven ROM-to-work-RAM copy loop, the shared animation
reader that indexes a longword sequence table and then reads a sign-extended
word at `2(sequence,index)`, and a root stored into the same object field. Each
sequence header supplies its entry count, so the emitter can write every frame
as `dc.w target-copy_source` even though one runtime update reads only one
frame. This schema also follows animation roots selected by an outer indexed
longword table.

The standard Mega Drive startup stream is recovered as a mixed-width structure
when the loader addresses it through `a5`, consumes the canonical `movem`
fields, copies the VDP, Z80, CRAM, VSRAM and PSG portions with the matching
counted loops, and branches to the byte immediately after the block. The emitter
writes its scalar fields as `dc.w`/`dc.l`, uses generated hardware symbols for
the five device addresses, and preserves the embedded byte streams as `dc.b`.

Calls whose handler consumes variable-length inline operands, such as a software
floating-point runtime reached by `JSR` followed by an op word and optional
immediates, are proven per call site by a partial 68000 emulator. ROM bytes are
concrete, registers and RAM are unknown with per-bit tracking of data registers,
the stack is symbolic, and both successors of an unknown condition are explored
with context-sensitive joins. A site is accepted only when every explored return
lands on one even address at most 32 bytes after the call; the operands become
data and the continuation a decoder seed. Direct flow from each continuation is
walked in the same pass, so a chain of such calls resolves without one decoder
pass per call.

Compiler switches that double a long index (`ADD.L Dn,Dn`,
`MOVE.W (T,PC,Dn.L),Dn`, `JMP (T,PC,Dn.W)`) are recovered as
`megadrive.s16be.target-table_base` tables. Ghidra's element references from the
inferred index no longer split such tables, and backend switch flows of both
PC-relative and `MOVEA.W`/`ADDA.L`/`JMP (An)` word tables are bounded by the
structural table when decoded code starts right after it, so over-read entries
cannot become trusted code. Speculative packed-gap decoding treats an address
loaded by `MOVEA.L #addr,An` or `LEA addr.l,An` as data when memory is read
through that register, locally or in a direct callee; stored or jumped-through
pointers may be callbacks and are not counted. `LEA d16(PC),An` naming the
instruction right after an unconditional branch, whose callee jumps through the
same register, is a hand-made return address and seeds that continuation. Packed
orphan entries skip longword alignment padding or a NUL-terminated literal only
when a `LINK` or `MOVEM.L ...,-(SP)` prologue follows.

The Z80 analysis follows word dispatch tables when executable code loads their
address into HL, calls a recognized A-indexed word lookup through RST, and jumps
through HL. A preceding `sub` bounds the selector range. The analyzer marks the
words as data and seeds their targets in Ghidra, repeating this pass when a
newly decoded handler reveals another table. Each table and its evidence are
recorded in `analysis/z80/programNN/dispatch-tables.json`. On the Flicky ROM,
this recovers the 4-entry sound-command table and the adjacent 32- and 8-entry
coordination tables.

For an independent Flicky source benchmark, run this after disassembly:

```powershell
python -m tools.benchmarks.source `
  --reference path\to\flicky_src `
  --generated build/megadrive-disassembly/generated `
  --output build/flicky-benchmark `
  --minimum-m68k-instruction-match 99 `
  --minimum-m68k-precision 99 `
  --minimum-m68k-f1 99 `
  --minimum-m68k-source-match 99 `
  --minimum-z80-instruction-match 99 `
  --minimum-z80-precision 99 `
  --minimum-z80-f1 99 `
  --minimum-z80-source-match 97
```

This creates flattened `reference/main.s` and `generated/main.s`, source maps,
and `comparison.json`. When the reference AS listing exists, the report compares
68000 instruction addresses and encodings. If the reference Z80 driver listing
is available at `comparison/reference/z80_driver.lst`, it also compares Z80
instruction addresses and full instruction bytes. Run `project build` before
this command: the benchmark reads its 68000 and Z80 assembler listings to count
instructions actually written as mnemonics. The processor-specific minimum flags
enforce separate 68000 and Z80 targets. The legacy `--minimum-instruction-match`
and `--minimum-source-match` flags apply one threshold to both processors. The
benchmark reads the reference only after the ROM pipeline completes; no
reference source or symbols enter generation.

The instruction comparison records recall, precision, and F1 independently.
Precision counts speculative instruction starts that are absent from the
reference as false positives, so broader code recovery cannot improve the gate
by decoding arbitrary data.

In the current Flicky benchmark, the 68000 instruction analysis matches
5707/5707 reference instructions; the Z80 analysis matches 1679/1683 (99.76%
recall, 99.29% precision). The generated Z80 source emits 1646/1683 reference
instructions as mnemonics (97.8%). The assembled ROM is byte exact.

For additional independent games, the Sonic Retro reference corpus is pinned in
`tools/references/sonic.lock.json`. `tools/references/prepare_sonic.py` exports
unified assembly units, preserves build profiles, and verifies them against
upstream builds and original ROMs. The references are evaluation inputs only;
they never seed the ROM analyzer.

The Sonic disassembly benchmark (`tools/benchmarks/sonic_corpus.py`) runs
ROM-only analysis against those verified references, measures opcode recall and
precision, verifies exact rebuilds, and produces differences-only HTML.

For side-by-side editing, export the two ROM-aligned reference files after
disassembly:

```powershell
python -m tools.reports.export_flicky_reference `
  --reference path\to\flicky_src `
  --generated path\to\flicky_src_kit_test\project\generated
```

This writes `rom-000200.reference.s` and `rom-010000.reference.s` beside the
generated `rom-*.s` files. They concatenate the matching source modules from
`flicky_src/src/main.s`; the first starts at `Sys_ErrorTrap` ($000200), after
the cartridge vectors and header. These comparison files are not assembled.

For a standalone address-aligned HTML view, build both projects and run:

```powershell
python -m tools.reports.flicky_html_diff `
  --reference path\to\flicky_src `
  --generated path\to\flicky_src_kit_test\project\generated `
  --output path\to\flicky_src_kit_test\comparison\flicky-source-diff.html
```

Add `--differences-only` and choose a separate output file to generate a compact
report containing only structural data differences, raw instruction fallbacks,
and source lines present on one side of the comparison.

The page places lines from both assembler listings side by side at their ROM
addresses, with filters for source differences and instructions still emitted as
`dc.b`. Instructions with the same mnemonic and encoded bytes are treated as
equal even when their labels, symbolic operands, or size spelling differ.
Reference data rows covered by an exact generated `binclude` are also treated as
equal; reference instructions inside such a span remain visible as missing
analysis. It requires the rebuilt ROM to match the reference byte for byte.

For an actionable text and JSON report of the same build, run:

```powershell
python -m tools.reports.flicky_diff_report `
  --reference path\to\flicky_src `
  --generated path\to\flicky_src_kit_test\project\generated `
  --output path\to\flicky_src_kit_test\comparison
```

`flicky-diff.md` groups the remaining raw instruction fallbacks by mnemonic;
`flicky-diff.json` records every mismatch with its ROM address, both source
lines, bytes, and Ghidra fact. It separates missing analysis from unsupported
emission and differences limited to names or formatting.

To turn the source differences into contiguous regions for heuristic work, run:

```powershell
python -m tools.reports.flicky_discrepancy_groups `
  --reference path\to\flicky_src `
  --generated path\to\flicky_src_kit_test\project\generated `
  --output path\to\flicky_src_kit_test\comparison
```

The command writes `flicky-discrepancy-groups.md` and JSON. It removes line
wrapping noise and classifies every differing ROM interval as text, word or long
data, an opaque or missing binary include, a false pointer table, false code, or
padding. It also groups consecutive missed and extra Z80 instructions. Each M68K
group links to the matching row in the HTML report.

### SNES / Super Famicom foundation

```powershell
python fixtures/scripts/build_fixtures.py build `
  snes.lorom_probe snes.hirom_probe
python rldisasm.py snes inspect `
  fixtures/snes/bin/snes-lorom-probe.sfc
python rldisasm.py snes analyze `
  fixtures/snes/bin/snes-lorom-probe.sfc `
  --output build/snes-lorom-analysis
python rldisasm.py snes disassemble `
  fixtures/snes/bin/snes-lorom-probe.sfc `
  --output build/snes-lorom-disassembly
rltool project build `
  build/snes-lorom-disassembly/retrolarium-project.json
rltool project verify `
  build/snes-lorom-disassembly/retrolarium-project.json
```

Inspection and independent state-aware W65C816 decoding are available. Full
analysis writes evidence-bearing pointer, stable-symbol and cross-CPU reports.
The modular ca65 emitter has exact rebuild proof for both synthetic mappings and
two open-game holdouts. The strict project schema, Qt 5.15 importer and common
build/verify/MAME operations are complete. MAME's SNES driver needs the
`spc700.rom` device ROM in its ROM path; it is not distributed here. See
[`snes_image.md`](docs/snes_image.md) and
[`snes_disassembly.md`](docs/snes_disassembly.md).

The output directory contains:

```text
analysis/instructions.json              merged bank-qualified neutral facts
analysis/pointers.json                  candidates, evidence and schema registry
analysis/banks/bankNN/analysis-input.nes exact analysis projection
analysis/banks/bankNN/instructions.tsv  backend facts for one PRG bank
analysis/banks/bankNN/program.json      backend metadata for one PRG bank
analysis/banks/bankNN/headless.log      reproducible analysis log
generated/main.asm                      container and asset assembly
generated/src/prg.asm                   single-bank full-coverage PRG source
generated/src/prg-bankNN.asm            multi-bank full-coverage PRG sources
generated/assets/                       header, optional trainer and CHR
generated/linker.cfg                    exact ordered memory layout
generated/Makefile                      ca65/ld65 rebuild recipe
generated/emission.json                 source coverage statistics
generated/symbols.json                  bank-qualified integration symbols
generated/build/rebuilt.nes             rebuilt image after project build
manifest.json                           input, backend, coverage and verification result
```

All of these are reproducible build artifacts and should stay below an ignored
`build/` directory.

## Other commands

```powershell
python rldisasm.py nes inspect game.nes
python rldisasm.py nes analyze game.nes `
  --output build/game-analysis
python rldisasm.py ghidra status
python rldisasm.py verify original.nes rebuilt.nes
python rldisasm.py benchmark pointers `
  build/honkey-disassembly/analysis/pointers.json `
  fixtures/oracles/nes.honkeypong.pointer-tables.json
python rldisasm.py preset game.nes --output build/game-studio
python -m unittest discover -s tests
```

`nes analyze` writes one isolated `banks/bankNN/` workspace per canonical PRG
projection plus a merged `instructions.json`. Every instruction and flow has an
explicit bank context, while `physical_offset` remains unique across the source
ROM. For mappers not understood by GhidraNes directly, the workspace records the
exact generated mapper-0 analysis input and its SHA-256.

The versioned manifest contracts consumed by the Studio and the kit are
[`nes_disassembly.md`](docs/nes_disassembly.md),
[`megadrive_disassembly.md`](docs/megadrive_disassembly.md) and
[`snes_disassembly.md`](docs/snes_disassembly.md).

## Trust boundary

The ROM is immutable input. Ghidra is an analysis backend, not the source of
truth: its exported facts must map to the original PRG bytes without overlap.
The emitter owns every physical byte exactly once, and the final verifier
compares both size and content. Difficult control flow, such as a branch into
the interior of another decoded instruction, is preserved with a relocatable
relative expression and recorded as a diagnostic.

Oracle metadata is never an analyzer input. The separate benchmark command first
checks that the report and oracle name the same ROM hash, then measures accepted
table ranges and decoded targets. The current HonkeyPong development baseline
has precision 1.0 and recall 1.0 across four tables. Besides compact monotonic
tables, it exercises two generic evidence patterns: pointer fields in a record
reached from an accepted table, and two interleaved monotonic lanes. RHDE
remains a source-isolated holdout and retains exact rebuild verification.

## License

Retrolarium Disassembler is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version (`GPL-3.0-or-later`, text in `LICENSE`). It comes without any
warranty. Ghidra, GhidraNes and the SLEIGH languages it installs keep their own
licenses.
