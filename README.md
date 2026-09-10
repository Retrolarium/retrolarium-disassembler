# Retrolarium Kit

Retrolarium Kit is the reproducible command-line layer used by the Retrolarium
application. The NES pipeline turns a profiled iNES image into a complete ca65
project, rebuilds it and can prove that the result is byte-identical. Mapper
profiles describe the physical-to-logical projections used for independent
bank analysis and source emission.

The Mega Drive pipeline parses cartridge headers and checksums, analyzes the
68000 and statically recovered Z80 payloads as independent Ghidra Programs,
emits a complete modular ASM68K project, and proves an exact rebuild. Stable
symbols, big-endian/relative pointer candidates and cross-CPU copy evidence are
published through a versioned project manifest.

The SNES pipeline now reaches the same integration boundary. Its versioned
image component parses plain LoROM/HiROM containers, optional copier headers,
mirrored checksums, native/emulation vectors and ROM/WRAM/SRAM bus windows. A
project-owned ca65 probe builds the same W65C816 state and pointer cases as
both LoROM and HiROM. Statically proven APU uploads are extracted and analyzed
as independent SPC700 Programs; ExROM layouts and enhancement chips are
rejected in v1.

The generated source is deliberately conservative: Ghidra-recognized official
6502 instructions become assembly, accepted pointer tables and interrupt
vectors become symbolic entries, and every unclassified or unsupported byte
remains explicit `.byte` data. The iNES header, trainer and CHR payload are
separate binary assets. A whole-ROM `.incbin` fallback is never used.

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
- conservative pointer promotion with evidence, contradictions and overlap checks;
- exact ca65/ld65 rebuild verification in the fixture Docker image.

NES 2.0 and unprofiled mappers are rejected explicitly. Overlapping PRG windows
are analyzed independently and emitted as ordered ca65 segments with
bank-qualified symbols.

## Quick start

Run the source-checkout launcher from the repository root. Python 3.11+, Java
21 and Docker are required for the complete verified path.

```powershell
python retrolarium/fixtures/scripts/build_fixtures.py toolchain nes
python retrolarium/fixtures/scripts/build_fixtures.py build `
  nes.honkeypong nes.rhde nes.cnrom_probe nes.gnrom_probe
python retrolarium/kit/rltool.py ghidra install
python retrolarium/kit/rltool.py nes disassemble `
  retrolarium/fixtures/nes/bin/HonkeyPong.nes `
  --output retrolarium/build/honkey-disassembly `
  --build-container retrolarium-fixtures-nes:2026-09-09
```

`ghidra install` downloads the versions recorded in
`src/retrolarium_kit/toolchains/disassembly.lock.json`, verifies the archive
sizes and SHA-256 values, rejects unsafe ZIP members and installs into the
ignored `retrolarium/kit/.tools/` directory. An existing compatible install can
be selected with `--ghidra-home` or `RETROLARIUM_GHIDRA_HOME`.
The same command installs the pinned MIT W65C816 and SPC700 languages as
`Retrolarium65816` and `RetrolariumSPC700`, compiles them with Ghidra's SLEIGH
compiler and preserves their upstream licenses; it does not install the
upstream SNES cartridge loader.

### Mega Drive / Genesis

```powershell
python retrolarium/fixtures/scripts/build_fixtures.py toolchain megadrive
python retrolarium/fixtures/scripts/build_fixtures.py build `
  megadrive.dualcpu_probe megadrive.5stars megadrive.dragons_castle `
  megadrive.miniplanets
python retrolarium/kit/rltool.py megadrive disassemble `
  retrolarium/fixtures/megadrive/bin/megadrive-dualcpu-probe.bin `
  --output retrolarium/build/megadrive-disassembly `
  --build-container retrolarium-fixtures-megadrive:2026-09-09
python retrolarium/kit/rltool.py project launch `
  retrolarium/build/megadrive-disassembly/retrolarium-project.json `
  --mame mame_testing/mame/consoles.exe --machine genesis --seconds 2
```

### SNES / Super Famicom foundation

```powershell
python retrolarium/fixtures/scripts/build_fixtures.py build `
  snes.lorom_probe snes.hirom_probe
python retrolarium/kit/rltool.py snes inspect `
  retrolarium/fixtures/snes/bin/snes-lorom-probe.sfc
python retrolarium/kit/rltool.py snes analyze `
  retrolarium/fixtures/snes/bin/snes-lorom-probe.sfc `
  --output retrolarium/build/snes-lorom-analysis
python retrolarium/kit/rltool.py snes disassemble `
  retrolarium/fixtures/snes/bin/snes-lorom-probe.sfc `
  --output retrolarium/build/snes-lorom-disassembly `
  --build-container retrolarium-fixtures-snes:2026-09-09
```

Inspection and independent state-aware W65C816 decoding are available. Full
analysis writes evidence-bearing pointer, stable-symbol and cross-CPU reports.
The modular ca65 emitter has exact rebuild proof for both synthetic mappings
and two open-game holdouts. The strict project schema, Qt 5.15 importer and
common build/verify/MAME operations are complete. The required `spc700.rom` is
hash-pinned under `mame_testing/roms` and installed into a local MAME checkout
by `mame_testing/install-required-roms.ps1`. See
[`Retrolarium_SNES_Container_Contract.md`](../docs/Retrolarium_SNES_Container_Contract.md)
and
[`Retrolarium_SNES_Integration_Contract.md`](../docs/Retrolarium_SNES_Integration_Contract.md).

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
generated/build/rebuilt.nes             rebuilt image when verification is requested
manifest.json                           input, backend, coverage and verification result
```

All of these are reproducible build artifacts and should stay below an ignored
`build/` directory.

## Other commands

```powershell
python retrolarium/kit/rltool.py nes inspect game.nes
python retrolarium/kit/rltool.py nes analyze game.nes `
  --output retrolarium/build/game-analysis
python retrolarium/kit/rltool.py project validate `
  retrolarium/build/game-disassembly/manifest.json
python retrolarium/kit/rltool.py project build `
  retrolarium/build/game-disassembly/manifest.json
python retrolarium/kit/rltool.py project verify `
  retrolarium/build/game-disassembly/manifest.json
python retrolarium/kit/rltool.py project launch `
  retrolarium/build/game-disassembly/manifest.json `
  --mame mame_testing/mame/consoles.exe --seconds 2
python retrolarium/kit/rltool.py ghidra status
python retrolarium/kit/rltool.py verify original.nes rebuilt.nes
python retrolarium/kit/rltool.py benchmark pointers `
  retrolarium/build/honkey-disassembly/analysis/pointers.json `
  retrolarium/fixtures/oracles/nes.honkeypong.pointer-tables.json
python -m unittest discover retrolarium/kit/tests -v
```

`nes analyze` writes one isolated `banks/bankNN/` workspace per canonical PRG
projection plus a merged `instructions.json`. Every instruction and flow has an
explicit bank context, while `physical_offset` remains unique across the source
ROM. For mappers not understood by GhidraNes directly, the workspace records
the exact generated mapper-0 analysis input and its SHA-256.

The package can also be installed in editable mode with
`python -m pip install -e retrolarium/kit`, after which the entry point is
available as `rltool`.

The versioned manifest contract consumed by the Retrolarium application is
documented in
[`Retrolarium_NES_Integration_Contract.md`](../docs/Retrolarium_NES_Integration_Contract.md).
The corresponding dual-CPU contract is
[`Retrolarium_MegaDrive_Integration_Contract.md`](../docs/Retrolarium_MegaDrive_Integration_Contract.md).

## Trust boundary

The ROM is immutable input. Ghidra is an analysis backend, not the source of
truth: its exported facts must map to the original PRG bytes without overlap.
The emitter owns every physical byte exactly once, and the final verifier
compares both size and content. Difficult control flow, such as a branch into
the interior of another decoded instruction, is preserved with a relocatable
relative expression and recorded as a diagnostic.

Oracle metadata is never an analyzer input. The separate benchmark command
first checks that the report and oracle name the same ROM hash, then measures
accepted table ranges and decoded targets. The current HonkeyPong development
baseline has precision 1.0 and recall 1.0 across four tables. Besides compact
monotonic tables, it exercises two generic evidence patterns: pointer fields in
a record reached from an accepted table, and two interleaved monotonic lanes.
RHDE remains a source-isolated holdout and retains exact rebuild verification.
