# Retrolarium Kit

Retrolarium Kit is the reproducible command-line layer used by the Retrolarium
application. The first working slice turns an iNES NROM image into a complete
ca65 project, rebuilds it and can prove that the result is byte-identical.

The generated source is deliberately conservative: Ghidra-recognized official
6502 instructions become assembly, accepted pointer tables and interrupt
vectors become symbolic entries, and every unclassified or unsupported byte
remains explicit `.byte` data. The iNES header, trainer and CHR payload are
separate binary assets. A whole-ROM `.incbin` fallback is never used.

## Current NES boundary

- iNES 1.0 containers;
- mapper 0 (NROM), with 16 or 32 KiB PRG;
- headless Ghidra 12.1.3 plus GhidraNes v20260531;
- complete physical PRG coverage and overlap checks;
- stable technical labels for functions and control-flow targets;
- explainable `u16le` and adjacent split-low/high pointer candidates;
- conservative pointer promotion with evidence, contradictions and overlap checks;
- exact ca65/ld65 rebuild verification in the fixture Docker image.

NES 2.0 and bank-switched mappers are rejected explicitly until their address
projection profiles are implemented.

## Quick start

Run the source-checkout launcher from the repository root. Python 3.11+, Java
21 and Docker are required for the complete verified path.

```powershell
python retrolarium/fixtures/scripts/build_fixtures.py toolchain nes
python retrolarium/fixtures/scripts/build_fixtures.py build nes.honkeypong nes.rhde
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

The output directory contains:

```text
analysis/instructions.tsv       neutral instruction facts
analysis/pointers.json           candidates, evidence and schema registry
analysis/program.json           backend metadata
analysis/headless.log           reproducible analysis log
generated/main.asm              container and asset assembly
generated/src/prg.asm           full-coverage PRG source
generated/assets/               header, optional trainer and CHR
generated/linker.cfg             exact memory layout
generated/Makefile               ca65/ld65 rebuild recipe
generated/emission.json          source coverage statistics
generated/build/rebuilt.nes      rebuilt image (when verification is requested)
manifest.json                    input, backend, coverage and verification result
```

All of these are reproducible build artifacts and should stay below an ignored
`build/` directory.

## Other commands

```powershell
python retrolarium/kit/rltool.py nes inspect game.nes
python retrolarium/kit/rltool.py ghidra status
python retrolarium/kit/rltool.py verify original.nes rebuilt.nes
python retrolarium/kit/rltool.py benchmark pointers `
  retrolarium/build/honkey-disassembly/analysis/pointers.json `
  retrolarium/fixtures/oracles/nes.honkeypong.pointer-tables.json
python -m unittest discover retrolarium/kit/tests -v
```

The package can also be installed in editable mode with
`python -m pip install -e retrolarium/kit`, after which the entry point is
available as `rltool`.

## Trust boundary

The ROM is immutable input. Ghidra is an analysis backend, not the source of
truth: its exported facts must map to the original PRG bytes without overlap.
The emitter owns every physical byte exactly once, and the final verifier
compares both size and content. Difficult control flow, such as a branch into
the interior of another decoded instruction, is preserved with a relocatable
relative expression and recorded as a diagnostic.

Oracle metadata is never an analyzer input. The separate benchmark command
first checks that the report and oracle name the same ROM hash, then measures
accepted table ranges and decoded targets. The initial HonkeyPong baseline has
precision 1.0 and recall 0.5: both promoted music tables are correct, while two
non-monotonic/repeated tables intentionally remain unpromoted for now.
