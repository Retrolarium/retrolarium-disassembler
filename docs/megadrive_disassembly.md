# Retrolarium Mega Drive Integration Contract v1

This contract defines the machine boundary between a disassembled Sega Mega
Drive / Genesis project and the tools that consume it. The root document uses
`schema: retrolarium.megadrive.disassembly` and `schema_version: 1`; unknown
schemas and versions are rejected.

## Address and CPU identity

The Motorola 68000 and Z80 never share an implicit address namespace. Every
instruction, symbol, flow, asset address and evidence endpoint carries an
explicit `cpu_id` and/or `address_space`:

```text
(platform=megadrive, cpu_id, address_space, logical_address, physical_offset?)
```

The cartridge ROM is big-endian 68000 input. Each statically proven Z80 copy is
an independent little-endian Ghidra Program. A Z80 program refers to one
`cross_cpu_evidence.edges[*].id` through `derived_from`; the edge records the
68000 ROM source range, Z80 RAM destination range, exact payload SHA-256 and the
68000 instructions supporting the copy inference.

## Project artifacts

- `analysis/analysis.json` enumerates independent 68000 and Z80 programs and
  hashes their analysis input, neutral instruction facts, raw backend facts and
  backend report.
- `analysis/pointers.json` contains versioned big-endian absolute and signed
  relative pointer candidates, evidence, contradictions and accepted status.
- `analysis/symbols.json` contains stable `Entry_`, `Sub_`, `Loc_`, `Tbl_` and
  `Off_` technical symbols, aliases and evidence.
- `analysis/cross-cpu-evidence.json` binds recovered Z80 payloads to exact ROM
  slices. An unproven byte run is not promoted to a Z80 program.
- `assets.items` declares the cartridge header and recovered Z80 programs as
  hashed AS `binclude` assets with non-overlapping ROM ranges.
- `source.units` enumerates the complete modular AS project. Coverage is a
  partition of the ROM into vectors, instructions, accepted pointers, assets and
  raw bytes; a whole-ROM fallback is not used.
- `verification` records independent size/SHA-256 equality and the parsed Sega
  checksum status.

All paths are relative to the project root (or the declared analysis root).
Absolute paths, parent traversal and symlink escapes are rejected. The portable
root manifest deliberately omits the host path of its input ROM.

The distributable structural schema ships with retrolarium-core as
`schemas/megadrive-disassembly-v1.schema.json`. The Python validator
additionally verifies file hashes, program architecture, cross-CPU payload
slices, coverage totals, operation invariants and an exact rebuilt artifact.

## Commands and operations

```powershell
python rldisasm.py megadrive inspect game.bin
python rldisasm.py megadrive analyze game.bin `
  --output build/game-analysis
python rldisasm.py megadrive disassemble game.bin `
  --output build/game-disassembly
rltool project validate `
  build/game-disassembly/retrolarium-project.json
rltool project build `
  build/game-disassembly/retrolarium-project.json
rltool project verify `
  build/game-disassembly/retrolarium-project.json
rltool project launch `
  build/game-disassembly/retrolarium-project.json `
  --mame path/to/mame.exe --machine genesis --seconds 2
```

The default build operation resolves the hash-pinned AS/p2bin suite shipped in
the `retrolarium-kit` wheel and executes the versioned `asl-p2bin-v1` recipe
without a shell. A caller can still select a pinned compatibility container
explicitly with `project build --container IMAGE`; its argv remains a literal
array. Launch supports only MAME `genesis` (NTSC) and `megadriv` (PAL).
`launch-plan` returns a versioned `retrolarium.process-spec`; the caller starts
it as program + argv against the MAME it chose, never through a shell.

## Consumers

The kit's `project` commands read this manifest, and a Retrolarium Studio
project (`.rlj`) names it as the disassembly it builds on. Consumers keep the
68000 and Z80 programs separate and show cross-CPU evidence instead of
flattening it into a single pseudo-address space. Build, verify and MAME
operations are the fixed ones above, common with NES.

## Validation baseline

The blind pipeline has produced byte-identical rebuilds for:

| Fixture                    |          Size | Result                                          |
| -------------------------- | ------------: | ----------------------------------------------- |
| Retrolarium dual-CPU probe |   1,024 bytes | exact; valid checksum; proven 68000-to-Z80 copy |
| 5 Stars                    |  10,967 bytes | exact; absent checksum; recovered Z80 program   |
| Dragon's Castle            | 175,708 bytes | exact; absent checksum; recovered Z80 program   |
| Miniplanets REMIX REV04    | 524,288 bytes | exact; valid checksum; recovered Z80 program    |

The source repositories and oracles are never inputs to blind analysis. They are
used only after artifact generation to measure known ranges and hashes. An exact
rebuild proves byte ownership and encoding, not that every code/data
classification is semantically correct; confidence and contradictions remain
visible to consumers.
