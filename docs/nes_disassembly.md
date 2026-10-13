# Retrolarium NES Integration Contract v1

This contract defines the machine boundary between a disassembled NES project
and the tools that consume it. A consumer must not parse ca65 text, guess the
mapper or look for artifacts by file name: the entry point is the root
`manifest.json` with schema `retrolarium.nes.disassembly` and
`schema_version: 1`.

## Address identity

A logical CPU address is not a unique key. PRG locations use:

```text
(platform=nes, region=prg, bank, cpu_address, physical_offset)
```

`physical_offset` counts from the start of PRG, not from the start of the iNES
file. CHR assets also carry a PPU space, bank and selector. A consumer must keep
the bank context while navigating and must not merge two `$8000` addresses from
different GNROM banks.

## Artifacts

- `analysis/instructions.json`: normalised instructions and flows;
- `analysis/pointers.json`: candidates, evidence and contradictions;
- `generated/symbols.json`: stable symbol IDs, bank/CPU/physical addresses and
  source unit;
- `assets.items`: checked slices of the header, trainer and CHR banks;
- `source.units`: the complete list of imported ca65 modules;
- `verification`: the independent exact-rebuild status.

Ordinary paths are relative to the root manifest's folder. `backend.banks[*]` is
relative to `backend.analysis_root`, and `symbols[*].source_unit` to
`source.directory`. Every machine artifact and asset slice is pinned by SHA-256.

The JSON Schema ships with retrolarium-core as
`schemas/nes-disassembly-v1.schema.json`. Validation also checks safe path
resolution, that files exist, their SHA-256, asset slice bounds and that the
built ROM matches the declared exact verification.

## Check before import

```powershell
rltool project validate build/game-disassembly/manifest.json
```

A contract validation error blocks the import. An unknown newer schema version
blocks it too until support is added explicitly. Adding fields within v1 is
allowed; changing the meaning of an existing field or removing it is not.

## Trust boundary

Ghidra facts are the backend's claims; the ROM remains the source of byte truth.
`exact` proves the files are equal, not that code and data were recognised
correctly. A consumer should therefore show evidence and diagnostics separately
from the build status.

## Operations

The `operations` section holds fixed IDs, not arbitrary commands from a game
preset. Retrolarium Kit provides these handlers:

```powershell
rltool project build manifest.json
rltool project verify manifest.json
rltool project launch-plan manifest.json --mame mame/consoles.exe --attach-window 1234
rltool project launch manifest.json --mame mame/consoles.exe --seconds 2
```

`build` uses the `ca65-ld65-v1` recipe shipped in the kit's wheel by default,
without Make or Docker; `--container IMAGE` remains an explicit compatibility
override. `verify` compares the size and SHA-256 with the original ROM.
`launch-plan` returns a `retrolarium.process-spec` to start as program + argv
and lets the caller add the handle of its emulator widget. `launch` runs a
time-limited headless MAME smoke run and keeps a `retrolarium.run-result`,
stdout, stderr and hashed screenshots. The supported machine IDs are listed in
the manifest and checked by the kit; a preset cannot pass an arbitrary MAME
driver or shell fragment.

## Consumers

The kit's `project` commands read this manifest. A Retrolarium Studio project
(`.rlj`) names it as the disassembly it builds on: the kit checks the manifest
whenever it loads, builds or verifies the project, and runs only the fixed
operations above, as program + argv, never through a shell.
