# Retrolarium SNES Integration Contract v1

This document defines the machine boundary between Retrolarium Kit and the Qt
5.15 application for Super Nintendo / Super Famicom disassembly projects. The
root document uses `schema: retrolarium.snes.disassembly` and
`schema_version: 1`; unknown schemas and versions are rejected.

## Address and CPU identity

W65C816 cartridge code and recovered SPC700 programs never share an implicit
address namespace. Every instruction, symbol, flow and evidence endpoint uses an
explicit CPU and address space:

```text
(platform=snes, cpu_id, address_space, logical_address, physical_offset?)
```

The main program uses `cpu_id=w65c816`, `address_space=snes-rom` and language
`65816:LE:24:snes`. Every statically proven APU upload becomes a separate
little-endian `SPC700:LE:16:default` Program in `spc700-ram`. Its `derived_from`
field names exactly one cross-CPU evidence edge. Bytes lacking complete static
copy evidence remain ordinary ROM data.

## Project artifacts

- `analysis/analysis.json` enumerates the main W65C816 program and zero or more
  independently analyzed SPC700 programs, with hashed analysis inputs and
  instruction artifacts.
- `analysis/state-analysis.json` contains Retrolarium's independent W65C816
  state, instruction and flow facts. Ghidra output does not silently replace
  these facts.
- `analysis/pointers.json` contains the versioned vector, near, far, split and
  signed-relative pointer schemas with evidence and contradictions.
- `analysis/symbols.json` contains stable `Entry_`, `Sub_`, `Loc_`, `Tbl_`,
  `Vec_` and `Off_` names, aliases and evidence.
- `analysis/cross-cpu-evidence.json` binds an SPC700 payload to its exact
  cartridge ROM slice and destination RAM interval.
- `assets.items` exposes proven SPC700 payloads as hashed resources.
- `source.units` lists every generated ca65 bank module. Coverage is a complete
  partition of copier header, instructions, local instruction fallbacks,
  accepted pointers, internal header and raw bytes. A whole-ROM fallback is
  forbidden.
- `verification` records independent size/SHA-256 equality and the parsed SNES
  checksum status.

All paths are relative to the project or declared analysis root. Absolute paths,
parent traversal and symlink escapes are rejected. The root manifest does not
retain the host path of the original ROM.

The distributable structural schema ships with retrolarium-core as
`schemas/snes-disassembly-v1.schema.json`. The Python validator additionally
verifies nested artifact hashes, architecture and byte order, exact ROM slices
for cross-CPU edges, source coverage totals, operation invariants and the exact
rebuilt artifact.

## Commands and operations

```powershell
python rldisasm.py snes inspect game.sfc
python rldisasm.py snes analyze game.sfc `
  --output build/game-analysis
python rldisasm.py snes disassemble game.sfc `
  --output build/game-disassembly
rltool project validate `
  build/game-disassembly/retrolarium-project.json
rltool project build `
  build/game-disassembly/retrolarium-project.json
rltool project verify `
  build/game-disassembly/retrolarium-project.json
rltool project launch `
  build/game-disassembly/retrolarium-project.json `
  --mame path/to/mame.exe --machine snes --seconds 2
```

The default build operation resolves ca65/ld65 from the installed
`retrolarium-kit` wheel and executes the fixed `ca65-ld65-v1` recipe without
Make or Docker. A pinned compatibility image remains an explicit override via
`project build --container IMAGE`. Launch accepts only MAME `snes` and `snespal`
machines. `launch-plan` returns a versioned `retrolarium.process-spec`; the Qt
bridge checks its platform, machine, executable and separate argument array
before passing it to `QProcess`.

MAME's SNES driver requires the 64-byte `spc700.rom` device ROM in its ROM path;
Retrolarium does not distribute it. A smoke run that reports
`spc700.rom NOT FOUND` proves process wiring only, not a successful runtime
test. The result reports this condition as `status: missing-dependency` with a
structured `failure.kind: mame-required-roms` and the missing filenames, so CI
and the Qt application do not confuse an incomplete MAME installation with a
cartridge failure.

## Qt consumer

`retrolarium::SnesDisassemblyProject::load()` imports the image identity,
W65C816 and SPC700 programs, instructions, symbols, pointer candidates,
cross-CPU edges, assets, source units and operation descriptors. It
independently checks schemas, canonical paths and SHA-256 records. The UI
presents every CPU program separately and preserves the evidence edge between
the cartridge and APU RAM.

`retrolarium.exe --studio-smoke retrolarium-project.json` exercises the same
loader as **File -> Open generated project**. Build, verify and MAME actions use
the common Retrolarium Kit bridge shared with NES and Mega Drive.

## Blind validation baseline

Source repositories and oracle metadata are excluded from every analysis run.
All four fixtures produced valid-checksum, byte-identical 131,072-byte rebuilds:

| Fixture                 | Mapping | Programs | W65C816 instructions | Symbols | Accepted pointers | Result                          |
| ----------------------- | ------- | -------: | -------------------: | ------: | ----------------: | ------------------------------- |
| Retrolarium LoROM probe | LoROM   |        2 |                   38 |      12 |                 5 | exact; one proven SPC700 upload |
| Retrolarium HiROM probe | HiROM   |        2 |                   38 |      12 |                 5 | exact; one proven SPC700 upload |
| Castle Platformer       | LoROM   |        1 |                1,641 |     176 |                 1 | exact                           |
| Horizontal Shooter      | HiROM   |        1 |                2,420 |     281 |                 7 | exact                           |

All four exact rebuilds complete a two-second MAME `snes` smoke run with exit
code zero and a captured frame. The two open games additionally pass the
non-blank frame gate: Castle Platformer produces 26 colours with a 0.5413
dominant-colour share; Horizontal Shooter produces 38 colours with a 0.9611
share. The synthetic mapping probes intentionally draw no scene and therefore
use process completion rather than the visual-content gate.

The open-game hashes are respectively
`1f674609e2fb05cb3e062796a10798a11e8bb0859e1b461f1a26727720c4bdf0` and
`9214dfb43a96f187d88aa12a6bf661a32521c0de9fc6870cbccba9653cb67a6e`. An exact
rebuild proves byte ownership and encoding, not that every code/data
classification is semantically correct; consumers must retain confidence,
contradictions and local instruction fallbacks.
