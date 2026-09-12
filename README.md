# Retrolarium Kit

Retrolarium Kit is the independently installable, non-GUI command-line layer
used by the Retrolarium application and automation. It has no Qt dependency.
The NES pipeline turns a profiled iNES image into a complete ca65
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

## Studio project contract

The Kit owns parsing and validation of the hand-editable `.rlj` TOML
entrypoint used by the GUI. A game profile supplies an initial template, but
the created project explicitly owns which editor tabs exist, their order,
groups, documents, codecs, capabilities and dependencies.
The retired `.retrolarium` suffix is intentionally rejected rather than
treated as a compatibility alias.

Generated NES resource workspaces declare `Screens -> Graphics/Palettes` and
`Graphics -> Palettes` dependencies explicitly. The GUI uses this graph for
immediate preview invalidation; hand-edited projects may change these edges,
and the Kit rejects missing nodes, disabled dependencies and cycles.

```powershell
rltool studio preset path\to\recognized-game.nes `
  --output build\game-studio
rltool studio create path\to\manifest.json `
  --output path\to\game.rlj `
  --id game --name "Game" --profile game.v1 `
  --resource-document path\to\documents\resources.json
rltool studio inspect path\to\game.rlj
rltool studio validate path\to\game.rlj
rltool studio build path\to\game.rlj
rltool studio verify path\to\game.rlj
rltool studio launch-plan path\to\game.rlj `
  --mame mame_testing\mame\consoles.exe
```

`studio preset` is the normal entry point for Super Mario Bros. 1 and Pac-Man.
It recognizes the exact supported revision, creates a full disassembly and
typed resource bundle in a temporary sibling directory, writes the configured
Studio project, and by default builds and verifies its first artifact. The
requested output directory appears only after the whole workflow succeeds.
Use `--no-build` only for diagnostics; the GUI always requests the complete
verified workflow.

`inspect` emits the versioned normalized JSON projection consumed by the Qt
application. Project references must be portable forward-slash paths beneath
the project root; absolute paths, `..`, symlink escapes, unknown editor
contracts and dependency cycles are rejected. Operation values are registered
identifiers rather than executable command strings. The resource document is
optional; a recognized `retrolarium.nes-resource-bundle` materializes ordered
Screens, Graphics, Palettes and Code & Analysis tabs with their actual codecs
and capabilities, while omitting it creates the minimal Code-only workspace.

`studio build` first rebuilds the generated source and requires its normal
exact verification to pass. It then applies the current typed authoring
document transactionally and writes the edited image plus a hash-bound build
report below the Studio project's ignored `build/` directory. `studio verify`
rejects a stale artifact whenever the TOML project, a referenced document or
the output image has changed. `launch-plan` accepts only a current artifact and
returns the same allowlisted MAME process specification used by the Qt shell;
`studio launch` provides the bounded headless form for automation.

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

## Bundled compiler suites

Installing the wheel now installs the pinned compilers used by the first NES
and Mega Drive authoring projects. No compiler download is performed at first
use: the command only copies hash-verified package data into a writable cache.

```powershell
python -m pip install retrolarium-kit
rltool build-tools status
rltool build-tools materialize nes
rltool build-tools materialize megadrive
rltool build-tools path nes ca65
rltool build-tools path megadrive asl
```

Python build integrations should use the public API instead of locating a
repository-local `bin/` directory:

```python
from retrolarium_kit.build_toolchains import materialize_build_toolchain

nes = materialize_build_toolchain("nes")
ca65 = nes.command("ca65")
ld65 = nes.command("ld65")

sega = materialize_build_toolchain("megadrive")
asl = sega.command("asl")
p2bin = sega.command("p2bin")
environment = sega.process_environment()
```

The `2026.09.11` payload provides both suites on Windows x86-64 and the Mega
Drive suite on Linux x86-64. Linux cc65 and macOS suites remain explicitly
unavailable until native wheel smoke tests exist. AS is GPL-2.0-or-later, so
the wheel includes the exact corresponding Flamewing source snapshot for each
host binary and the full license alongside the executables. cc65 and p2bin
notices are bundled as well.

## Castle Excellent / Castlequest authoring

The first profile-driven authoring slice recognizes both supported revisions
by exact hash and validates the complete room/object layout before exposing an
editable document. The source image is immutable; `build` writes a new image
and may also write a machine-readable capacity/diff report.

```powershell
rltool game profiles
rltool game inspect "Castle Excellent (J).nes"
rltool game extract "Castle Excellent (J).nes" `
  --output build/castle/levels.json
rltool game validate "Castle Excellent (J).nes" build/castle/levels.json
rltool game build "Castle Excellent (J).nes" build/castle/levels.json `
  --output build/castle/edited.nes `
  --report build/castle/build-report.json
rltool game launch-plan "Castle Excellent (J).nes" build/castle/edited.nes `
  --mame mame_testing/mame/consoles.exe
rltool game launch "Castle Excellent (J).nes" build/castle/edited.nes `
  --mame mame_testing/mame/consoles.exe `
  --output build/castle/mame-runs --seconds 2
```

Game/revision identities, resource codecs, addresses, arenas and capacity
rules live in `profiles/game_castle_excellent.json`. A user-supplied profile
can be selected with `--profile`; it is parsed with the same strict v1
contract. The shipped codec repacks the two room arenas, room pointers,
terminated object stream, object count/state offsets and mutable-cell state
offsets as one transactional `BuildPlan`. Zero-edit builds of both known
revisions are byte-identical.

`game launch-plan` produces the same allowlisted `retrolarium.process-spec`
consumed by the Qt shell. `game launch` is its bounded headless verification
form: it saves logs, screenshots and a versioned run result below the explicit
output directory. Both commands recognize the immutable source revision and
validate the edited image before MAME can be started.

The validate/build report includes the edited-byte count and
used/capacity/free byte totals for both room banks and the object stream. The
Qt bridge validates this arithmetic before presenting a concise summary in the
common diagnostics dock.

The generic Python layer (`Address`, `AddressRange`, `BinaryReader`,
`BinaryWriter`, `GameProfile`, `ResourceSpec`, `ResourceDocument`,
`ChangeSet`, `BuildPlan` and `Registry`) is game-independent. The Castle
adapter is selected by codec id rather than game-specific CLI branching.
See
[`Retrolarium_Castle_Integration_Contract.md`](../retrolarium/docs/Retrolarium_Castle_Integration_Contract.md).

The Qt 5.15 consumer calls the same commands with explicit `QProcess`
arguments. Its first editor presents Castle rooms/cells/objects with undo/redo
and atomic document saves; it intentionally delegates all codec and capacity
validation back to this package. After a successful build, the Game menu can
request a launch plan and start the edited ROM in the explicitly selected MAME.

## Open HonkeyPong NES resources

The second bundled game profile exercises a different authoring family on the
MIT-licensed HonkeyPong fixture. `nes.resource-bundle.v1` exposes the title
nametable, three palette blocks and all 512 CHR-ROM tiles as typed JSON, then
uses the same transactional `BuildPlan` and public game commands. It supports
zero-edit exact rebuilds, edited builds and the common MAME launch path without
a HonkeyPong-specific CLI branch.

```powershell
rltool game inspect retrolarium_kit/fixtures/nes/bin/HonkeyPong.nes
rltool game extract retrolarium_kit/fixtures/nes/bin/HonkeyPong.nes `
  --output build/honkeypong/resources.json
rltool game build retrolarium_kit/fixtures/nes/bin/HonkeyPong.nes `
  build/honkeypong/resources.json --output build/honkeypong/edited.nes
```

See
[`Retrolarium_NES_Resource_Authoring_Contract.md`](docs/Retrolarium_NES_Resource_Authoring_Contract.md).

## Quick start

Run the source-checkout launcher from the repository root. Python 3.11+, Java
21 and Docker are required for the complete verified path.

```powershell
python retrolarium_kit/fixtures/scripts/build_fixtures.py toolchain nes
python retrolarium_kit/fixtures/scripts/build_fixtures.py build `
  nes.honkeypong nes.rhde nes.cnrom_probe nes.gnrom_probe
python retrolarium_kit/rltool.py ghidra install
python retrolarium_kit/rltool.py nes disassemble `
  retrolarium_kit/fixtures/nes/bin/HonkeyPong.nes `
  --output retrolarium_kit/build/honkey-disassembly
python retrolarium_kit/rltool.py project build `
  retrolarium_kit/build/honkey-disassembly/manifest.json
python retrolarium_kit/rltool.py project verify `
  retrolarium_kit/build/honkey-disassembly/manifest.json
```

`ghidra install` downloads the versions recorded in
`src/retrolarium_kit/toolchains/disassembly.lock.json`, verifies the archive
sizes and SHA-256 values, rejects unsafe ZIP members and installs into the
ignored `retrolarium_kit/.tools/` directory. An existing compatible install can
be selected with `--ghidra-home` or `RETROLARIUM_GHIDRA_HOME`.
The same command installs the pinned MIT W65C816 and SPC700 languages as
`Retrolarium65816` and `RetrolariumSPC700`, compiles them with Ghidra's SLEIGH
compiler and preserves their upstream licenses; it does not install the
upstream SNES cartridge loader.

### Mega Drive / Genesis

```powershell
python retrolarium_kit/fixtures/scripts/build_fixtures.py toolchain megadrive
python retrolarium_kit/fixtures/scripts/build_fixtures.py build `
  megadrive.dualcpu_probe megadrive.5stars megadrive.dragons_castle `
  megadrive.miniplanets
python retrolarium_kit/rltool.py megadrive disassemble `
  retrolarium_kit/fixtures/megadrive/bin/megadrive-dualcpu-probe.bin `
  --output retrolarium_kit/build/megadrive-disassembly
python retrolarium_kit/rltool.py project build `
  retrolarium_kit/build/megadrive-disassembly/retrolarium-project.json
python retrolarium_kit/rltool.py project verify `
  retrolarium_kit/build/megadrive-disassembly/retrolarium-project.json
python retrolarium_kit/rltool.py project launch `
  retrolarium_kit/build/megadrive-disassembly/retrolarium-project.json `
  --mame mame_testing/mame/consoles.exe --machine genesis --seconds 2
```

### SNES / Super Famicom foundation

```powershell
python retrolarium_kit/fixtures/scripts/build_fixtures.py build `
  snes.lorom_probe snes.hirom_probe
python retrolarium_kit/rltool.py snes inspect `
  retrolarium_kit/fixtures/snes/bin/snes-lorom-probe.sfc
python retrolarium_kit/rltool.py snes analyze `
  retrolarium_kit/fixtures/snes/bin/snes-lorom-probe.sfc `
  --output retrolarium_kit/build/snes-lorom-analysis
python retrolarium_kit/rltool.py snes disassemble `
  retrolarium_kit/fixtures/snes/bin/snes-lorom-probe.sfc `
  --output retrolarium_kit/build/snes-lorom-disassembly
python retrolarium_kit/rltool.py project build `
  retrolarium_kit/build/snes-lorom-disassembly/retrolarium-project.json
python retrolarium_kit/rltool.py project verify `
  retrolarium_kit/build/snes-lorom-disassembly/retrolarium-project.json
```

Inspection and independent state-aware W65C816 decoding are available. Full
analysis writes evidence-bearing pointer, stable-symbol and cross-CPU reports.
The modular ca65 emitter has exact rebuild proof for both synthetic mappings
and two open-game holdouts. The strict project schema, Qt 5.15 importer and
common build/verify/MAME operations are complete. The required `spc700.rom` is
hash-pinned under `mame_testing/roms` and installed into a local MAME checkout
by `mame_testing/install-required-roms.ps1`. See
[`Retrolarium_SNES_Container_Contract.md`](docs/Retrolarium_SNES_Container_Contract.md)
and
[`Retrolarium_SNES_Integration_Contract.md`](docs/Retrolarium_SNES_Integration_Contract.md).

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

## Pac-Man maze authoring

The packaged `pacman.v1` profile currently recognizes the two verified
layout-compatible Japan v1.0/v1.1 revisions. `game extract` produces one
`retrolarium.nes-resource-bundle` containing the 27x22 maze, 23x6 title logo,
14 fixed-width messages, five main palette contexts, complete CHR bank and
fixed actor mappings; no ROM bytes are distributed with the Kit.
`pacman.maze-rle.v1`
preserves the source's 416 token bytes for a byte-exact zero-edit build and
deterministically repacks changed tiles without moving later data.

The codec rejects invalid geometry, tile IDs, pellet/power-pellet counts,
blocked actor spawns or tunnels, broken door placement, unexpected path
components and RLE overflow. A Studio project generated from the bundle owns
Maze, Graphics, Palettes, Animations & Mappings and Code tabs, with Maze and
Animations depending on Graphics for immediate preview refresh.
`pacman.palette-table.v1` exposes the title, attract,
round-gameplay, intermission-sprite and fruit-by-stage tables. Its declared
mirror pairs are validated and written together, preventing a GUI edit from
breaking the NES universal-background slots. Frightened/normal color command
copies are intentionally deferred until the bundle supports replicated ranges.
`pacman.actor-mapping.v1` round-trips the original 624-byte
table as 64 standard and 13 alternate four-quadrant frames, validates OAM
attribute bits and keeps the shared 16x16 offset layout read-only. See
[`Retrolarium_Pacman_Maze_Authoring_Contract.md`](docs/Retrolarium_Pacman_Maze_Authoring_Contract.md).

The title logo reuses `nes.nametable.v1` as a tile-only 23x6 region. Both
verified revisions rebuild exactly, and the common Screens editor disables its
palette brush when a region has no attribute bytes. The addressed PPU packets,
HUD/intermission regions are not bundled yet. `nes.fixed-text-fields.v1`
projects 14 disjoint title, attract and pause ranges into one Text resource;
the profile owns the glyph map, case folding, labels, widths and addresses.
See
[`Retrolarium_NES_Text_Authoring_Contract.md`](docs/Retrolarium_NES_Text_Authoring_Contract.md).

## Super Mario Bros. authoring

The packaged `smb1.v1` profile recognizes the verified byte-identical JU build
from the open `smb1_src` reconstruction. `game extract` emits a 12-resource
bundle containing all 36 course routes, nine player-physics tables, 34 level
areas, metatiles, palette packets and player palettes, five screen regions,
seven fixed text fields, 26 player frames, the main APU music bank and effect
envelope, and the complete CHR bank. The generated Studio workspace owns World,
Levels, Screens, Music & Sounds, Text, Graphics, Metatiles, Palettes, Player
Frames and Code & Analysis tabs. These editors share undo/redo, restore and
atomic save. The zero-edit disassemble/extract/build/verify path is
byte-identical. See
[`Retrolarium_SMB_World_Authoring_Contract.md`](docs/Retrolarium_SMB_World_Authoring_Contract.md).
ANN and SMB2 Japan additionally expose their ending-bank FDS waveforms and
volume programs through a dedicated `audio.synthesis` Studio tab; see
[`Retrolarium_FDS_Synthesis_Authoring_Contract.md`](docs/Retrolarium_FDS_Synthesis_Authoring_Contract.md).

## Other commands

```powershell
python retrolarium_kit/rltool.py nes inspect game.nes
python retrolarium_kit/rltool.py nes analyze game.nes `
  --output retrolarium_kit/build/game-analysis
python retrolarium_kit/rltool.py project validate `
  retrolarium_kit/build/game-disassembly/manifest.json
python retrolarium_kit/rltool.py project build `
  retrolarium_kit/build/game-disassembly/manifest.json
python retrolarium_kit/rltool.py project verify `
  retrolarium_kit/build/game-disassembly/manifest.json
python retrolarium_kit/rltool.py project launch `
  retrolarium_kit/build/game-disassembly/manifest.json `
  --mame mame_testing/mame/consoles.exe --seconds 2
python retrolarium_kit/rltool.py ghidra status
python retrolarium_kit/rltool.py verify original.nes rebuilt.nes
python retrolarium_kit/rltool.py benchmark pointers `
  retrolarium_kit/build/honkey-disassembly/analysis/pointers.json `
  retrolarium_kit/fixtures/oracles/nes.honkeypong.pointer-tables.json
python -m unittest discover retrolarium_kit/tests -v
```

Generated NES/SNES projects use the bundled `ca65-ld65-v1` recipe, and Mega
Drive projects use `asl-p2bin-v1`. `project build` therefore needs neither
Docker nor a local compiler directory; pass `--container IMAGE` only when an
explicit compatibility build is wanted.

`nes analyze` writes one isolated `banks/bankNN/` workspace per canonical PRG
projection plus a merged `instructions.json`. Every instruction and flow has an
explicit bank context, while `physical_offset` remains unique across the source
ROM. For mappers not understood by GhidraNes directly, the workspace records
the exact generated mapper-0 analysis input and its SHA-256.

Build or install this distribution directly from its repository-root package
directory:

```powershell
python -m pip install ./retrolarium_kit
rltool --version

uv build --wheel --out-dir retrolarium_kit/build/dist ./retrolarium_kit
```

An editable development install uses
`python -m pip install -e ./retrolarium_kit`. All three forms expose the
`rltool` entry point. Installing the separate `retrolarium` GUI distribution
also resolves this package as its declared dependency.

The versioned manifest contract consumed by the Retrolarium application is
documented in
[`Retrolarium_NES_Integration_Contract.md`](docs/Retrolarium_NES_Integration_Contract.md).
The corresponding dual-CPU contract is
[`Retrolarium_MegaDrive_Integration_Contract.md`](docs/Retrolarium_MegaDrive_Integration_Contract.md).

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
