# Retrolarium open-game fixtures

The open games the build, ROM analysis and exact rebuild are tested on. Git
holds only the build descriptions, pinned tool versions and minimal
compatibility patches.

## Layout

```text
<platform>/<fixture-id>/upstream-source/  # ignored upstream checkout
<platform>/bin/                          # built ROMs only, ignored as well
.work/                                   # throwaway source copies for a build
.state/build-results.json                # sizes, SHA-256 and provenance of the last run
```

The URL, the main repository's commit and every submodule's commit are pinned in
`upstreams.lock.json`. Build commands, the expected ROM names and sizes and the
toolchain images are described in `projects.json`. Patches never touch a
checkout: they are applied to a fresh copy in `.work/`.

## Quick start

Needs Python 3, Git and a running Docker Engine. Run the commands from the
repository root:

```powershell
python fixtures/scripts/build_fixtures.py fetch
python fixtures/scripts/build_fixtures.py doctor
python fixtures/scripts/build_fixtures.py toolchain nes
python fixtures/scripts/build_fixtures.py toolchain megadrive
python fixtures/scripts/build_fixtures.py toolchain snes
python fixtures/scripts/build_fixtures.py build all
python fixtures/scripts/build_fixtures.py verify
```

Fetch or build individual projects by passing one or more IDs:

```powershell
python fixtures/scripts/build_fixtures.py fetch nes.thwaite
python fixtures/scripts/build_fixtures.py build nes.thwaite megadrive.5stars
```

Before each run the builder checks the exact commit and that the checkout is
clean, makes a new working copy, removes the expected finished ROM from it, runs
the pinned container and validates the platform header, size and SHA-256 against
`projects.json`. An unexpected file in any `<platform>/bin/` is an error.

## Synthetic mapper probes

The controlled sources in `synthetic/` belong to the project and are committed
under 0BSD. Unlike the upstream fixtures, their identity is the SHA-256 of the
whole source tree, relative paths included. That lets a probe change on purpose
without hiding a change in the analyser's input.

Available now: `nes.nrom_probe` (mapper 0: mirrored 16 KiB PRG, positive and
negative pointer cases), `nes.cnrom_probe` (mapper 3: fixed PRG and four CHR
banks) and `nes.gnrom_probe` (mapper 66: four overlapping 32 KiB PRG banks and
four CHR banks):

```powershell
python fixtures/scripts/build_fixtures.py build `
  nes.nrom_probe nes.cnrom_probe nes.gnrom_probe
python fixtures/scripts/build_fixtures.py verify `
  nes.nrom_probe nes.cnrom_probe nes.gnrom_probe
```

The built ROMs still land only in the ignored `nes/bin/`.

## What not to commit

- the `upstream-source/` and `.work/` folders;
- Docker images and downloaded third-party tool sources;
- ROMs from `nes/bin/`, `megadrive/bin/` and `snes/bin/`;
- `.state/build-results.json` and other reproducible artifacts.

When an upstream or a toolchain changes, update the lock, config, recipes and
patches first, then run a clean `build all`. Testing the Python code:

```powershell
python -m unittest discover fixtures/tests
```
