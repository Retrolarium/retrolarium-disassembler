# Retrolarium SNES Container Contract v1

This document defines the first versioned SNES/Super Famicom component: what
inspecting a cartridge image hands to analysis and source emission. The
machine-readable document uses `schema: retrolarium.snes.image`,
`schema_version: 1`; its distributable JSON Schema ships with retrolarium-core
as `schemas/snes-image-v1.schema.json`.

## Supported cartridge boundary

Version 1 accepts a headerless ROM payload whose size is a multiple of 32 KiB,
optionally preceded by one 512-byte copier header. It supports ordinary LoROM
and HiROM images up to 4 MiB, slow or fast ROM, with chipset header values for
ROM, ROM+RAM and ROM+RAM+battery. ExLoROM, ExHiROM and enhancement-chip boards
such as SA-1, Super FX and S-DD1 are rejected rather than projected through an
incorrect generic map.

The parser selects the internal header at `$007FC0` (LoROM) or `$00FFC0` (HiROM)
using map mode, checksum complement, reset vector, title and declared size
evidence. It publishes the raw and computed mirrored checksum, all eight native
and eight emulation vectors, the file offset reached by every backed vector, and
warnings for non-fatal size/checksum disagreement. An emulation RESET vector
outside cartridge ROM is fatal.

## Address identity

Every later fact must preserve this identity:

```text
(platform=snes, cpu_id=w65c816, address_space=cpu, logical_address,
 mapping=lorom|hirom, physical_offset?)
```

For LoROM, the generic ROM projection is
`((bank & $7F) << 15) | (address & $7FFF)` in valid ROM windows. For HiROM it is
`((bank & $3F) << 16) | address`. File-size mirroring is then resolved against
the actual payload. Conversion APIs expose one canonical logical address and the
standard direct aliases of every physical ROM byte.

The manifest enumerates ROM, WRAM and declared SRAM bus windows by inclusive
bank and 16-bit address bounds. Full `$7E-$7F` WRAM and low-bank `$0000-$1FFF`
mirrors map to one 128 KiB space. Plain LoROM SRAM uses the lower halves of
`$70-$7D/$F0-$FF`; plain HiROM SRAM uses `$6000-$7FFF` in `$20-$3F/$A0-$BF`.
Board-specific enhancement mappings are outside v1.

## Container ownership

The component records separate hashes for the complete input container and the
headerless cartridge payload. Its regions form an ordered byte partition:
optional copier header, ROM before the internal header, the 64-byte internal
header/vector block and ROM after it. The copier header is preserved as data; it
never shifts CPU-visible ROM offsets.

This component is intentionally earlier than `retrolarium.snes.disassembly`. It
contains no guessed instructions, symbols or pointer tables. Those will be
separate evidence-bearing components so that Ghidra output cannot silently alter
cartridge facts.

## Synthetic conformance pair

`snes.lorom_probe` and `snes.hirom_probe` build the same project-owned W65C816
program into different physical layouts. The source exercises emulation-to-
native transition, `REP`/`SEP` M/X changes, 8/16-bit immediates, near and far
calls, branches, native/emulation vectors, and four pointer encodings:
current-bank u16le, far u24le, split low/high/bank and signed table-relative
u16le. It also performs an explicit fixed-size upload of a six-byte SPC700
program through the SNES APU I/O ports. `oracle.json` binds logical truth to
each ROM hash, but is never an input to blind analysis.

The pinned fixture build produces:

| Fixture            | Mapping |    Size | SHA-256                                                            |
| ------------------ | ------- | ------: | ------------------------------------------------------------------ |
| `snes.lorom_probe` | LoROM   | 131,072 | `5dc904609e07c74d5ad21f02be215e08f3f742eaa42cc436a9afdc9cd83d6574` |
| `snes.hirom_probe` | HiROM   | 131,072 | `acb319fa6129aedf28b91031a4c6d3693af4e550f9f8cd2c1c3f6d548ff31f6a` |

Both have valid mirrored checksums and rebuild from one ca65 object through a
deterministic packer. Generated ROMs, Docker images and working directories
remain ignored artifacts.

## Pinned disassembly backend

The 65816 processor definition is pinned independently from cartridge parsing:

- upstream: `joshleaves/ghidra-snes` commit
  `d33ce5dbfbc3645f00449be1c7ca1c1c65e81756`, version 1.3.2;
- license: MIT, preserved as `LICENSE.upstream` in the installed extension;
- language: `65816:LE:24:snes`;
- verified host: Ghidra 12.1.3;
- source archive size and SHA-256: recorded in
  `src/retrolarium_disassembler/toolchains/disassembly.lock.json`.

`rldisasm ghidra install` extracts only the upstream `data/languages` processor
material, compiles `65816.slaspec` with the pinned Ghidra SLEIGH compiler and
installs it as `Retrolarium65816`. The upstream Java cartridge loader is not
installed: Retrolarium creates explicit per-bank raw analysis inputs from the
validated component instead.

A headless smoke on the synthetic probe produced a 24-bit `bus` Program and
correctly decoded the M/X-dependent 8-bit and 16-bit immediate instructions.
Backend flow/reference classifications remain untrusted candidates; the smoke
also demonstrates why Retrolarium must independently derive and validate state,
flow and physical-byte facts before publishing them.

## Independent W65C816 state analysis

`rldisasm snes analyze` now runs a Retrolarium-owned decoder covering all 256
W65C816 opcodes. Entry states come from the validated native/emulation vectors;
RESET starts with `E=M=X=1`, `PBR=DBR=DP=0`. The worklist propagates E, M, X,
carry, PBR, DBR, Direct Page and limited accumulator/stack evidence. It handles
`CLC`/`SEC`/`XCE`, `REP`/`SEP`, status pulls, the common `PHK; PLB` data-bank
idiom and `LDA #imm16; TCD` Direct Page idiom.

Immediate operand length is never guessed when M or X is unknown. Conflicting
control-flow states are widened to unknown in a convergent fixed point, stale
downstream decodes are discarded, and an `ambiguous-width` diagnostic stops that
path. Near flow retains PBR, far flow carries its explicit 24-bit bank, and
every accepted instruction records the original physical ROM offset and bytes.
Ghidra facts are accepted only when address projection, bytes, length and
mnemonic agree with this independent result; backend-only speculative code is
not promoted.

## Pointer and symbol evidence

The blind analyzer publishes five explicit pointer schemas:

- `snes.vectors.u16le.bank00` for the validated native/emulation vector block;
- `snes.u16le.current-bank` for near pointers whose bank comes from the table;
- `snes.u24le.far` for explicit little-endian 24-bit pointers;
- `snes.split-lo-hi-bank` for parallel component arrays;
- `snes.s16le.table-base` for signed offsets relative to the table start.

A generic data run is accepted only when at least three consecutive entries map
to independently decoded instruction starts and none targets an instruction
interior or the table itself. Reports preserve raw values, logical and physical
locations, bases/components, positive evidence and contradictions. On both probe
layouts the detector recovers exactly the four authored data tables plus the
vector table, despite their different physical offsets.

Stable logical names are derived from evidence rather than discovery order:
`Entry_SNES_AAAAAA`, `Sub_SNES_AAAAAA`, `Loc_SNES_AAAAAA`, `Tbl_SNES_AAAAAA`,
`Vec_SNES_AAAAAA` and `Off_SNES_AAAAAA`. Vector-specific names remain aliases.
The LoROM and HiROM probes therefore produce the same ten logical symbols while
retaining different physical offsets.

## Exact-first source emission

`rldisasm snes disassemble` emits a complete ca65 project with one source unit
per physical 32 KiB LoROM bank or 64 KiB HiROM bank. `header.asm` owns the
internal header, stored checksum/complement and symbolic vectors; `symbols.inc`
separates stable 24-bit logical names from physical source labels. Accepted
tables use `.word`, `.faraddr`, `.lobytes`, `.hibytes`, `.bankbytes` and
relocatable signed expressions. Independently decoded instructions use W65C816
mnemonics with explicit `.a8/.a16` and `.i8/.i16` context; an unsupported
encoding falls back only for that instruction.

Every remaining byte is explicit `.byte` data in its bank module. The coverage
report proves that instruction, instruction-fallback, pointer, header and raw
ranges partition the ROM exactly once. There is no whole-ROM `incbin`; only an
optional 512-byte copier header is allowed as a separate hashed container asset.
The pinned Docker ca65/ld65 build reproduces both synthetic ROMs byte-for-byte
with their original SHA-256 and a valid SNES checksum.

## SPC700 program boundary

`rldisasm ghidra install` also pins the MIT-licensed `Raikaru/ghidra-spc700`
processor at commit `af628ce1a8e86ae1382dcec4c03d4412e013890c`, installs it as
`RetrolariumSPC700`, and compiles language `SPC700:LE:16:default` with the same
Ghidra 12.1.3 SLEIGH compiler.

SPC700 extraction is deliberately evidence-gated. Version 1 recognizes an
explicit `PHK; PLB` data-bank setup followed by a 16-bit destination write to
`$2142/$2143` and a fixed-count indexed ROM copy through `$2141`, with the
counter written through `$2140`. Source mapping, destination, count, loop-back,
non-overlap with decoded 65816 code and every payload byte must all be proven. A
coincidental byte sequence that merely decodes as SPC700 is never promoted.

Every accepted upload produces a hashed payload, a
`retrolarium.cross-cpu-evidence` edge and an independent Ghidra Program in the
`spc700-ram` address space. Bytes without complete upload evidence remain raw,
opaque source assets. Blind LoROM and HiROM runs each recover one six-byte
program at SPC RAM `$0200`, decode three SPC700 instructions, and still rebuild
the complete cartridge exactly with a valid checksum.

The project manifest, its operations and the blind holdout boundary are
specified in [`snes_disassembly.md`](snes_disassembly.md).
