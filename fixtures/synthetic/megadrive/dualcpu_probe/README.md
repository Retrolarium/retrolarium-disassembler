# Mega Drive dual-CPU probe

Project-owned 1 KiB cartridge fixture with a small Motorola 68000 program and
an embedded Z80 program. The 68000 explicitly acquires the sound bus, copies
the payload from ROM to `$A00000`, releases reset and the bus, and then loops.

The fixture also contains known absolute-long and signed PC-relative pointer
tables. `oracle.json` belongs to the benchmark harness only: the disassembly
pipeline must receive the built ROM, never this source directory or oracle.

The ROM is a generated test artifact and is not tracked.
