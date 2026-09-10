# SNES mapping and processor-state probe

Project-owned 128 KiB LoROM and HiROM images built from the same W65C816
program. The program enters native mode, changes accumulator/index widths with
`REP` and `SEP`, and exercises near/far calls, branches and interrupt returns.

Known data covers current-bank 16-bit pointers, 24-bit far pointers, split
low/high/bank lanes and signed offsets. Both images contain native and
emulation vectors plus a valid checksum/complement pair.

The built `.sfc`, linker outputs and generated label file are reproducible test
artifacts and are not tracked. Source/oracle material must never be passed to a
blind analyzer.
