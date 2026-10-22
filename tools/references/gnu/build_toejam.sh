#!/bin/sh
# Run on a disposable copy of tje-disasm, with tjae_rev02.bin in /work.
set -eu
cd /work
mkdir -p obj
export SDL_VIDEODRIVER=dummy
python3 tools/extract_resources.py resources.cfg tjae_rev02.bin
m68k-linux-gnu-cpp -D__z80__ -I include -E src/SoundDriver.z80.S -o obj/SoundDriver.tmp.s
z80-unknown-coff-as obj/SoundDriver.tmp.s -o obj/SoundDriver.z80.o
z80-unknown-coff-objcopy -O binary obj/SoundDriver.z80.o obj/SoundDriver.z80.bin
for unit in vectors header main; do
    m68k-linux-gnu-gcc -E -P -DGAME_REVISION=2 -Iinclude src/$unit.S -o obj/$unit.s
    m68k-linux-gnu-as -m68000 --bitwise-or --register-prefix-optional -alhmnd=obj/$unit.lst obj/$unit.s -o obj/$unit.o
done
m68k-linux-gnu-ld -T src/genesis.ld --build-id=none -Map=obj/target.map obj/vectors.o obj/header.o obj/main.o -o obj/target.elf
m68k-linux-gnu-objcopy -O binary obj/target.elf obj/target.bin
cmp tjae_rev02.bin obj/target.bin
cat obj/vectors.s obj/header.s obj/main.s >obj/combined.s
m68k-linux-gnu-as -m68000 --bitwise-or --register-prefix-optional -alhmnd=obj/combined.lst obj/combined.s -o obj/combined.o
m68k-linux-gnu-ld -T src/genesis.ld --build-id=none -Map=obj/combined.map obj/combined.o -o obj/combined.elf
m68k-linux-gnu-objcopy -O binary obj/combined.elf obj/combined.bin
cmp obj/target.bin obj/combined.bin
sha256sum tjae_rev02.bin obj/target.bin obj/combined.bin
