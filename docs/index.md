# Retrolarium Disassembler documentation

The contracts of the projects `rldisasm` writes. Each names the JSON schema its
manifest follows (the schemas ship with retrolarium-core).

- [nes_disassembly.md](nes_disassembly.md): an NES disassembly project
  (`retrolarium.nes.disassembly`): banks, address identity, artifacts, the fixed
  build, verify and launch operations.
- [megadrive_disassembly.md](megadrive_disassembly.md): a Mega Drive project
  (`retrolarium.megadrive.disassembly`): 68000 and Z80 programs, cross-CPU
  evidence, the AS/p2bin build.
- [snes_image.md](snes_image.md): an inspected SNES cartridge
  (`retrolarium.snes.image`): mapping, header, vectors, bus windows.
- [snes_disassembly.md](snes_disassembly.md): an SNES project
  (`retrolarium.snes.disassembly`): W65C816 and SPC700 programs and the blind
  validation baseline.
