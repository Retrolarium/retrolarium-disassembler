.PHONY: all clean

all: cnrom_probe.nes

build/main.o: main.asm
	mkdir -p build
	ca65 -g -o $@ $<

build/prg.bin: build/main.o linker.cfg
	ld65 -C linker.cfg -m build/cnrom_probe.map -o $@ $<

cnrom_probe.nes: build/prg.bin pack.py
	python3 pack.py $< $@

clean:
	rm -rf build cnrom_probe.nes
