.PHONY: all lorom hirom clean

all: lorom hirom

lorom: snes-lorom-probe.sfc

hirom: snes-hirom-probe.sfc

build/probe.o: probe.asm
	mkdir -p build
	ca65 -g -o $@ $<

build/code.bin: build/probe.o linker.cfg
	ld65 -C linker.cfg -Ln build/labels.txt -m build/probe.map -o $@ $<

snes-lorom-probe.sfc: build/code.bin build/labels.txt pack.py
	python3 pack.py lorom build/code.bin build/labels.txt $@

snes-hirom-probe.sfc: build/code.bin build/labels.txt pack.py
	python3 pack.py hirom build/code.bin build/labels.txt $@

clean:
	rm -rf build snes-lorom-probe.sfc snes-hirom-probe.sfc

