.PHONY: all clean

BANKS := build/bank0.bin build/bank1.bin build/bank2.bin build/bank3.bin

all: gnrom_probe.nes

build/bank%.o: bank.asm
	mkdir -p build
	ca65 -g -D BANK_ID=$* -o $@ $<

build/bank%.bin: build/bank%.o bank.cfg
	ld65 -C bank.cfg -m build/bank$*.map -o $@ $<

gnrom_probe.nes: $(BANKS) pack.py
	python3 pack.py $@ $(BANKS)

clean:
	rm -rf build gnrom_probe.nes
