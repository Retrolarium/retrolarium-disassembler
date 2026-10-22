// Seed an extracted Mega Drive Z80 RAM program at logical address zero and,
// when IM 1 and EI are decoded, its RST 38h interrupt handler.
// @category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class SeedZ80Entry extends GhidraScript {
    private static class TableRange {
        final long start;
        final long end;

        TableRange(long start, long end) {
            this.start = start;
            this.end = end;
        }
    }

    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock ram = memory.getBlock("Z80_RAM");
        if (ram == null || !ram.isInitialized()) {
            throw new IllegalStateException("initialized Z80_RAM block not found");
        }
        ram.setWrite(true);
        ram.setExecute(true);
        List<TableRange> tables = new ArrayList<>();
        List<Long> targets = new ArrayList<>();
        String[] arguments = getScriptArgs();
        if (arguments.length > 1) {
            throw new IllegalArgumentException("at most one Z80 seed plan is allowed");
        }
        if (arguments.length == 1) {
            Path plan = Paths.get(arguments[0]);
            for (String raw : Files.readAllLines(plan)) {
                String line = raw.split("#", 2)[0].trim();
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split("\\s+");
                if (parts.length == 3 && parts[0].equals("T")) {
                    long start = Long.parseLong(parts[1], 16);
                    long end = Long.parseLong(parts[2], 16);
                    if (start < 0
                            || end > ram.getSize()
                            || start >= end
                            || (end - start) % 2 != 0) {
                        throw new IllegalArgumentException("invalid Z80 word table: " + line);
                    }
                    tables.add(new TableRange(start, end));
                } else if (parts.length == 2 && parts[0].equals("S")) {
                    long target = Long.parseLong(parts[1], 16);
                    if (target < 0 || target >= ram.getSize()) {
                        throw new IllegalArgumentException("invalid Z80 seed: " + line);
                    }
                    targets.add(target);
                } else {
                    throw new IllegalArgumentException("invalid Z80 seed plan: " + line);
                }
            }
        }
        for (TableRange table : tables) {
            for (long offset = table.start; offset < table.end; offset += 2) {
                createData(ram.getStart().add(offset), WordDataType.dataType);
            }
            println(
                    String.format(
                            "[TABLE] Z80 word dispatch 0x%04X..0x%04X", table.start, table.end));
        }
        Address entry = ram.getStart();
        // Only an image loaded at logical zero contains the reset entry; a
        // segment copied elsewhere is decoded solely from explicit seeds.
        boolean hasReset = entry.getOffset() == 0;
        if (hasReset) {
            createLabel(entry, "Z80_Entry", true);
            if (!disassemble(entry)) {
                throw new IllegalStateException("cannot disassemble Z80 entry point");
            }
        }
        int seeded = 0;
        for (long target : targets) {
            Address address = ram.getStart().add(target);
            if (disassemble(address)) {
                seeded++;
            }
        }
        boolean im1 = false;
        if (hasReset && usesInterruptMode1(ram)) {
            Address vector = entry.add(IM1_VECTOR);
            if (ram.contains(vector)) {
                createLabel(vector, "Z80_IM1_Handler", true);
                im1 =
                        disassemble(vector)
                                || currentProgram.getListing().getInstructionAt(vector) != null;
            }
        }
        println(
                "[OK] seeded Mega Drive Z80 entry "
                        + entry
                        + ", "
                        + seeded
                        + " dispatch targets"
                        + (im1 ? " and IM1 handler" : ""));
    }

    private static final long IM1_VECTOR = 0x38;

    // IM 1 (ED 56) together with EI (FB) in decoded code proves RST 38h use.
    private boolean usesInterruptMode1(MemoryBlock ram) throws Exception {
        boolean im1 = false;
        boolean ei = false;
        InstructionIterator iterator =
                currentProgram
                        .getListing()
                        .getInstructions(new AddressSet(ram.getStart(), ram.getEnd()), true);
        while (iterator.hasNext()) {
            byte[] bytes = iterator.next().getBytes();
            if (bytes.length == 2 && (bytes[0] & 0xFF) == 0xED && (bytes[1] & 0xFF) == 0x56) {
                im1 = true;
            } else if (bytes.length == 1 && (bytes[0] & 0xFF) == 0xFB) {
                ei = true;
            }
        }
        return im1 && ei;
    }
}
