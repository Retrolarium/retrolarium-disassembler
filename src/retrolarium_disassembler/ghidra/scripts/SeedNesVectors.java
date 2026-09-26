// Seed analysis from NES interrupt vectors in every executable PRG space.
// Optional argument: path to a seed plan with one hexadecimal CPU address
// per line; each address is disassembled in every executable PRG space
// whose initialized block contains it.

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SeedNesVectors extends GhidraScript {
    private static final long[] VECTOR_OFFSETS = {0xfffaL, 0xfffcL, 0xfffeL};
    private static final String[] VECTOR_NAMES = {"NMI", "RESET", "IRQ"};

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 1) {
            throw new IllegalArgumentException(
                "usage: SeedNesVectors.java [seed-plan]");
        }
        List<Long> planned = args.length == 1 ? readPlan(args[0]) : new ArrayList<>();

        Memory memory = currentProgram.getMemory();
        int seeded = 0;
        List<AddressSpace> spaces = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            AddressSpace space = block.getStart().getAddressSpace();
            if (!spaces.contains(space)) {
                spaces.add(space);
            }
            for (int index = 0; index < VECTOR_OFFSETS.length; index++) {
                Address vector = space.getAddress(VECTOR_OFFSETS[index]);
                if (!block.contains(vector) || !block.contains(vector.add(1))) {
                    continue;
                }
                int low = memory.getByte(vector) & 0xff;
                int high = memory.getByte(vector.add(1)) & 0xff;
                Address target = space.getAddress(low | (high << 8));
                if (!isExecutable(memory, target)) {
                    println("[SKIP] " + space.getName() + " "
                        + VECTOR_NAMES[index] + " target " + target);
                    continue;
                }
                if (disassemble(target)) {
                    seeded++;
                }
                println("[SEED] " + space.getName() + " "
                    + VECTOR_NAMES[index] + " target " + target);
            }
        }
        println("[OK] seeded " + seeded + " NES vector targets");

        int planSeeded = 0;
        for (long offset : planned) {
            boolean placed = false;
            for (AddressSpace space : spaces) {
                Address target = space.getAddress(offset);
                if (!isExecutable(memory, target)) {
                    continue;
                }
                placed = true;
                if (disassemble(target)) {
                    planSeeded++;
                }
                println("[SEED] " + space.getName() + " plan target " + target);
            }
            if (!placed) {
                println(String.format("[SKIP] plan target %04X not executable", offset));
            }
        }
        if (args.length == 1) {
            println("[OK] seeded " + planSeeded + " of " + planned.size()
                + " NES plan targets");
        }
    }

    private static boolean isExecutable(Memory memory, Address target) {
        MemoryBlock block = memory.getBlock(target);
        return block != null && block.isInitialized() && block.isExecute();
    }

    private static List<Long> readPlan(String argument) throws Exception {
        Path plan = Paths.get(argument);
        if (!Files.isRegularFile(plan)) {
            throw new IllegalArgumentException("NES seed plan not found: " + plan);
        }
        List<Long> addresses = new ArrayList<>();
        int lineNumber = 0;
        for (String raw : Files.readAllLines(plan, StandardCharsets.UTF_8)) {
            lineNumber++;
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            if (!line.matches("[0-9A-Fa-f]{1,4}")) {
                throw new IllegalArgumentException(
                    "invalid NES seed at line " + lineNumber + ": " + raw);
            }
            long address = Long.parseLong(line, 16);
            if (!addresses.contains(address)) {
                addresses.add(address);
            }
        }
        return addresses;
    }
}
