// Seed analysis from NES interrupt vectors in every executable PRG space.

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
        Memory memory = currentProgram.getMemory();
        int seeded = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            AddressSpace space = block.getStart().getAddressSpace();
            for (int index = 0; index < VECTOR_OFFSETS.length; index++) {
                Address vector = space.getAddress(VECTOR_OFFSETS[index]);
                if (!block.contains(vector) || !block.contains(vector.add(1))) {
                    continue;
                }
                int low = memory.getByte(vector) & 0xff;
                int high = memory.getByte(vector.add(1)) & 0xff;
                Address target = space.getAddress(low | (high << 8));
                MemoryBlock targetBlock = memory.getBlock(target);
                if (targetBlock == null || !targetBlock.isInitialized()
                        || !targetBlock.isExecute()) {
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
    }
}
