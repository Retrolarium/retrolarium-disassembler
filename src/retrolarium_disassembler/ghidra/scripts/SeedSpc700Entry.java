// Seed an extracted Mega Drive Z80 RAM program at logical address zero.
//@category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SeedZ80Entry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock ram = memory.getBlock("Z80_RAM");
        if (ram == null || !ram.isInitialized()) {
            throw new IllegalStateException("initialized Z80_RAM block not found");
        }
        ram.setWrite(true);
        ram.setExecute(true);
        Address entry = ram.getStart();
        createLabel(entry, "Z80_Entry", true);
        if (!disassemble(entry)) {
            throw new IllegalStateException("cannot disassemble Z80 entry point");
        }
        println("[OK] seeded Mega Drive Z80 entry " + entry);
    }
}
