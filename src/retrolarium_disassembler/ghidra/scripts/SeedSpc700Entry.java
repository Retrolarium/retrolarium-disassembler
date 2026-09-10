// Seed one statically proven SNES SPC700 upload as an independent Program.
//@category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SeedSpc700Entry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock ram = memory.getBlock("SPC700_RAM");
        if (ram == null || !ram.isInitialized()) {
            throw new IllegalStateException("initialized SPC700_RAM block not found");
        }
        ram.setWrite(true);
        ram.setExecute(true);
        Address entry = ram.getStart();
        createLabel(entry, "SPC700_Entry", true);
        if (!disassemble(entry)) {
            throw new IllegalStateException("cannot disassemble SPC700 entry point");
        }
        println("[OK] seeded SNES SPC700 entry " + entry);
    }
}
