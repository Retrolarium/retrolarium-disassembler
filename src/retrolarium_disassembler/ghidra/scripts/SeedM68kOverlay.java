// Seed code in a standalone M68K overlay using addresses derived from its binary header.
// @category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SeedM68kOverlay extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("overlay seed plan path is required");
        }
        MemoryBlock module = currentProgram.getMemory().getBlock("CD_MODULE");
        if (module == null || !module.isInitialized()) {
            throw new IllegalStateException("initialized CD_MODULE block not found");
        }
        module.setWrite(false);
        module.setExecute(true);
        Path plan = Paths.get(args[0]);
        int seeded = 0;
        for (String raw : Files.readAllLines(plan)) {
            String line = raw.split("#", 2)[0].trim();
            if (line.isEmpty()) {
                continue;
            }
            long value = Long.parseUnsignedLong(line, 16);
            Address address = module.getStart().getAddressSpace().getAddress(value);
            if ((value & 1) != 0 || !module.contains(address)) {
                throw new IllegalArgumentException("seed outside overlay: " + line);
            }
            if (disassemble(address)) {
                seeded++;
            }
        }
        println("[OK] seeded " + seeded + " overlay entry points");
    }
}
