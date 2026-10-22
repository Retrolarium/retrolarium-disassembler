// Seed one physical SNES ROM bank using an independently computed context plan.
// @category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class SeedSnesBank extends GhidraScript {
    private static long parseHex(String value) {
        return Long.parseUnsignedLong(value, 16);
    }

    private static void setContext(
            ProgramContext context, Register register, Address start, Address end, String raw)
            throws Exception {
        if (raw.equals("?")) {
            return;
        }
        int value = Integer.parseInt(raw);
        if (value != 0 && value != 1) {
            throw new IllegalArgumentException("context bits must be 0, 1 or ?");
        }
        context.setRegisterValue(
                start, end, new RegisterValue(register, BigInteger.valueOf(value)));
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                    "expected block name, entry hex address and context TSV path");
        }
        Memory memory = currentProgram.getMemory();
        MemoryBlock rom = memory.getBlock(args[0]);
        if (rom == null || !rom.isInitialized()) {
            throw new IllegalStateException("initialized SNES ROM block not found");
        }
        rom.setWrite(false);
        rom.setExecute(true);
        AddressSpace space = rom.getStart().getAddressSpace();
        ProgramContext context = currentProgram.getProgramContext();
        Register ef = context.getRegister("ctx_EF");
        Register mf = context.getRegister("ctx_MF");
        Register xf = context.getRegister("ctx_XF");
        if (ef == null || mf == null || xf == null) {
            throw new IllegalStateException("65816 E/M/X context registers not found");
        }

        List<String> lines =
                Files.readAllLines(Path.of(args[2]).toAbsolutePath(), StandardCharsets.UTF_8);
        int ranges = 0;
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\\t", -1);
            if (fields.length != 5) {
                throw new IllegalArgumentException("invalid SNES context TSV line: " + line);
            }
            Address start = space.getAddress(parseHex(fields[0]));
            Address end = space.getAddress(parseHex(fields[1]));
            if (!rom.contains(start) || !rom.contains(end) || end.compareTo(start) < 0) {
                throw new IllegalArgumentException("context range is outside SNES ROM block");
            }
            setContext(context, ef, start, end, fields[2]);
            setContext(context, mf, start, end, fields[3]);
            setContext(context, xf, start, end, fields[4]);
            ranges++;
        }

        Address entry = space.getAddress(parseHex(args[1]));
        if (!rom.contains(entry)) {
            throw new IllegalArgumentException("SNES entry is outside ROM block");
        }
        createLabel(entry, "SNES_Entry", true);
        if (!disassemble(entry)) {
            throw new IllegalStateException("cannot disassemble SNES entry point");
        }
        println("[OK] seeded SNES entry " + entry + " with " + ranges + " context ranges");
    }
}
