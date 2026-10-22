// Apply a Python-produced 68000 decoder plan and name cartridge vectors.
// @category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

public class SeedMegaDriveVectors extends GhidraScript {
    private static final String[] VECTOR_NAMES = {
        "InitialSsp",
        "Reset",
        "BusError",
        "AddressError",
        "IllegalInstruction",
        "DivisionByZero",
        "Chk",
        "Trapv",
        "PrivilegeViolation",
        "Trace",
        "Line1010",
        "Line1111",
        "Reserved12",
        "Reserved13",
        "Reserved14",
        "UninitializedInterrupt",
        "Reserved16",
        "Reserved17",
        "Reserved18",
        "Reserved19",
        "Reserved20",
        "Reserved21",
        "Reserved22",
        "Reserved23",
        "SpuriousInterrupt",
        "Level1Interrupt",
        "Level2Interrupt",
        "Level3Interrupt",
        "Level4Interrupt",
        "Level5Interrupt",
        "Level6Interrupt",
        "Level7Interrupt",
        "Trap0",
        "Trap1",
        "Trap2",
        "Trap3",
        "Trap4",
        "Trap5",
        "Trap6",
        "Trap7",
        "Trap8",
        "Trap9",
        "Trap10",
        "Trap11",
        "Trap12",
        "Trap13",
        "Trap14",
        "Trap15",
        "Reserved48",
        "Reserved49",
        "Reserved50",
        "Reserved51",
        "Reserved52",
        "Reserved53",
        "Reserved54",
        "Reserved55",
        "Reserved56",
        "Reserved57",
        "Reserved58",
        "Reserved59",
        "Reserved60",
        "Reserved61",
        "Reserved62",
        "Reserved63"
    };

    private static long readUnsignedBigEndianLong(Memory memory, Address address) throws Exception {
        return ((long) (memory.getByte(address) & 0xff) << 24)
                | ((long) (memory.getByte(address.add(1)) & 0xff) << 16)
                | ((long) (memory.getByte(address.add(2)) & 0xff) << 8)
                | (long) (memory.getByte(address.add(3)) & 0xff);
    }

    private boolean seedAddress(MemoryBlock rom, long offset, Set<Long> disassembled)
            throws Exception {
        if (offset < 0x200
                || (offset & 1) != 0
                || offset >= rom.getSize()
                || !disassembled.add(offset)) {
            return false;
        }
        return disassemble(rom.getStart().add(offset));
    }

    private int seedPythonPlan(MemoryBlock rom, Set<Long> disassembled) throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("Python decoder seed plan path is required");
        }
        Path plan = Paths.get(arguments[0]);
        int seeded = 0;
        // Inline arguments proven by Python must exist as data BEFORE any
        // root is decoded, so TRAP fall-through cannot swallow continuation
        // instructions as operands of an accidental decode.
        for (String raw : Files.readAllLines(plan)) {
            String line = raw.split("#", 2)[0].trim();
            if (!line.startsWith("DATA ")) continue;
            String[] fields = line.split("\\s+");
            if (fields.length != 3)
                throw new IllegalArgumentException("invalid inline-data range: " + line);
            long offset = Long.parseLong(fields[1], 16);
            int size = Integer.parseInt(fields[2]);
            if (size < 2
                    || size > 32
                    || (size & 1) != 0
                    || offset < 0x200
                    || offset + size > rom.getSize()
                    || (offset & 1) != 0)
                throw new IllegalArgumentException("invalid inline-data range: " + line);
            Address address = rom.getStart().add(offset);
            clearListing(address, address.add(size - 1));
            createData(address, new ArrayDataType(ByteDataType.dataType, size, 1));
        }
        for (String raw : Files.readAllLines(plan)) {
            String line = raw.split("#", 2)[0].trim();
            if (line.isEmpty() || line.startsWith("DATA ")) {
                continue;
            }
            long target = Long.parseLong(line, 16);
            if (seedAddress(rom, target, disassembled)) {
                seeded++;
                println(String.format("[SEED] Python decoder target 0x%06X", target));
            }
        }
        return seeded;
    }

    private int labelVectors(MemoryBlock rom, Memory memory) throws Exception {
        AddressSpace space = rom.getStart().getAddressSpace();
        int labels = 0;
        for (int index = 1; index < VECTOR_NAMES.length; index++) {
            Address slot = rom.getStart().add(index * 4L);
            if (!rom.contains(slot) || !rom.contains(slot.add(3))) {
                break;
            }
            long raw = readUnsignedBigEndianLong(memory, slot);
            long busAddress = raw & 0x00ffffffL;
            Address target = space.getAddress(busAddress);
            if (busAddress < 0x200 || memory.getBlock(target) != rom) {
                continue;
            }
            createLabel(target, "Vector_" + VECTOR_NAMES[index], index == 1);
            labels++;
            println(String.format("[LABEL] vector %d raw 0x%08X target %s", index, raw, target));
        }
        return labels;
    }

    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock rom = memory.getBlock("ROM");
        if (rom == null || !rom.isInitialized()) {
            throw new IllegalStateException("initialized ROM block not found");
        }
        rom.setWrite(false);
        rom.setExecute(true);
        int labels = labelVectors(rom, memory);
        int pythonTargets = seedPythonPlan(rom, new HashSet<>());
        println(
                "[OK] created "
                        + labels
                        + " vector labels and seeded "
                        + pythonTargets
                        + " Python decoder targets");
    }
}
