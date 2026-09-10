// Seed 68000 analysis from the Mega Drive cartridge vector table.
//@category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.HashSet;
import java.util.Set;

public class SeedMegaDriveVectors extends GhidraScript {
    private static final String[] VECTOR_NAMES = {
        "InitialSsp", "Reset", "BusError", "AddressError",
        "IllegalInstruction", "DivisionByZero", "Chk", "Trapv",
        "PrivilegeViolation", "Trace", "Line1010", "Line1111",
        "Reserved12", "Reserved13", "Reserved14", "UninitializedInterrupt",
        "Reserved16", "Reserved17", "Reserved18", "Reserved19",
        "Reserved20", "Reserved21", "Reserved22", "Reserved23",
        "SpuriousInterrupt", "Level1Interrupt", "Level2Interrupt",
        "Level3Interrupt", "Level4Interrupt", "Level5Interrupt",
        "Level6Interrupt", "Level7Interrupt", "Trap0", "Trap1", "Trap2",
        "Trap3", "Trap4", "Trap5", "Trap6", "Trap7", "Trap8", "Trap9",
        "Trap10", "Trap11", "Trap12", "Trap13", "Trap14", "Trap15",
        "Reserved48", "Reserved49", "Reserved50", "Reserved51",
        "Reserved52", "Reserved53", "Reserved54", "Reserved55",
        "Reserved56", "Reserved57", "Reserved58", "Reserved59",
        "Reserved60", "Reserved61", "Reserved62", "Reserved63"
    };

    private static long readUnsignedBigEndianLong(Memory memory, Address address)
            throws Exception {
        return ((long) (memory.getByte(address) & 0xff) << 24)
            | ((long) (memory.getByte(address.add(1)) & 0xff) << 16)
            | ((long) (memory.getByte(address.add(2)) & 0xff) << 8)
            | (long) (memory.getByte(address.add(3)) & 0xff);
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
        AddressSpace space = rom.getStart().getAddressSpace();
        int seeded = 0;
        Set<Long> disassembled = new HashSet<>();
        for (int index = 1; index < VECTOR_NAMES.length; index++) {
            Address slot = rom.getStart().add(index * 4L);
            if (!rom.contains(slot) || !rom.contains(slot.add(3))) {
                break;
            }
            long raw = readUnsignedBigEndianLong(memory, slot);
            long busAddress = raw & 0x00ffffffL;
            Address target = space.getAddress(busAddress);
            MemoryBlock targetBlock = memory.getBlock(target);
            if (busAddress < 0x200 || targetBlock != rom) {
                continue;
            }
            createLabel(target, "Vector_" + VECTOR_NAMES[index], index == 1);
            if (disassembled.add(busAddress) && disassemble(target)) {
                seeded++;
            }
            println(String.format(
                "[SEED] vector %d raw 0x%08X target %s",
                index, raw, target
            ));
        }
        println("[OK] seeded " + seeded + " Mega Drive vector targets");
    }
}
