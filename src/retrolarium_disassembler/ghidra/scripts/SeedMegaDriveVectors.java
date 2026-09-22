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

    private static int readWord(Memory memory, Address address) throws Exception {
        return ((memory.getByte(address) & 0xff) << 8)
            | (memory.getByte(address.add(1)) & 0xff);
    }

    private boolean seedAddress(MemoryBlock rom, long offset, Set<Long> disassembled)
            throws Exception {
        if (offset < 0x200 || (offset & 1) != 0 || offset >= rom.getSize()
                || !disassembled.add(offset)) {
            return false;
        }
        return disassemble(rom.getStart().add(offset));
    }

    // The 68000 may execute a copy in RAM. Its ROM origin is still code and
    // needs an entry point for static analysis. Recognize the complete copy
    // idiom, including the count, backwards DBF and jump to the RAM target.
    private int seedRamCopyOrigins(MemoryBlock rom, Memory memory,
            Set<Long> disassembled) throws Exception {
        int seeded = 0;
        for (long offset = 0x200; offset + 28 <= rom.getSize(); offset += 2) {
            Address at = rom.getStart().add(offset);
            if (readWord(memory, at) != 0x41f9
                    || readWord(memory, at.add(6)) != 0x43f9
                    || readWord(memory, at.add(12)) != 0x303c
                    || readWord(memory, at.add(16)) != 0x22d8
                    || readWord(memory, at.add(18)) != 0x51c8
                    || readWord(memory, at.add(20)) != 0xfffc
                    || readWord(memory, at.add(22)) != 0x4ef9) {
                continue;
            }
            long source = readUnsignedBigEndianLong(memory, at.add(2));
            long destination = readUnsignedBigEndianLong(memory, at.add(8));
            long jump = readUnsignedBigEndianLong(memory, at.add(24));
            long length = (readWord(memory, at.add(14)) + 1L) * 4;
            if (destination != jump || source < 0x200
                    || (source & 1) != 0 || source + length > rom.getSize()
                    || (destination & 0xff0000L) != 0xff0000L) {
                continue;
            }
            if (seedAddress(rom, source, disassembled)) {
                seeded++;
                println(String.format("[SEED] RAM copy ROM 0x%06X -> RAM 0x%06X, %d bytes",
                    source, destination, length));
            }
        }
        return seeded;
    }

    // Indexed dispatch commonly lands on a dense run of BRA.W stubs. Require
    // four consecutive valid branches before seeding their ROM destinations.
    private int seedBranchTables(MemoryBlock rom, Memory memory,
            Set<Long> disassembled) throws Exception {
        int seeded = 0;
        for (long offset = 0x200; offset + 16 <= rom.getSize(); offset += 2) {
            long cursor = offset;
            while (cursor + 4 <= rom.getSize()) {
                Address at = rom.getStart().add(cursor);
                if (readWord(memory, at) != 0x6000) {
                    break;
                }
                long target = cursor + 2 + (short) readWord(memory, at.add(2));
                if (target < 0x200 || target >= rom.getSize()
                        || (target & 1) != 0) {
                    break;
                }
                cursor += 4;
            }
            if (cursor - offset < 16) {
                continue;
            }
            for (long entry = offset; entry < cursor; entry += 4) {
                long target = entry + 2
                    + (short) readWord(memory, rom.getStart().add(entry + 2));
                if (seedAddress(rom, target, disassembled)) {
                    seeded++;
                }
                seedAddress(rom, entry, disassembled);
            }
            println(String.format("[SEED] BRA.W dispatch table 0x%06X, %d entries",
                offset, (cursor - offset) / 4));
            offset = cursor - 2;
        }
        return seeded;
    }

    // A computed JSR/JMP through d8(PC,Dn.W) is direct evidence for a branch
    // table even when it has only two or three entries. The broad scanner
    // above deliberately requires four entries, so recover these smaller
    // dispatch tables from the validated 68000 addressing mode itself.
    private int seedIndexedBranchTables(MemoryBlock rom, Memory memory,
            Set<Long> disassembled) throws Exception {
        int seeded = 0;
        Set<Long> tables = new HashSet<>();
        for (long offset = 0x200; offset + 4 <= rom.getSize(); offset += 2) {
            Address at = rom.getStart().add(offset);
            int opcode = readWord(memory, at);
            if (opcode != 0x4ebb && opcode != 0x4efb) {
                continue;
            }
            int extension = readWord(memory, at.add(2));
            // Brief extension, Dn.W index, scale 1 (plain 68000 form).
            if ((extension & 0x8f00) != 0) {
                continue;
            }
            long table = offset + 2 + (byte) (extension & 0xff);
            if (table < 0x200 || (table & 1) != 0 || table + 8 > rom.getSize()
                    || !tables.add(table)) {
                continue;
            }
            long cursor = table;
            while (cursor + 4 <= rom.getSize() && cursor - table < 0x400) {
                Address entry = rom.getStart().add(cursor);
                if (readWord(memory, entry) != 0x6000) {
                    break;
                }
                long target = cursor + 2 + (short) readWord(memory, entry.add(2));
                if (target < 0x200 || target >= rom.getSize() || (target & 1) != 0) {
                    break;
                }
                cursor += 4;
            }
            if (cursor - table < 8) {
                continue;
            }
            for (long entry = table; entry < cursor; entry += 4) {
                long target = entry + 2
                    + (short) readWord(memory, rom.getStart().add(entry + 2));
                if (seedAddress(rom, target, disassembled)) {
                    seeded++;
                }
                seedAddress(rom, entry, disassembled);
            }
            println(String.format(
                "[SEED] indexed BRA.W dispatch table 0x%06X, %d entries",
                table, (cursor - table) / 4));
        }
        return seeded;
    }

    // A common dispatcher builds JMP abs.l trampolines in work RAM from a
    // counted ROM table of 16-bit code addresses. Recover the table only when
    // the loader's write of opcode 4EF9 and the DBF loop are both present.
    private int seedRamTrampolineTables(MemoryBlock rom, Memory memory,
            Set<Long> disassembled) throws Exception {
        int seeded = 0;
        for (long offset = 0x200; offset + 24 <= rom.getSize(); offset += 2) {
            Address at = rom.getStart().add(offset);
            if (readWord(memory, at) != 0x41fa
                    || readWord(memory, at.add(4)) != 0x43f8
                    || readWord(memory, at.add(8)) != 0x3018
                    || readWord(memory, at.add(10)) != 0x32fc
                    || readWord(memory, at.add(12)) != 0x4ef9
                    || readWord(memory, at.add(14)) != 0x7200
                    || readWord(memory, at.add(16)) != 0x3218
                    || readWord(memory, at.add(18)) != 0x22c1
                    || readWord(memory, at.add(20)) != 0x51c8
                    || readWord(memory, at.add(22)) != 0xfff4) {
                continue;
            }
            long table = offset + 2 + (short) readWord(memory, at.add(2));
            if (table < 0x200 || table + 4 > rom.getSize()
                    || (table & 1) != 0) {
                continue;
            }
            int count = readWord(memory, rom.getStart().add(table)) + 1;
            if (count < 4 || count > 1024 || table + 2L + count * 2L > rom.getSize()) {
                continue;
            }
            int valid = 0;
            for (int index = 0; index < count; index++) {
                long target = readWord(memory, rom.getStart().add(table + 2L + index * 2L));
                if (target >= 0x200 && target < rom.getSize() && (target & 1) == 0) {
                    valid++;
                }
            }
            if (valid != count) {
                continue;
            }
            for (int index = 0; index < count; index++) {
                long target = readWord(memory, rom.getStart().add(table + 2L + index * 2L));
                if (seedAddress(rom, target, disassembled)) {
                    seeded++;
                }
            }
            println(String.format("[SEED] RAM trampoline table 0x%06X, %d entries",
                table, count));
        }
        return seeded;
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
            if (seedAddress(rom, busAddress, disassembled)) {
                seeded++;
            }
            println(String.format(
                "[SEED] vector %d raw 0x%08X target %s",
                index, raw, target
            ));
        }
        int copies = seedRamCopyOrigins(rom, memory, disassembled);
        int indexedTables = seedIndexedBranchTables(rom, memory, disassembled);
        int tables = seedBranchTables(rom, memory, disassembled);
        int trampolines = seedRamTrampolineTables(rom, memory, disassembled);
        println("[OK] seeded " + seeded + " vector, " + copies
            + " RAM copy, " + indexedTables + " indexed branch table, "
            + tables + " broad branch table, " + trampolines
            + " RAM trampoline targets");
    }
}
