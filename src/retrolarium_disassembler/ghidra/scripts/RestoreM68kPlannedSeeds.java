// Reapply planned roots erased by backend no-return analysis, without clearing.
//@category Retrolarium
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;

public class RestoreM68kPlannedSeeds extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("expected seed plan");
        MemoryBlock rom = currentProgram.getMemory().getBlock("ROM");
        if (rom == null || !rom.isInitialized()) throw new IllegalStateException("ROM block missing");
        Listing listing = currentProgram.getListing();
        AddressSet protectedData = new AddressSet();
        List<Long> roots = new ArrayList<>();
        for (String raw : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            String line = raw.split("#", 2)[0].trim();
            if (line.isEmpty()) continue;
            if (line.startsWith("DATA ")) {
                String[] fields = line.split("\\s+");
                if (fields.length != 3) throw new IllegalArgumentException("invalid inline-data range");
                long offset = Long.parseLong(fields[1], 16);
                int size = Integer.parseInt(fields[2]);
                if (size < 2 || size > 32 || (size & 1) != 0 || offset < 0x200
                        || (offset & 1) != 0 || offset + size > rom.getSize())
                    throw new IllegalArgumentException("invalid inline-data range");
                Address begin = rom.getStart().add(offset);
                protectedData.add(begin, begin.add(size - 1));
            } else roots.add(Long.parseLong(line, 16));
        }
        // Constrain the entire decoder walk, not only its first instruction.
        // A DATA plan range stays protected even if backend cleanup removed
        // its data declaration. Existing instructions and defined data never
        // enter the allowed set, including their operand/interior bytes.
        AddressSet available = new AddressSet(listing.getUndefinedRanges(
            new AddressSet(rom.getStart(), rom.getEnd()), false, monitor));
        available.delete(protectedData);
        PseudoDisassembler decoder = new PseudoDisassembler(currentProgram);
        HashSet<Address> visited = new HashSet<>();
        int restored = 0;
        for (long offset : roots) {
            monitor.checkCancelled();
            if (offset < 0x200 || (offset & 1) != 0 || offset >= rom.getSize()) continue;
            Address address = rom.getStart().add(offset);
            if (!available.contains(address)) continue;
            ArrayDeque<Address> pending = new ArrayDeque<>();
            pending.add(address);
            while (!pending.isEmpty()) {
                monitor.checkCancelled();
                Address cursor = pending.removeFirst();
                if (!available.contains(cursor) || !visited.add(cursor)
                        || (cursor.getOffset() & 1) != 0) continue;
                Instruction first;
                try {
                    first = decoder.disassemble(cursor);
                } catch (ghidra.program.model.lang.InsufficientBytesException
                        | ghidra.program.model.lang.UnknownInstructionException
                        | ghidra.program.model.lang.UnknownContextException exception) {
                    continue;
                }
                if (first == null || first.getLength() < 2 || (first.getLength() & 1) != 0
                        || !available.contains(cursor, cursor.add(first.getLength() - 1))) continue;
                // Ghidra's restricted set constrains instruction starts, not
                // complete operand spans. Validate every successor separately.
                AddressSet instructionBytes = new AddressSet(cursor, cursor.add(first.getLength() - 1));
                DisassembleCommand command = new DisassembleCommand(cursor, instructionBytes, false);
                command.enableCodeAnalysis(false);
                command.applyTo(currentProgram, monitor);
                AddressSet decoded = command.getDisassembledAddressSet();
                if (decoded != null) available.delete(decoded);
                Instruction actual = listing.getInstructionAt(cursor);
                if (actual == null) continue;
                for (Address target : actual.getFlows())
                    if (available.contains(target)) pending.add(target);
                Address following = actual.getFallThrough();
                if (following != null && available.contains(following)) pending.add(following);
            }
            if (listing.getInstructionAt(address) != null) {
                restored++;
                println(String.format("[RESTORED] planned root 0x%06X", offset));
            }
        }
        println("[OK] restored " + restored + " missing planned roots");
    }
}
