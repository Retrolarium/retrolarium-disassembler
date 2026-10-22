// Preserve normal call continuations proven from a balanced path to RTS.
// @category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;

public class RestoreM68kReturningCalls extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1)
            throw new IllegalArgumentException("expected normal-return call plan");
        MemoryBlock rom = currentProgram.getMemory().getBlock("ROM");
        int normalized = 0;
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            monitor.checkCancelled();
            if (line.isBlank()) continue;
            String[] fields = line.trim().split("\\s+");
            if (fields.length != 2) throw new IllegalArgumentException("invalid return plan");
            long site = Long.parseLong(fields[0], 16);
            long following = Long.parseLong(fields[1], 16);
            Address address = rom.getStart().add(site);
            if (!rom.contains(address) || (site & 1) != 0)
                throw new IllegalArgumentException("call outside ROM");
            Instruction call = getInstructionAt(address);
            if (call == null) continue; // An unrooted writer is not a call witness.
            int opcode = currentProgram.getMemory().getShort(address) & 0xffff;
            if (!((opcode & 0xffc0) == 0x4e80 || (opcode & 0xff00) == 0x6100)
                    || site + call.getLength() != following
                    || !rom.contains(rom.getStart().add(following)))
                throw new IllegalArgumentException("return plan disagrees with decoded call");
            // Auto-analysis may infer no-return and erase an explicitly seeded
            // fall-through. Override only this independently proven call site.
            call.setFlowOverride(FlowOverride.CALL);
            // Continuations are independently planned roots. The subsequent
            // RestoreM68kPlannedSeeds walk validates every complete instruction
            // against DATA, defined data and existing instruction spans.
            // An unrestricted disassemble here would bypass those protections.
            normalized++;
        }
        println("[OK] normalized " + normalized + " proven normal-call flow overrides");
    }
}
