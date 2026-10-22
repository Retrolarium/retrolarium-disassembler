// Synthetic safety and persistence checks against the actual Ghidra listing.
// @category RetrolariumTests
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

import java.util.Arrays;

public class VerifyM68kFallthrough extends GhidraScript {
    private Listing listing;
    private long base;

    private void require(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }

    private void single(long offset, int length) {
        DisassembleCommand command =
                new DisassembleCommand(
                        toAddr(base + offset),
                        new AddressSet(toAddr(base + offset), toAddr(base + offset + length - 1)),
                        false);
        command.enableCodeAnalysis(false);
        command.applyTo(currentProgram, monitor);
        require(listing.getInstructionAt(toAddr(base + offset)) != null, "fixture did not decode");
    }

    private Instruction instruction(long offset) {
        return listing.getInstructionAt(toAddr(base + offset));
    }

    private void clear(long offset) {
        Instruction code = instruction(offset);
        listing.clearCodeUnits(code.getMinAddress(), code.getMaxAddress(), false);
    }

    private void runPlan(String path) throws Exception {
        runScript("RestoreM68kFallthrough.java", new String[] {path});
    }

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        base = currentProgram.getMemory().getBlocks()[0].getStart().getOffset();
        byte[] original = getBytes(toAddr(base), 0x500);
        for (long source :
                new long[] {0x200, 0x240, 0x280, 0x2c0, 0x300, 0x340, 0x380, 0x3c0, 0x400, 0x440})
            single(source, 2);
        for (long conflict : new long[] {0x204, 0x244, 0x2c4, 0x304, 0x384}) single(conflict, 2);
        single(0x246, 4);
        single(0x346, 4);
        createData(toAddr(base + 0x284), WordDataType.dataType);
        runPlan(getScriptArgs()[0]);
        require(
                instruction(0x202) != null && instruction(0x202).getLength() == 6,
                "canonical instruction missing");
        require(
                instruction(0x242) != null && instruction(0x242).getLength() == 6,
                "union repair missing");
        require(instruction(0x248) == null, "cleared union tail was decoded");
        for (long rejected : new long[] {0x282, 0x2c2, 0x302, 0x342, 0x382, 0x3c2, 0x402, 0x442})
            require(
                    instruction(rejected) == null,
                    "unsafe repair accepted at " + Long.toHexString(rejected));
        for (long conflict : new long[] {0x2c4, 0x304, 0x346, 0x384})
            require(instruction(conflict) != null, "rejected repair cleared its conflict");
        require(listing.getDefinedDataAt(toAddr(base + 0x284)) != null, "defined data was cleared");
        // Current code in a historically cleared tail cannot block a no-op.
        single(0x248, 2);
        runPlan(getScriptArgs()[1]);
        require(instruction(0x248) != null, "new trusted tail was cleared");
        // Restore a forgotten boundary while an independent repaired target
        // remains canonical. Only the actual conflict may be cleared again.
        clear(0x202);
        single(0x204, 2);
        runPlan(getScriptArgs()[1]);
        require(
                instruction(0x202) != null && instruction(0x248) != null,
                "persistent proof failed");
        // Historical tail data is irrelevant to an exact existing target.
        clear(0x248);
        createData(toAddr(base + 0x248), WordDataType.dataType);
        runPlan(getScriptArgs()[2]);
        require(
                listing.getDefinedDataAt(toAddr(base + 0x248)) != null,
                "historical tail data cleared");
        // Contradictory DATA on the source or own target must revoke a proof.
        clear(0x202);
        single(0x204, 2);
        runPlan(getScriptArgs()[3]);
        require(
                instruction(0x202) == null && instruction(0x204) != null,
                "source DATA proof ignored");
        runPlan(getScriptArgs()[4]);
        require(
                instruction(0x202) == null && instruction(0x204) != null,
                "target DATA proof ignored");
        require(Arrays.equals(original, getBytes(toAddr(base), 0x500)), "ROM bytes changed");
        println("[PASS] canonical repair protects spans, data, roots and persistent ownership");
    }
}
