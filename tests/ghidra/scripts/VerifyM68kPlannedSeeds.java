// Synthetic integration checks for RestoreM68kPlannedSeeds.
// @category RetrolariumTests
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Listing;

import java.util.Arrays;

public class VerifyM68kPlannedSeeds extends GhidraScript {
    private Address at(long address) {
        return toAddr(address);
    }

    private void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private void single(long address) {
        DisassembleCommand command = new DisassembleCommand(at(address), null, false);
        command.enableCodeAnalysis(false);
        command.applyTo(currentProgram, monitor);
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        currentProgram.getMemory().getBlock("ROM").setExecute(true);
        byte[] original = getBytes(at(0), 0x400);
        single(0x224); // Existing instruction within the candidate at $220.
        single(0x260); // Existing four-byte instruction; planned $262 is interior.
        single(0x302); // A valid restored prefix may join existing code.
        createData(at(0x242), ByteDataType.dataType);
        createData(at(0x280), WordDataType.dataType);
        createData(at(0x2e4), ByteDataType.dataType);
        runScript("RestoreM68kPlannedSeeds.java", getScriptArgs());
        require(listing.getInstructionAt(at(0x200)) != null, "ordinary root lost");
        require(listing.getInstructionAt(at(0x202)) != null, "ordinary fall-through lost");
        require(
                listing.getInstructionAt(at(0x220)) == null,
                "first instruction crossed existing code");
        require(
                listing.getInstructionAt(at(0x240)) == null,
                "first instruction crossed defined data");
        require(listing.getInstructionAt(at(0x262)) == null, "interior instruction seeded");
        require(listing.getInstructionAt(at(0x280)) == null, "defined data seeded");
        require(listing.getInstructionAt(at(0x2a0)) == null, "undefined DATA-plan range seeded");
        require(listing.getInstructionAt(at(0x2c0)) != null, "safe prefix before DATA missing");
        require(
                listing.getInstructionAt(at(0x2c2)) == null,
                "following instruction crossed DATA range");
        require(
                listing.getInstructionAt(at(0x2e0)) != null,
                "safe prefix before defined data missing");
        require(
                listing.getInstructionAt(at(0x2e2)) == null,
                "following instruction crossed defined data");
        require(listing.getInstructionAt(at(0x300)) != null, "prefix joining existing code lost");
        require(listing.getInstructionAt(at(0x343)) == null, "odd root seeded");
        require(
                listing.getInstructionAt(at(0x360)) == null,
                "first instruction crossed DATA range");
        require(listing.getInstructionAt(at(0x380)) != null, "restored TRAP missing");
        require(listing.getInstructionAt(at(0x382)) == null, "stale argument root restored");
        require(listing.getInstructionAt(at(0x384)) != null, "TRAP continuation missing");
        require(listing.getInstructionAt(at(0x224)).getLength() == 2, "existing RTS changed");
        require(
                listing.getInstructionAt(at(0x260)).getLength() == 4,
                "existing instruction changed");
        require(listing.getInstructionAt(at(0x302)).getLength() == 2, "existing join changed");
        for (long address : new long[] {0x242, 0x280, 0x2e4})
            require(listing.getDefinedDataAt(at(address)) != null, "defined data cleared");
        require(Arrays.equals(original, getBytes(at(0), 0x400)), "ROM bytes changed");
        long count = listing.getNumInstructions();
        runScript("RestoreM68kPlannedSeeds.java", getScriptArgs());
        require(count == listing.getNumInstructions(), "reapplication is not idempotent");
        println(
                "[PASS] planned-seed restoration respects code, data, interiors and inline"
                        + " arguments");
    }
}
