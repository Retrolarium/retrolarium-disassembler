// Synthetic integration checks for protected normal-return restoration.
//@category RetrolariumTests
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.data.WordDataType;
import java.util.Arrays;

public class VerifyM68kReturningCalls extends GhidraScript {
    private Address at(long address) { return toAddr(address); }
    private void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private void single(long address) {
        int length = address == 0x268 ? 2 : 6;
        DisassembleCommand command = new DisassembleCommand(at(address),
                new AddressSet(at(address), at(address + length - 1)), false);
        command.enableCodeAnalysis(false);
        command.applyTo(currentProgram, monitor);
    }
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        currentProgram.getMemory().getBlock("ROM").setExecute(true);
        byte[] original = getBytes(at(0), 0x400);
        long[] calls = {0x200, 0x220, 0x240, 0x260, 0x280, 0x2a0};
        for (long site : calls) {
            single(site);
            listing.getInstructionAt(at(site)).setFlowOverride(FlowOverride.CALL_RETURN);
        }
        single(0x268); // Operand-shaped RTS in the proposed instruction at $266.
        createData(at(0x248), WordDataType.dataType);
        runScript("RestoreM68kReturningCalls.java", new String[]{getScriptArgs()[0]});
        for (long site : calls) {
            require(listing.getInstructionAt(at(site)).getFlowOverride() == FlowOverride.CALL,
                    "normal return override missing");
            require(listing.getInstructionAt(at(site + 6)) == null,
                    "call override decoded a continuation before DATA checks");
        }
        runScript("RestoreM68kPlannedSeeds.java", new String[]{getScriptArgs()[1]});
        require(listing.getInstructionAt(at(0x206)) != null, "safe continuation was not restored");
        require(listing.getInstructionAt(at(0x208)) != null, "safe following RTS was not restored");
        for (long target : new long[]{0x226, 0x246, 0x266, 0x286, 0x2a6})
            require(listing.getInstructionAt(at(target)) == null,
                    "restoration bypassed data, operand, or planned-root protection");
        require(listing.getDefinedDataAt(at(0x248)) != null, "defined data changed");
        require(listing.getInstructionAt(at(0x268)).getLength() == 2, "existing interior code changed");
        require(Arrays.equals(original, getBytes(at(0), 0x400)), "ROM bytes changed");
        long count = listing.getNumInstructions();
        runScript("RestoreM68kReturningCalls.java", new String[]{getScriptArgs()[0]});
        runScript("RestoreM68kPlannedSeeds.java", new String[]{getScriptArgs()[1]});
        require(listing.getNumInstructions() == count, "reapplication changed instruction set");
        println("[PASS] normal-return restoration uses protected planned-root decoding");
    }
}
