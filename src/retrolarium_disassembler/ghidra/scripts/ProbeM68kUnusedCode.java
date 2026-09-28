// Decode bounded gaps after terminal instructions WITHOUT changing the listing.
//@category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

public class ProbeM68kUnusedCode extends GhidraScript {
    private static final int MAX_GAP = 2048;

    private static String clean(String value) {
        return value.replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "").replace("\n", "\\n");
    }

    private static String row(Instruction instruction) throws Exception {
        Address address = instruction.getAddress();
        List<String> bytes = new ArrayList<>();
        for (byte value : instruction.getBytes()) bytes.add(String.format("%02X", value & 255));
        List<String> operands = new ArrayList<>();
        List<String> references = new ArrayList<>();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            operands.add(clean(instruction.getDefaultOperandRepresentation(index)));
            // PseudoInstruction computes operand references from the prototype.
            for (Reference reference : instruction.getOperandReferences(index)) {
                if (reference.getToAddress().isMemoryAddress()) {
                    references.add(reference.getToAddress().toString() + "~"
                        + reference.getReferenceType().toString() + "~" + index);
                }
            }
        }
        List<String> flows = new ArrayList<>();
        for (Address flow : instruction.getFlows()) flows.add(flow.toString());
        return "ROM\t" + clean(address.getAddressSpace().getName()) + "\t"
            + String.format("%06X", address.getOffset()) + "\t" + instruction.getLength()
            + "\t" + String.join(" ", bytes) + "\t" + clean(instruction.getMnemonicString())
            + "\t" + String.join("|", operands) + "\t" + String.join("|", flows)
            + "\t" + String.join("|", references) + "\t" + instruction.getFlowType()
            + "\t\t";
    }

    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("expected output TSV");
        MemoryBlock rom = currentProgram.getMemory().getBlock("ROM");
        if (rom == null) throw new IllegalStateException("ROM block missing");
        List<Instruction> known = new ArrayList<>();
        InstructionIterator iterator = currentProgram.getListing().getInstructions(rom.getStart(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (!rom.contains(instruction.getAddress())) break;
            known.add(instruction);
        }
        TreeMap<Long, String> rows = new TreeMap<>();
        PseudoDisassembler decoder = new PseudoDisassembler(currentProgram);
        for (int index = 0; index < known.size(); index++) {
            monitor.checkCancelled();
            Instruction previous = known.get(index);
            if (!(previous.getFlowType().isTerminal() || previous.getFlowType().isJump()
                    && !previous.getFlowType().isConditional())) continue;
            long start = previous.getAddress().getOffset() + previous.getLength();
            long end = index + 1 < known.size() ? known.get(index + 1).getAddress().getOffset()
                : rom.getEnd().getOffset() + 1;
            if (start < 0x200 || (start & 1) != 0 || end - start < 2 || end - start > MAX_GAP) continue;
            long cursor = start;
            while (cursor < end) {
                monitor.checkCancelled();
                Instruction instruction;
                try {
                    instruction = decoder.disassemble(rom.getStart().getAddressSpace().getAddress(cursor));
                } catch (ghidra.program.model.lang.InsufficientBytesException
                        | ghidra.program.model.lang.UnknownInstructionException
                        | ghidra.program.model.lang.UnknownContextException exception) {
                    break;
                }
                if (instruction == null || instruction.getLength() < 2
                        || cursor + instruction.getLength() > end) break;
                rows.put(cursor, row(instruction));
                cursor += instruction.getLength();
            }
        }
        List<String> lines = new ArrayList<>();
        lines.add("block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\treferences\tflow_type\tsymbol\tfunction");
        lines.addAll(rows.values());
        Path output = Path.of(getScriptArgs()[0]).toAbsolutePath();
        Files.createDirectories(output.getParent());
        Files.write(output, lines, StandardCharsets.UTF_8);
        println("[OK] exported " + rows.size() + " speculative M68K instructions; listing unchanged");
    }
}
