// Export instruction facts from a selected executable memory block.
// @category Retrolarium

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class ExportInstructionFacts extends GhidraScript {
    private static String clean(String value) {
        return value.replace("\\", "\\\\")
                .replace("\t", "\\t")
                .replace("\r", "")
                .replace("\n", "\\n");
    }

    private static boolean isCanonicalPrg(MemoryBlock block) {
        String name = block.getName().toUpperCase();
        String space = block.getStart().getAddressSpace().getName().toUpperCase();
        return block.isInitialized()
                && block.isExecute()
                && name.startsWith("PRG")
                && !name.contains("MIRROR")
                && space.startsWith("PRG")
                && !space.contains("MIRROR");
    }

    private static boolean isSelectedCode(MemoryBlock block, String selector) {
        if (selector.equals("NES_PRG")) {
            return isCanonicalPrg(block);
        }
        return block.isInitialized()
                && block.isExecute()
                && block.getName().equalsIgnoreCase(selector);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException(
                    "expected output TSV path and optional block selector");
        }
        String selector = args.length == 2 ? args[1] : "NES_PRG";

        List<MemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (isSelectedCode(block, selector)) {
                blocks.add(block);
            }
        }
        blocks.sort(Comparator.comparing(block -> block.getStart().toString()));
        if (blocks.isEmpty()) {
            throw new IllegalStateException(
                    "no selected initialized executable blocks found: " + selector);
        }

        List<String> lines = new ArrayList<>();
        lines.add(
                "block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\treferences"
                        + "\tflow_type\tsymbol\tfunction");
        for (MemoryBlock block : blocks) {
            InstructionIterator iterator =
                    currentProgram.getListing().getInstructions(block.getStart(), true);
            while (iterator.hasNext()) {
                Instruction instruction = iterator.next();
                Address address = instruction.getAddress();
                if (!block.contains(address)) {
                    break;
                }
                byte[] raw = instruction.getBytes();
                StringBuilder bytes = new StringBuilder();
                for (byte value : raw) {
                    if (bytes.length() != 0) {
                        bytes.append(' ');
                    }
                    bytes.append(String.format("%02X", value & 0xff));
                }
                List<String> operands = new ArrayList<>();
                for (int index = 0; index < instruction.getNumOperands(); index++) {
                    operands.add(clean(instruction.getDefaultOperandRepresentation(index)));
                }
                List<String> flows = new ArrayList<>();
                for (Address flow : instruction.getFlows()) {
                    flows.add(flow.toString());
                }
                List<String> references = new ArrayList<>();
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (!reference.getToAddress().isMemoryAddress()) {
                        continue;
                    }
                    references.add(
                            clean(reference.getToAddress().toString())
                                    + "~"
                                    + clean(reference.getReferenceType().toString())
                                    + "~"
                                    + reference.getOperandIndex());
                }
                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                lines.add(
                        clean(block.getName())
                                + "\t"
                                + clean(address.getAddressSpace().getName())
                                + "\t"
                                + String.format("%04X", address.getOffset())
                                + "\t"
                                + instruction.getLength()
                                + "\t"
                                + bytes
                                + "\t"
                                + clean(instruction.getMnemonicString())
                                + "\t"
                                + String.join("|", operands)
                                + "\t"
                                + String.join("|", flows)
                                + "\t"
                                + String.join("|", references)
                                + "\t"
                                + clean(instruction.getFlowType().toString())
                                + "\t"
                                + (symbol == null ? "" : clean(symbol.getName()))
                                + "\t"
                                + (function == null ? "" : clean(function.getName())));
            }
        }
        Path output = Path.of(args[0]).toAbsolutePath();
        Files.createDirectories(output.getParent());
        Files.write(output, lines, StandardCharsets.UTF_8);
        println("[OK] wrote " + (lines.size() - 1) + " Retrolarium instruction facts to " + output);
    }
}
