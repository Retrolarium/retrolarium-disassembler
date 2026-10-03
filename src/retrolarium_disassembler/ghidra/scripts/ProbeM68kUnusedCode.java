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
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.TreeMap;

public class ProbeM68kUnusedCode extends GhidraScript {
    private static final int MAX_GAP = 2048;
    private static final int MAX_REQUESTS = 4096;

    private void probeRequested(PseudoDisassembler decoder, long start, long end,
            MemoryBlock rom, TreeMap<Long, String> rows,
            TreeMap<Long, Instruction> cache) throws Exception {
        ArrayDeque<Long> pending = new ArrayDeque<>();
        HashSet<Long> visited = new HashSet<>();
        pending.add(start);
        while (!pending.isEmpty() && visited.size() < MAX_GAP / 2) {
            long cursor = pending.removeFirst();
            if (cursor < start || cursor >= end || (cursor & 1) != 0 || !visited.add(cursor)) continue;
            monitor.checkCancelled();
            Instruction instruction = cache.get(cursor);
            if (instruction == null) {
                try {
                    instruction = decoder.disassemble(rom.getStart().getAddressSpace().getAddress(cursor));
                } catch (ghidra.program.model.lang.InsufficientBytesException
                        | ghidra.program.model.lang.UnknownInstructionException
                        | ghidra.program.model.lang.UnknownContextException exception) {
                    continue;
                }
                if (instruction != null) cache.put(cursor, instruction);
            }
            if (instruction == null || instruction.getLength() < 2
                    || cursor + instruction.getLength() > end) continue;
            rows.putIfAbsent(cursor, row(instruction, rom.getName()));
            // A callee outside this interval needs its own bounded request.
            // No speculative call target becomes a listing instruction/root.
            if (!instruction.getFlowType().isCall() && !instruction.getFlowType().isComputed()) {
                for (Address flow : instruction.getFlows()) {
                    if (flow.getAddressSpace().equals(rom.getStart().getAddressSpace()))
                        pending.add(flow.getOffset());
                }
            }
            if (instruction.getFlowType().hasFallthrough())
                pending.add(cursor + instruction.getLength());
        }
    }

    private boolean hasTrapHandler(MemoryBlock rom, int opcode) throws Exception {
        if ((opcode & 0xfff0) != 0x4e40) return false;
        Address vector = rom.getStart().getAddressSpace().getAddress((32 + (opcode & 15)) * 4);
        if (!rom.contains(vector) || !rom.contains(vector.add(3))) return false;
        long handler = currentProgram.getMemory().getInt(vector) & 0x00ffffffL;
        return currentProgram.getListing().getInstructionAt(
            vector.getAddressSpace().getAddress(handler)) != null;
    }

    private static boolean functionSignature(int opcode) {
        return (opcode & 0xf1c0) == 0x41c0 // LEA
            || opcode == 0x48e7 || opcode == 0x48a7 // MOVEM saves
            || (opcode & 0xfff8) == 0x4e50 // LINK
            || (opcode & 0xf1ff) == 0x303c // MOVE.W immediate,Dn
            || (opcode & 0xff00) == 0x0c00 && (opcode & 0x00c0) != 0x00c0; // CMPI
    }

    private void probe(PseudoDisassembler decoder, long start, long end,
            MemoryBlock rom, TreeMap<Long, String> rows) throws Exception {
        ArrayDeque<Long> pending = new ArrayDeque<>();
        HashSet<Long> visited = new HashSet<>();
        pending.add(start);
        while (!pending.isEmpty()) {
          for (long cursor = pending.removeFirst(); cursor < end;) {
            if (!visited.add(cursor)) break;
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
            rows.put(cursor, row(instruction, rom.getName()));
            // Inline data can misalign the linear walk. Decode direct branch
            // targets as separate hypotheses, within this same bounded gap.
            // Python still proves whole CFGs and protects data before seeding.
            for (Address flow : instruction.getFlows()) {
                long target = flow.getOffset();
                if (flow.getAddressSpace().equals(rom.getStart().getAddressSpace())
                        && target >= start && target < end && (target & 1) == 0
                        && !visited.contains(target)) pending.add(target);
            }
            int opcode = currentProgram.getMemory().getShort(instruction.getAddress()) & 0xffff;
            if (instruction.getLength() == 2 && hasTrapHandler(rom, opcode)) {
                // These are hypotheses, never real instructions/data
                // declarations. Python selects only the continuation
                // proven by the already rooted vector's frame protocol.
                for (int size = 2; size <= 32; size += 2) {
                    long continuation = cursor + 2 + size;
                    if (continuation < end && !visited.contains(continuation))
                        pending.add(continuation);
                }
            }
            cursor += instruction.getLength();
          }
        }
    }

    private static String clean(String value) {
        return value.replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "").replace("\n", "\\n");
    }

    private static String row(Instruction instruction, String block) throws Exception {
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
        return clean(block) + "\t" + clean(address.getAddressSpace().getName()) + "\t"
            + String.format("%06X", address.getOffset()) + "\t" + instruction.getLength()
            + "\t" + String.join(" ", bytes) + "\t" + clean(instruction.getMnemonicString())
            + "\t" + String.join("|", operands) + "\t" + String.join("|", flows)
            + "\t" + String.join("|", references) + "\t" + instruction.getFlowType()
            + "\t\t";
    }

    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length < 1 || getScriptArgs().length > 2)
            throw new IllegalArgumentException("expected output TSV and optional probe-request TSV");
        MemoryBlock rom = currentProgram.getMemory().getBlock("ROM");
        if (rom == null) rom = currentProgram.getMemory().getBlock("CD_MODULE");
        if (rom == null) throw new IllegalStateException("ROM block missing");
        long listingBefore = currentProgram.getListing().getNumInstructions();
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
            int opcode = currentProgram.getMemory().getShort(previous.getAddress()) & 0xffff;
            if (previous.getLength() == 2 && hasTrapHandler(rom, opcode)) {
                long at = previous.getAddress().getOffset();
                int next = index + 1;
                while (next < known.size() && known.get(next).getAddress().getOffset() < at + 34) next++;
                long limit = next < known.size() ? known.get(next).getAddress().getOffset()
                    : rom.getEnd().getOffset() + 1;
                // A known TRAP may border backend code islands, so ordinary
                // terminal-gap probing would miss its real continuation.
                probe(decoder, at, Math.min(limit, at + MAX_GAP), rom, rows);
            }
            if (!(previous.getFlowType().isTerminal() || previous.getFlowType().isJump()
                    && !previous.getFlowType().isConditional())) continue;
            long start = previous.getAddress().getOffset() + previous.getLength();
            long end = index + 1 < known.size() ? known.get(index + 1).getAddress().getOffset()
                : rom.getEnd().getOffset() + 1;
            if (start < 0x200 || (start & 1) != 0 || end - start < 2) continue;
            end = Math.min(end, start + MAX_GAP);
            probe(decoder, start, end, rom, rows);
            // An unused function can follow a local table/string. Decode
            // selected prologues inside this bounded gap, without adding
            // them to the real listing. Python requires a full CFG, RTS,
            // a known callee, and absence of known data use before seeding.
            for (long candidate = start + 2; candidate + 2 <= end; candidate += 2) {
                int candidateOpcode = currentProgram.getMemory().getShort(
                    rom.getStart().getAddressSpace().getAddress(candidate)) & 0xffff;
                if (functionSignature(candidateOpcode)) probe(decoder, candidate, end, rom, rows);
            }
        }
        int requests = 0;
        if (getScriptArgs().length == 2) {
            TreeMap<Long, Instruction> cache = new TreeMap<>();
            HashSet<Long> seenRequests = new HashSet<>();
            // Standalone CD modules have no cartridge vector/header area.
            long requestStart = rom.getStart().getOffset()
                + (rom.getName().equals("ROM") ? 0x200 : 0);
            for (String line : Files.readAllLines(Path.of(getScriptArgs()[1]))) {
                if (line.isBlank()) continue;
                String[] fields = line.trim().split("\\s+");
                if (fields.length != 2) throw new IllegalArgumentException("invalid probe request: " + line);
                long start = Long.parseUnsignedLong(fields[0], 16);
                long end = Long.parseUnsignedLong(fields[1], 16);
                if (start < requestStart || end > rom.getEnd().getOffset() + 1
                        || (start & 1) != 0 || end <= start || end - start > MAX_GAP)
                    throw new IllegalArgumentException("invalid bounded probe request: " + line);
                if (!seenRequests.add(start)) continue;
                if (++requests > MAX_REQUESTS) throw new IllegalArgumentException("probe request budget exceeded");
                probeRequested(decoder, start, end, rom, rows, cache);
            }
        }
        long listingAfter = currentProgram.getListing().getNumInstructions();
        if (listingBefore != listingAfter) throw new IllegalStateException("pseudo decoding modified listing");
        List<String> lines = new ArrayList<>();
        lines.add("block\tspace\taddress\tlength\tbytes\tmnemonic\toperands\tflows\treferences\tflow_type\tsymbol\tfunction");
        lines.addAll(rows.values());
        Path output = Path.of(getScriptArgs()[0]).toAbsolutePath();
        Files.createDirectories(output.getParent());
        Files.write(output, lines, StandardCharsets.UTF_8);
        println("[OK] exported " + rows.size() + " speculative M68K instructions; requested=" + requests
            + "; listing unchanged (" + listingBefore + " -> " + listingAfter + ")");
    }
}
