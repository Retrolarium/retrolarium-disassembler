// Restore only a proved next instruction; never traverse or create new roots.
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
import java.util.HashSet;
import java.util.List;
import java.util.TreeMap;

public class RestoreM68kFallthrough extends GhidraScript {
    private static class Repair {
        long source, target;
        String sourceBytes, bytes;
        TreeMap<Long,String> conflicts = new TreeMap<>();
    }
    private final List<long[]> protectedData = new ArrayList<>();
    private final TreeMap<Long,String> trusted = new TreeMap<>();
    private final HashSet<Long> roots = new HashSet<>();
    private MemoryBlock rom;
    private Listing listing;
    private PseudoDisassembler decoder;

    private Address at(long address) { return rom.getStart().getAddressSpace().getAddress(address); }
    private boolean backed(long address, int length) {
        return address>=rom.getStart().getOffset() && length>=2 && length<=10
            && (address & 1)==0 && (length & 1)==0 && address+length<=rom.getEnd().getOffset()+1;
    }
    private String bytes(long start, int length) throws Exception {
        byte[] data = new byte[length];
        currentProgram.getMemory().getBytes(at(start),data);
        StringBuilder result = new StringBuilder();
        for (byte value:data) result.append(String.format("%02x",value & 255));
        return result.toString();
    }
    private boolean ordinary(Instruction instruction) {
        String op=instruction.getMnemonicString().toUpperCase().split("\\.")[0];
        if (List.of("JSR","BSR","JMP","BRA","RTS","RTE","RTR","TRAP","TRAPV","STOP",
                    "RESET","ILLEGAL","PEA","LINK","UNLK","CHK","CHK2","DIVU","DIVS",
                    "DIVUL","DIVSL").contains(op)) return false;
        for (int i=0;i<instruction.getNumOperands();i++) {
            String operand=instruction.getDefaultOperandRepresentation(i).toUpperCase();
            if (operand.equals("USP") || i==instruction.getNumOperands()-1 && operand.equals("SR"))
                return false;
        }
        for (Address flow:instruction.getFlows()) if ((flow.getOffset() & 1)!=0) return false;
        return instruction.getFlowType().hasFallthrough() && !instruction.getFlowType().isCall()
            && !instruction.getFlowType().isComputed();
    }
    private boolean protectedSpan(long start, long end, String ownBytes) {
        for (long[] range:protectedData)
            if (range[0]<end && start<range[1]) return true;
        for (var code:trusted.entrySet()) {
            long codeStart=code.getKey(), limit=codeStart+code.getValue().length()/2;
            if (codeStart<end && start<limit
                    && !(codeStart==start && code.getValue().equals(ownBytes))) return true;
        }
        for (long root:roots) if (start<root && root<end) return true;
        return false;
    }
    private boolean apply(Repair repair) throws Exception {
        int length=repair.bytes.length()/2;
        long end=repair.target+length;
        if (!backed(repair.target,length) || !backed(repair.source,repair.sourceBytes.length()/2)
                || !bytes(repair.target,length).equals(repair.bytes)) return false;
        if (protectedSpan(repair.source,repair.source+repair.sourceBytes.length()/2,repair.sourceBytes))
            return false; // New data/interior evidence can revoke an old source proof.
        Instruction source=listing.getInstructionAt(at(repair.source));
        if (source==null || !ordinary(source) || source.getFallThrough()==null
                || source.getFallThrough().getOffset()!=repair.target
                || source.getLength()!=repair.sourceBytes.length()/2
                || !bytes(repair.source,source.getLength()).equals(repair.sourceBytes)) return false;
        Instruction canonical;
        try { canonical=decoder.disassemble(at(repair.target)); }
        catch (ghidra.program.model.lang.InsufficientBytesException
                | ghidra.program.model.lang.UnknownInstructionException
                | ghidra.program.model.lang.UnknownContextException exception) { return false; }
        if (canonical==null || canonical.getLength()!=length) return false;
        for (Address flow:canonical.getFlows()) if ((flow.getOffset() & 1)!=0) return false;
        if (protectedSpan(repair.target,end,repair.bytes)) return false;
        Instruction existing=listing.getInstructionAt(at(repair.target));
        if (existing!=null) {
            // No destructive work is needed. A historical conflict's cleared
            // tail may now contain newly proved code/data: it is irrelevant.
            return existing.getLength()==length;
        }
        TreeMap<Long,Instruction> conflicts=new TreeMap<>();
        long cleanupEnd=end;
        for (long cursor=repair.target;cursor<end;cursor++) {
            if (listing.getDefinedDataContaining(at(cursor))!=null) return false;
            Instruction unit=listing.getInstructionContaining(at(cursor));
            if (unit==null) continue;
            long start=unit.getAddress().getOffset();
            String expected=repair.conflicts.get(start);
            if (start<repair.target || expected==null || !backed(start,unit.getLength())
                    || unit.getLength()!=expected.length()/2
                    || !bytes(start,unit.getLength()).equals(expected)) return false;
            conflicts.put(start,unit);
            cleanupEnd=Math.max(cleanupEnd,start+unit.getLength());
        }
        // Validate the complete current destructive span before any clear.
        // Planned and trusted boundaries beyond the canonical instruction are
        // protected too. Historical units no longer present are not cleared.
        if (cleanupEnd>rom.getEnd().getOffset()+1 || protectedSpan(repair.target,cleanupEnd,repair.bytes)) return false;
        for (long cursor=repair.target;cursor<cleanupEnd;cursor++) {
            if (listing.getDefinedDataContaining(at(cursor))!=null) return false;
            Instruction unit=listing.getInstructionContaining(at(cursor));
            if (unit!=null && !conflicts.containsKey(unit.getAddress().getOffset())) return false;
        }
        for (Instruction unit:conflicts.values())
            listing.clearCodeUnits(unit.getMinAddress(),unit.getMaxAddress(),false);
        Address start=at(repair.target);
        DisassembleCommand command=new DisassembleCommand(start,new AddressSet(start,at(end-1)),false);
        command.enableCodeAnalysis(false);
        command.applyTo(currentProgram,monitor);
        Instruction restored=listing.getInstructionAt(start);
        if (restored==null || restored.getLength()!=length)
            throw new IllegalStateException("proved canonical instruction failed to decode");
        println(String.format("[REPAIRED] ordinary fallthrough %06X -> %06X (%d conflicts)",
            repair.source,repair.target,conflicts.size()));
        return true;
    }
    private String raw(String value) {
        if (!value.matches("(?i)[0-9a-f]{4}(?:[0-9a-f]{4}){0,4}"))
            throw new IllegalArgumentException("invalid instruction byte proof");
        return value.toLowerCase();
    }
    private String protectedBytes(String value) {
        // Backend facts can contain longer, non-68000 extension forms. They
        // still occupy protected listing spans; accepting their metadata here
        // does not make them eligible as sources or canonical repair proofs.
        if (!value.matches("(?i)(?:[0-9a-f]{2})+"))
            throw new IllegalArgumentException("invalid protected instruction bytes");
        return value.toLowerCase();
    }
    @Override
    public void run() throws Exception {
        if (getScriptArgs().length!=1) throw new IllegalArgumentException("expected repair plan");
        rom=currentProgram.getMemory().getBlock("ROM");
        if (rom==null) rom=currentProgram.getMemory().getBlock("CD_MODULE");
        if (rom==null || !rom.isInitialized()) throw new IllegalStateException("M68K program block missing");
        listing=currentProgram.getListing();
        decoder=new PseudoDisassembler(currentProgram);
        List<Repair> repairs=new ArrayList<>();
        for (String line:Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            if (line.isBlank()) continue;
            String[] fields=line.split("\t");
            if (fields[0].equals("PROTECT_DATA")) {
                long start=Long.parseLong(fields[1],16),end=Long.parseLong(fields[2],16);
                if (end<=start) throw new IllegalArgumentException("invalid data range");
                protectedData.add(new long[]{start,end});
            } else if (fields[0].equals("TRUSTED")) trusted.put(Long.parseLong(fields[1],16),protectedBytes(fields[2]));
            else if (fields[0].equals("ROOT")) roots.add(Long.parseLong(fields[1],16));
            else if (fields[0].equals("REPAIR")) {
                Repair repair=new Repair();
                repair.source=Long.parseLong(fields[1],16);repair.sourceBytes=raw(fields[2]);
                repair.target=Long.parseLong(fields[3],16);repair.bytes=raw(fields[4]);
                if (!fields[5].equals("-")) for (String item:fields[5].split(",")) {
                    String[] pair=item.split(":");repair.conflicts.put(Long.parseLong(pair[0],16),raw(pair[1]));
                }
                repairs.add(repair);
                if (repairs.size()>4096) throw new IllegalArgumentException("repair budget exceeded");
            } else throw new IllegalArgumentException("unknown repair plan record");
        }
        int satisfied=0;
        for (Repair repair:repairs) { monitor.checkCancelled(); if (apply(repair)) satisfied++; }
        println("[OK] ordinary fallthrough proofs satisfied="+satisfied+" of "+repairs.size());
    }
}
