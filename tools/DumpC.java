import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DumpC extends GhidraScript {
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        String outDir = System.getenv().getOrDefault("OUT_DIR", "/tmp/ghidra_out");
        new File(outDir).mkdirs();
        String[] keys = {"appmain","SQLSaveFile","InputCore","DoAction","GonResource","SwfCutscene","MewSaveFile"};
        int n = 0, total = 0;
        try (PrintWriter idx = new PrintWriter(new FileWriter(new File(outDir, "index.tsv")))) {
            for (Function f : fm.getFunctions(true)) {
                total++;
                String name = f.getName();
                String dem = name;
                boolean hit = false;
                for (String k : keys) if (name.contains(k)) { hit = true; break; }
                idx.println(f.getEntryPoint() + "\t" + f.getBody().getNumAddresses() + "\t" + dem);
                if (!hit || n >= 400) continue;
                DecompileResults r = dec.decompileFunction(f, 60, monitor);
                if (!r.decompileCompleted()) continue;
                String c = r.getDecompiledFunction().getC();
                String safe = name.replaceAll("[^A-Za-z0-9_]", "_");
                try (PrintWriter w = new PrintWriter(new FileWriter(new File(outDir, "fn_" + (n++) + "_" + safe + ".c")))) {
                    w.println("// " + f.getEntryPoint() + "  " + name);
                    w.println(c);
                }
            }
        }
        try (PrintWriter w = new PrintWriter(new FileWriter(new File(outDir, "_stats.txt")))) {
            w.println("functions=" + total);
            w.println("decompiled=" + n);
        }
        dec.dispose();
        println("DONE functions=" + total + " decompiled=" + n);
    }
}
