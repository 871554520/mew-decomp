// Ghidra 脚本：按函数序号取模分片，反编译该分片的全部函数到一个翻译单元。
// 环境变量：MEW_SHARD（第几片，从 0 开始）、MEW_SHARDS（总片数）
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DumpShard extends GhidraScript {
    @Override
    public void run() throws Exception {
        int shard = 0, shards = 8;
        String s1 = System.getenv("MEW_SHARD");
        String s2 = System.getenv("MEW_SHARDS");
        if (s1 != null && !s1.isEmpty()) shard = Integer.parseInt(s1.trim());
        if (s2 != null && !s2.isEmpty()) shards = Integer.parseInt(s2.trim());

        File dir = new File("/tmp/ghidra_out/shard" + shard);
        dir.mkdirs();

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        PrintWriter one = new PrintWriter(new FileWriter(new File(dir, "sample_shard.c")));
        one.println("#include \"shim.h\"");
        one.println("#include \"globals.h\"");
        PrintWriter idx = new PrintWriter(new FileWriter(new File(dir, "index.tsv")));

        int index = 0, mine = 0, emitted = 0, failed = 0;
        long bytes = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            long sz = f.getBody().getNumAddresses();
            if (sz < 16) continue;
            int which = index % shards;
            index++;
            if (which != shard) continue;
            mine++;
            DecompileResults r = ifc.decompileFunction(f, 60, monitor);
            if (!r.decompileCompleted()) { failed++; continue; }
            String c = r.getDecompiledFunction().getC();
            bytes += c.length();
            one.println("/* ---- " + f.getEntryPoint() + " size=" + sz + " ---- */");
            one.println(c);
            idx.println(String.format("%s\t%d\t%s\t%d", f.getEntryPoint(), sz, f.getName(), c.length()));
            emitted++;
            if (emitted % 500 == 0) println("progress " + emitted + "/" + mine);
        }
        one.close();
        idx.close();
        println("SHARD " + shard + "/" + shards + " mine=" + mine + " emitted=" + emitted
                + " decompileFailed=" + failed + " cBytes=" + bytes);
    }
}
