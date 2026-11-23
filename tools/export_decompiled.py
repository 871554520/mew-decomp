# -*- coding: utf-8 -*-
# Ghidra Headless Post-Script: 导出应用函数伪 C 代码与外部 API 调用清单
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

out_dir = os.path.join(os.getcwd(), "decompiled_out")
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

fm = currentProgram.getFunctionManager()
api_map_path = os.path.join(out_dir, "win32_api_calls.txt")
code_path = os.path.join(out_dir, "all_functions.c")

with open(code_path, "w") as cf, open(api_map_path, "w") as af:
    for func in fm.getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        name = func.getName()
        # 跳过常见编译器桩函数
        if name.startswith(("__scrt", "_RTC", "__security", "FID_conflict")):
            continue

        # 记录该函数调用了哪些外部 Win32/DLL API
        called_apis = []
        for called in func.getCalledFunctions(monitor):
            if called.isExternal() or called.isThunk():
                called_apis.append(called.getName())
        if called_apis:
            af.write("{} -> {}\n".format(name, ", ".join(sorted(set(called_apis)))))

        res = ifc.decompileFunction(func, 30, monitor)
        if res and res.decompileCompleted():
            cf.write("// === {} @ {} ===\n".format(name, func.getEntryPoint()))
            cf.write(res.getDecompiledFunction().getC())
            cf.write("\n\n")

print("Done. Exported to:", out_dir)
