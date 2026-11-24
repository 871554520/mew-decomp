#!/usr/bin/env python3
"""把 Ghidra 合并产物按函数边界切成单文件，便于逐函数编译统计。

用法：python3 split_functions.py sample_all.c 输出目录
"""
import os
import re
import sys

src_path = sys.argv[1] if len(sys.argv) > 1 else 'sample_all.c'
out_dir = sys.argv[2] if len(sys.argv) > 2 else 'perf'

src = open(src_path).read()
parts = re.split(r'/\* ---- ([0-9a-fx]+) size=(\d+) ---- \*/', src)
os.makedirs(out_dir, exist_ok=True)
head = '#include "shim.h"\n#include "globals.h"\n'
n = 0
for i in range(1, len(parts) - 2, 3):
    addr = parts[i]
    body = parts[i + 2]
    with open(os.path.join(out_dir, 'f_%s.c' % addr), 'w') as w:
        w.write(head + body)
    n += 1
print('split', n)
