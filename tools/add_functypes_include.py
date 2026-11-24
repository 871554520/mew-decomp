#!/usr/bin/env python3
"""给逐函数拆分出来的 .c 补上 functypes.h 的 include。用法：python3 add_functypes_include.py <目录>"""
import glob
import os
import sys

d = sys.argv[1] if len(sys.argv) > 1 else 'perf'
n = 0
for f in glob.glob(os.path.join(d, 'f_*.c')):
    t = open(f, errors='replace').read()
    if 'functypes.h' in t:
        continue
    if '#include "globals.h"' in t:
        t = t.replace('#include "globals.h"', '#include "globals.h"\n#include "functypes.h"', 1)
    else:
        t = '#include "functypes.h"\n' + t
    open(f, 'w').write(t)
    n += 1
print('patched includes:', n)
