#!/usr/bin/env python3
"""编译前对 Ghidra 产物做最小清洗，并把可修的符号收进 globals 需要的 typedef。

用法：python3 postprocess_sample.py <目标.c> <typedef输出.h>

做三件事：
1. 删掉 Ghidra 偶尔吐出的 C++ 模板语法 `_Func_impl_no_alloc<...>`（C 里不可能编译）
2. 把 `_func_1234` 这类函数指针类型收集起来，生成 `typedef void (*_func_1234)();`
3. 去掉残留的 `&DAT_x` 里的反斜杠转义之类脏字符（保持幂等）
"""
import re
import sys

src_path = sys.argv[1]
hdr_path = sys.argv[2]

src = open(src_path, errors='replace').read()

# 1. 模板语法：_Func_impl_no_alloc<...> / _Func_impl<...> 之类
before = src
src = re.sub(r'_Func_impl_no_alloc<[^;\n]*?>', '__TMPL__', src)
src = re.sub(r'_Func_impl<[^;\n]*?>', '__TMPL__', src)
if src != before:
    print('template junk removed:', before.count('_Func_impl') - src.count('_Func_impl'))

# 2. 函数指针类型名
func_types = sorted(set(re.findall(r'\b(_func_[0-9a-fA-F]+)\b', src)))
with open(hdr_path, 'w') as h:
    h.write('#ifndef MEW_FUNCTYPES_H\n#define MEW_FUNCTYPES_H\n')
    for t in func_types:
        h.write('typedef void (*%s)();\n' % t)
    h.write('#endif\n')

if '#include "functypes.h"' not in src:
    if '#include "globals.h"' in src:
        src = src.replace('#include "globals.h"', '#include "globals.h"\n#include "functypes.h"', 1)
    else:
        src = '#include "functypes.h"\n' + src

open(src_path, 'w').write(src)
print('func typedefs:', len(func_types))
