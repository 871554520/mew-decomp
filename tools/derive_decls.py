#!/usr/bin/env python3
"""从 Ghidra 产物里精确推导缺失声明，写出 globals.h。

覆盖：
  · DAT_/UNK_/EXT_/LAB_ 等数据符号 → extern unsigned long long
  · s_/a_ 等字符串符号            → extern char [...]
  · FUN_/thunk_FUN_/j_FUN_ 等函数 → extern void NAME();
用法：python3 derive_decls.py [目标.c，默认 sample_one.c]
"""
import re
import sys

target = sys.argv[1] if len(sys.argv) > 1 else 'sample_one.c'
src = open(target).read()

# 已定义的函数（带函数体的）
defined = set(re.findall(
    r'^\s*(?:void|undefined\w*|code|int|long long|char|short|float|double|bool|\w+\s*\*)\s+'
    r'((?:thunk_|j_)?FUN_[0-9a-fA-F]+)\s*\(', src, re.M))

data_idents = set(re.findall(r'\b(_?(?:DAT|UNK|EXTD?|LAB)_[0-9a-fA-F]+)\b', src))
# MSVC 虚表与 CRT 符号（Ghidra 会直接引用它们）
data_idents |= set(re.findall(r'\b(PTR_[A-Za-z0-9_]+)\b', src))
data_idents |= set(re.findall(r'\b(__std_[A-Za-z0-9_]+)\b', src))
data_idents.add('vftable')
str_idents = set(re.findall(r'\b([sa]_[A-Za-z0-9_]+?_[0-9a-fA-F]{6,})\b', src))
called = set(re.findall(r'\b((?:thunk_|j_)?FUN_[0-9a-fA-F]+)\s*\(', src))
missing_calls = sorted(called - defined)

with open('globals.h', 'w') as g:
    g.write('#ifndef MEW_GLOBALS_H\n#define MEW_GLOBALS_H\n')
    for n in sorted(data_idents):
        g.write('extern unsigned long long %s;\n' % n)
    for n in sorted(str_idents):
        g.write('extern unsigned long long %s;\n' % n)
    for n in missing_calls:
        # 关键：不能声明成 void —— 反编译代码会把返回值参与运算/赋值，
        # void 会让成千上万行报 "operand of type 'void'"。用 64 位整数兼容一切用法。
        g.write('extern unsigned long long %s();\n' % n)
    g.write('#endif\n')

print('data decls: %d   string decls: %d   fn protos: %d   defined in sample: %d'
      % (len(data_idents), len(str_idents), len(missing_calls), len(defined)))
