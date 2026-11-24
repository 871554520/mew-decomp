#!/usr/bin/env python3
"""从 Ghidra 产物里推导缺失声明，写出 globals.h。

三类处理：
  1. 纯数据符号（DAT_/UNK_/EXT_/LAB_/PTR_/vftable/CRT 等） → extern unsigned long long
     · 但如果它**只被当作结构体用**（所有出现都是 X.field），则生成一个带全部被访问成员的
       结构体并声明为结构体变量 —— 这样成员访问才能编译
  2. 字符串符号（s_xxx_140abcdef）→ extern unsigned long long（当指针用）
  3. 被调用但未定义的函数 → extern unsigned long long NAME();

用法：python3 derive_decls.py [目标.c，默认 sample_one.c]
"""
import collections
import re
import sys

target = sys.argv[1] if len(sys.argv) > 1 else 'sample_one.c'
src = open(target).read()

defined = set(re.findall(
    r'^\s*(?:void|undefined\w*|code|int|long long|char|short|float|double|bool|\w+\s*\*)\s+'
    r'((?:thunk_|j_)?FUN_[0-9a-fA-F]+)\s*\(', src, re.M))

data_idents = set(re.findall(r'\b(_?(?:DAT|UNK|EXTD?|LAB)_[0-9a-fA-F]+)\b', src))
data_idents |= set(re.findall(r'\b(PTR_[A-Za-z0-9_]+)\b', src))
data_idents |= set(re.findall(r'\b(__std_[A-Za-z0-9_]+)\b', src))
data_idents |= set(re.findall(r'\b([sa]_[A-Za-z0-9_]+?_[0-9a-fA-F]{6,})\b', src))
data_idents.add('vftable')

called = set(re.findall(r'\b((?:thunk_|j_)?FUN_[0-9a-fA-F]+)\s*\(', src))
missing_calls = sorted(called - defined)

# --- 找出「只当结构体用」的符号 ---
member_uses = collections.defaultdict(set)
for m in re.finditer(r'\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b', src):
    member_uses[m.group(1)].add(m.group(2))

structable = {}
for ident, fields in member_uses.items():
    if ident not in data_idents:
        continue
    # 该符号除 "X." 之外还有别的用法吗？
    total = len(re.findall(r'\b%s\b' % re.escape(ident), src))
    as_member = len(re.findall(r'\b%s\s*\.' % re.escape(ident), src))
    if total == as_member and fields:
        structable[ident] = sorted(f for f in fields if re.fullmatch(r'[A-Za-z_]\w*', f))

with open('globals.h', 'w') as g:
    g.write('#ifndef MEW_GLOBALS_H\n#define MEW_GLOBALS_H\n')

    for ident, fields in sorted(structable.items()):
        g.write('struct S_%s {\n' % ident)
        for f in fields:
            g.write('    unsigned long long %s;\n' % f)
        g.write('};\n')
        g.write('extern struct S_%s %s;\n' % (ident, ident))

    skip = set(structable)
    for n in sorted(data_idents - skip):
        g.write('extern unsigned long long %s;\n' % n)
    for n in missing_calls:
        g.write('extern unsigned long long %s();\n' % n)
    g.write('#endif\n')

print('data decls: %d (其中结构体 %d)   fn protos: %d   defined in sample: %d'
      % (len(data_idents - skip), len(structable), len(missing_calls), len(defined)))
