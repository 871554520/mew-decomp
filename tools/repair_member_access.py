#!/usr/bin/env python3
"""把 Ghidra 的字节切片成员访问改写成带偏移的指针解引用。

Ghidra 对聚合类型使用 `_OFF_SIZE_` 记法，例如：
    local_28._0_1_ = 0x41;        # 偏移 0、1 字节
    uStack_20 = (ulonglong)(ushort)s_x._8_2_;   # 偏移 8、2 字节

改写成（语义等价、偏移正确、语法合法）：
    (*(unsigned char  *)((char *)&local_28 + 0)) = 0x41;
    uStack_20 = (ulonglong)(ushort)(*(unsigned short *)((char *)&s_x + 8));

同时兼容 `field_0xNN` 形态（部分产物会是这种）。

用法：
  python3 repair_member_access.py <文件.c>
  python3 repair_member_access.py <目录>     # 处理目录下所有 f_*.c
"""
import glob
import os
import re
import sys

# _偏移_宽度_
SLICE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*_(\d+)_(\d+)_\b')
# field_0xNN（宽度未知，默认 8）
FIELD = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\.(field_0x[0-9a-fA-F]+)\b')

WIDTH = {
    '1': 'unsigned char',
    '2': 'unsigned short',
    '3': 'unsigned int',
    '4': 'unsigned int',
    '8': 'unsigned long long',
}


def _slice_repl(m):
    ident, off, size = m.group(1), m.group(2), m.group(3)
    typ = WIDTH.get(size, 'unsigned long long')
    return '(*(%s *)((char *)&%s + %s))' % (typ, ident, off)


def _field_repl(m):
    ident, name = m.group(1), m.group(2)
    off = int(name.split('0x')[1], 16)
    return '(*(unsigned long long *)((char *)&%s + 0x%x))' % (ident, off)


def fix_segment(seg):
    seg = SLICE.sub(_slice_repl, seg)
    seg = FIELD.sub(_field_repl, seg)
    return seg


def fix_text(text):
    """逐行处理，跳过字符串字面量与块注释，避免误伤。"""
    out = []
    in_block = False
    changed = 0
    for line in text.split('\n'):
        # 块注释状态机（保持行数不变）
        if in_block:
            if '*/' in line:
                in_block = False
            out.append(line)
            continue
        stripped = line.lstrip()
        if stripped.startswith('/*') or stripped.startswith('*'):
            if '*/' not in line:
                in_block = True
            out.append(line)
            continue

        # 按双引号切分，只处理奇数段之外的部分（引号内是字符串）
        parts = line.split('"')
        new_parts = []
        for i, p in enumerate(parts):
            if i % 2 == 1:          # 字符串内容，原样保留
                new_parts.append(p)
            else:
                before = p
                p = fix_segment(p)
                if p != before:
                    changed += 1
                new_parts.append(p)
        out.append('"'.join(new_parts))
    return '\n'.join(out), changed


def process_file(path):
    text = open(path, errors='replace').read()
    fixed, n = fix_text(text)
    if n:
        open(path, 'w').write(fixed)
    return n


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'sample_one.c'
    if os.path.isdir(target):
        total = 0
        files = 0
        for f in glob.glob(os.path.join(target, 'f_*.c')):
            n = process_file(f)
            if n:
                total += n
                files += 1
        print('member accesses rewritten in dir: %d (files %d)' % (total, files))
        return
    n = process_file(target)
    print('member accesses rewritten:', n)


if __name__ == '__main__':
    main()
