#!/usr/bin/env python3
"""把 Ghidra 里 `X.field_0xNN` 形式的成员访问改写成带偏移的指针解引用。

Ghidra 的成员名里自带偏移（field_0x10 / field_0x2c），因此不需要知道结构体类型，
就能把 `X.field_0x10` 变成 `(*(unsigned long long *)((char *)&X + 0x10))`：
  · 偏移正确
  · 语法合法（不再报 "not a structure"）
  · 语义等价（读该地址的 64 位）

用法：
  python3 repair_member_access.py <文件.c>
  python3 repair_member_access.py <目录>        # 处理目录下所有 f_*.c
"""
import glob
import os
import re
import sys

PATTERN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\.(field_0x[0-9a-fA-F]+)\b')


def fix_text(s):
    return PATTERN.subn(
        lambda m: '(*(unsigned long long *)((char *)&%s + 0x%x))'
                  % (m.group(1), int(m.group(2).split('0x')[1], 16)),
        s)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'sample_one.c'
    if os.path.isdir(target):
        total = 0
        files = 0
        for f in glob.glob(os.path.join(target, 'f_*.c')):
            s = open(f, errors='replace').read()
            s2, n = fix_text(s)
            if n:
                open(f, 'w').write(s2)
                total += n
                files += 1
        print('member accesses rewritten in dir: %d (files %d)' % (total, files))
        return
    s = open(target, errors='replace').read()
    s2, n = fix_text(s)
    open(target, 'w').write(s2)
    print('member accesses rewritten:', n)


if __name__ == '__main__':
    main()
