#!/usr/bin/env python3
"""把「标量被当数组/指针用」的写法改写成带偏移的指针解引用。

Ghidra 产物里常见：
    s_en_US_utf8_14111f930[0]     # 全局被声明成标量，却按下标访问
    *local_c8                      # 局部标量被当指针解引用

改写为（语义等价、可编译）：
    (*(unsigned long long *)((char *)&s_en_US_utf8_14111f930 + 8*0))
    (*(unsigned long long *)((char *)&local_c8))

只处理「确定是标量」的标识符：
  · globals.h 里以 `extern ... NAME;` 声明的全局
  · 本文件里以 `unsigned long long NAME;` 之类单值声明的局部

用法：python3 repair_scalar_access.py <目标.c> [globals.h]
"""
import re
import sys

SCALAR_DECL = re.compile(
    r'^\s*(?:unsigned\s+long\s+long|longlong|ulonglong|undefined8|undefined4|int|uint|long|short|char)\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=)', re.M)
GLOBAL_DECL = re.compile(r'^extern\s+[^;]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*;', re.M)

IDX = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\[\]]{1,40}?)\s*\]')
DEREF = re.compile(r'(?<![*&\w])\*\s*([A-Za-z_][A-Za-z0-9_]*)\b')


def mask(text):
    """把字符串与注释内容替换成空格，返回 (masked, original) 供改写定位。"""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            out.append(' ')
            i += 1
            while i < n and text[i] != '"':
                out.append(' ')
                i += 1
            if i < n:
                out.append(' ')
                i += 1
        elif c == '/' and i + 1 < n and text[i + 1] == '*':
            while i < n and not (text[i] == '*' and i + 1 < n and text[i + 1] == '/'):
                out.append('\n' if text[i] == '\n' else ' ')
                i += 1
            if i < n:
                out.append('  ')
                i += 2
        elif c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                out.append(' ')
                i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def load_globals(path):
    try:
        g = open(path, errors='replace').read()
    except OSError:
        return set()
    return set(GLOBAL_DECL.findall(g))


def fix(text, globals_set):
    masked = mask(text)
    scalars = set(globals_set)
    scalars |= set(SCALAR_DECL.findall(masked))

    edits = []  # (start, end, replacement)
    for m in IDX.finditer(masked):
        name, idx = m.group(1), m.group(2)
        if name not in scalars:
            continue
        # 下标表达式必须是简单表达式，避免误改复杂结构
        if not re.fullmatch(r'[0-9a-fx+\-*/ ]{1,40}', idx):
            continue
        repl = '(*(unsigned long long *)((char *)&%s + 8*(%s)))' % (name, idx.strip())
        edits.append((m.start(), m.end(), repl))

    # 注意：`*NAME` 的改写会误伤指针声明（`unsigned long long *p;`），v15 实测导致 7,516 条
    # 语法错误，因此默认关闭，只做下标改写。

    # 从后往前应用，避免位移
    edits.sort(key=lambda e: e[0], reverse=True)
    out = text
    for s, e, r in edits:
        out = out[:s] + r + out[e:]
    return out, len(edits)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'sample_one.c'
    gpath = sys.argv[2] if len(sys.argv) > 2 else 'globals.h'
    globals_set = load_globals(gpath)
    text = open(target, errors='replace').read()
    fixed, n = fix(text, globals_set)
    open(target, 'w').write(fixed)
    print('scalar accesses rewritten:', n)


if __name__ == '__main__':
    main()
