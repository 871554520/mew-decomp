/* 给 Ghidra 反编译产物补类型与平台声明，只为让它尽量通过编译检查 */
#ifndef MEW_SHIM_H
#define MEW_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdarg.h>
#include <wchar.h>

/* Ghidra 的占位类型 */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef signed char char1;
typedef unsigned char uchar;
typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned long ulong;
typedef unsigned short word;
typedef int bool32;

/* code = 指令/函数体。用「无原型」函数类型：
   code *p; p(a, b) 合法（K&R 风格），避免 "too many arguments" 成片报错 */
typedef void code();

/* Ghidra 的拼接/拆位伪函数 */
#define CONCAT44(hi, lo) (((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo))
#define CONCAT22(hi, lo) ((unsigned int)((((unsigned int)(hi) & 0xffff) << 16) | ((unsigned int)(lo) & 0xffff)))
#define CONCAT31(hi, lo) ((unsigned int)((((unsigned int)(hi) & 0xffffff) << 8) | ((unsigned int)(lo) & 0xff)))
#define CONCAT13(a, b)   ((unsigned int)((((unsigned int)(a) & 0xff) << 24) | ((unsigned int)(b) & 0xffffff)))
#define CONCAT12(a, b)   ((unsigned int)((((unsigned int)(a) & 0xffff) << 16) | ((unsigned int)(b) & 0xffff)))
#define CONCAT11(a, b)   ((unsigned short)((((unsigned int)(a) & 0xff) << 8) | ((unsigned int)(b) & 0xff)))
#define SUB84(x, n)      ((unsigned int)(((unsigned long long)(x)) >> ((n) * 8)))
#define SUB41(x, n)      ((unsigned char)(((unsigned int)(x)) >> ((n) * 8)))
#define SUB42(x, n)      ((unsigned short)(((unsigned int)(x)) >> ((n) * 8)))
#define __PAIR64(hi, lo) CONCAT44(hi, lo)
#define ZEXT48(x)        ((unsigned long long)(unsigned int)(x))
#define SEXT48(x)        ((unsigned long long)(long long)(int)(x))
#define ZEXT816(x)       ((unsigned long long)(unsigned long long)(x))
#define SEXT816(x)       ((unsigned long long)(long long)(x))

/* MSVC / 平台宏 */
#ifndef __noreturn__
#define __noreturn__
#endif
#ifndef __fastcall
#define __fastcall
#endif
#ifndef __cdecl
#define __cdecl
#endif
#ifndef WINAPI
#define WINAPI
#endif
#ifndef APIENTRY
#define APIENTRY
#endif
#ifndef FARPROC
#define FARPROC void*
#endif
#ifndef LPVOID
#define LPVOID void*
#endif
#ifndef HANDLE
#define HANDLE void*
#endif
#ifndef DWORD
#define DWORD unsigned int
#endif
#ifndef BOOL
#define BOOL int
#endif


/* Windows 过程指针与 TEB 变量（Ghidra 会直接引用） */
typedef void (*PROC)();
typedef void (*FARPROC_ALT)();
extern unsigned long long ThreadLocalStoragePointer;
extern unsigned long long TEB;
extern unsigned long long PEB;
extern unsigned long long _tls_index;

#endif
