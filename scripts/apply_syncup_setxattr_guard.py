#!/usr/bin/env python3
"""BakaSU sync-up：让 setxattr 初始化只在「无 SUSFS manual hook」时参与编译。

背景
----
BakaSU PR #662（sync-up）引入 `inode_setxattr` LSM hook 时，`selinux_hide_init_setxattr()`
原本被 `#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE ... #endif` 包住，
但 `ku_selinux_hide_enable()` 里的调用没包 → 接 SUSFS 的内核链接失败：
    ld.lld: error: undefined symbol: selinux_hide_init_setxattr

后来上游 commit a671d800（"fix2"）把**函数定义**挪出了 `#ifndef` 块（调用仍在外），
链接错误消失；但函数体引用了 `inode_doinit_with_dentry_fn`，而该变量只在
`#ifndef` 块内声明 → 接 SUSFS 时变成编译错误：
    error: use of undeclared identifier 'inode_doinit_with_dentry_fn'

本脚本做自适应修补（三种布局都能处理）：
- 旧布局（如 252b1520）：定义已在 #ifndef 内，只需给「调用」加同样保护；
- 新布局（a671d800）：定义被挪到 #ifndef 外 → 给「定义」和「调用」都加保护；
- 已修复布局（如 55f3dcb1 "test"，2026-11-16 22:21）：上游自己把「调用」移进了
  #ifndef 块 → 定义和调用都已被保护，本脚本直接跳过（不注入、不报错）。

`selinux_hide_init_setxattr()` 只服务于旧的 manual hook 实现；新 SUSFS 的隐藏由
内核侧 security/selinux/* 完成，接 SUSFS 时这两块本来就不该参与编译。

用法
----
    python3 apply_syncup_setxattr_guard.py <path/to/KernelSU/kernel/feature/selinux_hide.c>

退出码
------
    0  已注入 / 已存在
    2  锚点不匹配
"""

import os
import re
import sys

MARK = "hmt-syncup-setxattr-guard"
MACRO = "KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE"

DEF_RE = re.compile(r"^\s*(?:static|__maybe_static)\s+int\s+selinux_hide_init_setxattr\s*\(\s*\)\s*$")
CALL_RE = re.compile(r"^\s*ret\s*=\s*selinux_hide_init_setxattr\(\);\s*$")


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def find_block_end(lines, start):
    """从 start 行开始找花括号配对的结束行索引（0-based）。"""
    depth = 0
    seen = False
    for i in range(start, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    return i
    return None


def guarded_before(lines, idx):
    """判断 idx 之前是否存在未闭合的 #ifndef <MACRO> 区块。"""
    start = None
    for i in range(idx - 1, -1, -1):
        if re.match(r"^\s*#ifndef\s+" + MACRO + r"\b", lines[i]):
            start = i
            break
    if start is None:
        return False
    depth = 0
    for i in range(start + 1, idx):
        line = lines[i].strip()
        if re.match(r"^#if(n?def)?\b", line) or line.startswith("#if "):
            depth += 1
        elif line.startswith("#endif"):
            depth -= 1
            if depth < 0:
                return False
    return True


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <selinux_hide.c>\n" % sys.argv[0])
        sys.exit(2)

    path = sys.argv[1]
    if not os.path.isfile(path):
        fail("找不到 %s" % path)

    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")

    if any(MARK in l for l in lines):
        print("[setxattr-guard] 已注入，跳过：%s" % path)
        return

    def_idx = next((i for i, l in enumerate(lines) if DEF_RE.match(l)), None)
    call_idx = next((i for i, l in enumerate(lines) if CALL_RE.match(l)), None)
    if def_idx is None or call_idx is None:
        fail("%s: 找不到 selinux_hide_init_setxattr 的定义或调用" % path)

    def_guarded = guarded_before(lines, def_idx)
    call_guarded = guarded_before(lines, call_idx)
    if def_guarded and call_guarded:
        print("[setxattr-guard] 定义与调用均已在 #ifndef 保护内（上游已修复布局），跳过：%s" % path)
        return

    # 每一项：(行号, 要插入到该行之前的文本)
    ins = []
    added = 0

    # 1) 新布局：定义在 #ifndef 外 → 给定义加保护
    if not def_guarded:
        def_end = find_block_end(lines, def_idx)
        if def_end is None:
            fail("无法定位 selinux_hide_init_setxattr 定义结束行")
        ins.append((def_idx, "#ifndef " + MACRO + " // " + MARK + "\n"))
        ins.append((def_end + 1, "#endif // #ifndef " + MACRO + "\n"))
        added += 1

    # 2) 调用加保护
    if not call_guarded:
        if call_idx + 1 >= len(lines) or not re.match(r"^\s*if\s*\(ret\)\s*\{\s*$", lines[call_idx + 1]):
            fail("selinux_hide_init_setxattr() 调用后找不到 if (ret) { ... }")
        if_end = find_block_end(lines, call_idx + 1)
        if if_end is None:
            fail("无法定位 if (ret) { ... } 结束行")
        ins.append((call_idx, "#ifndef " + MACRO + " // " + MARK + "\n"))
        ins.append((if_end + 1, "#endif // #ifndef " + MACRO + "\n"))
        added += 1

    if not ins:
        fail("没有需要注入的位置（文件结构与预期不符）")

    base_mark = "\n".join(lines).count(MARK)
    base_endif = "\n".join(lines).count("#endif // #ifndef " + MACRO)

    for idx, text in sorted(ins, key=lambda x: -x[0]):
        lines.insert(idx, text)

    patched = "\n".join(lines)
    if patched.count(MARK) - base_mark != added:
        fail("注入后 #ifndef 数量异常（%d != %d）" % (patched.count(MARK) - base_mark, added))
    if patched.count("#endif // #ifndef " + MACRO) - base_endif != added:
        fail("注入后 #endif 数量异常")

    # 自检：修补后定义行/调用行都应处于 #ifndef 保护内（后插的 #endif 不影响后续判断）
    new_lines = patched.split("\n")
    new_def = next(i for i, l in enumerate(new_lines) if DEF_RE.match(l))
    new_call = next(i for i, l in enumerate(new_lines) if CALL_RE.match(l))
    if not guarded_before(new_lines, new_def):
        fail("自检失败：定义未处于 #ifndef 保护内")
    if not guarded_before(new_lines, new_call):
        fail("自检失败：调用未处于 #ifndef 保护内")

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    print("[setxattr-guard] 注入完成：%s" % path)
    print("[setxattr-guard]   定义加保护=%s，调用加保护=yes" % (added == 2))


if __name__ == "__main__":
    main()
