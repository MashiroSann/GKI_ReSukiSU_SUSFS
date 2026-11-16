#!/usr/bin/env python3
"""给 BakaSU sync-up(PR #662) 的 selinux_hide.c 补一层 #ifndef 保护。

背景
----
BakaSU sync-up 分支的 head 提交 `252b1520`
（"kernel: Add LSM hook for inode_setxattr", KernelSU PR #3996）在
`kernel/feature/selinux_hide.c` 的 `ksu_selinux_hide_enable()` 里新增了：

    ret = selinux_hide_init_setxattr();
    if (ret) {
        pr_err("selinux_hide: init: setxattr helpers err: %d\\n", ret);
        return ret;
    }

但同一个提交把 `selinux_hide_init_setxattr()` 的**定义**放进了
`#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE` 块内。

只要 SUSFS 提供 manual hook（即 `security/selinux/hooks.c` 里出现
`ksu_selinux_hide_running`，BakaSU 的 `susfs_compat.mk` 就会定义
`KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE`），定义就被预处理器裁掉、
调用却还在 → 链接报：

    ld.lld: error: undefined symbol: selinux_hide_init_setxattr

新版 SUSFS 的 setxattr 隐藏由内核侧 `handle_selinux_inode_setxattr` 接管，
BakaSU 侧这个 helper 在 manual hook 模式下本来就不需要调用，因此这里直接把
调用包进同样的 `#ifndef`。属于上游漏保护，等 BakaSU 修复后本脚本可移除。

用法
----
    python3 apply_syncup_setxattr_guard.py <path/to/KernelSU/kernel/feature/selinux_hide.c>

退出码
------
    0  已注入 / 已存在（幂等）；或该文件不含这段代码（非 sync-up，无需处理）
    2  锚点不匹配（需要人工适配）
"""

import os
import sys

MARK = "hmt-syncup-setxattr-guard"

CALL_BLOCK = """    ret = selinux_hide_init_setxattr();
    if (ret) {
        pr_err("selinux_hide: init: setxattr helpers err: %d\\n", ret);
        return ret;
    }"""

GUARDED_BLOCK = """#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    /* hmt-syncup-setxattr-guard: sync-up(252b1520) 漏了这层 guard，
     * 该函数定义只在宏未定义时编译；manual hook 模式下由内核侧接管。 */
    ret = selinux_hide_init_setxattr();
    if (ret) {
        pr_err("selinux_hide: init: setxattr helpers err: %d\\n", ret);
        return ret;
    }
#endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE"""


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <selinux_hide.c>\n" % sys.argv[0])
        sys.exit(2)

    path = sys.argv[1]
    if not os.path.isfile(path):
        fail("找不到 %s" % path)

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARK in src:
        print("[syncup-guard] 已注入，跳过：%s" % path)
        return

    if "selinux_hide_init_setxattr" not in src:
        # main / 其他分支没有这段代码，无需处理
        print("[syncup-guard] 该文件不含 selinux_hide_init_setxattr，跳过：%s" % path)
        return

    if src.count(CALL_BLOCK) != 1:
        fail(
            "%s: 调用锚点匹配 %d 次（期望 1 次），sync-up 结构可能已变，需人工适配"
            % (path, src.count(CALL_BLOCK))
        )

    patched = src.replace(CALL_BLOCK, GUARDED_BLOCK, 1)

    # 自检：注入后花括号/预处理配平粗检
    if patched.count("#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE") != \
            src.count("#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE") + 2:
        fail("注入后预处理指令数量异常")
    if patched.count("#endif") != src.count("#endif") + 1:
        fail("注入后 #endif 数量异常")

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    print("[syncup-guard] 注入完成：%s" % path)
    print("[syncup-guard]   ksu_selinux_hide_enable(): selinux_hide_init_setxattr() 调用已加 #ifndef 保护")


if __name__ == "__main__":
    main()
