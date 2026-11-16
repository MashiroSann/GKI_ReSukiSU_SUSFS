#!/usr/bin/env python3
"""修复 sync-up 内核上「开关一次隐藏 SELinux 后隐藏失效」的问题。

背景
----
sync-up(252b1520) 的 ksu_selinux_hide_enable() 开头要求 backup_sepolicy
存在，否则直接返回 -EAGAIN：

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
        if (!backup_sepolicy) {
            pr_err("no backup sepolicy available, please save feature and reboot to retry!\\n");
            return -EAGAIN;
        }
    ...
    #endif

而 boot-completed 阶段 ksu_selinux_hide_drop_backup_if_unused() 会把
backup_sepolicy 释放掉。于是用户在设置里「关一次再开」时：
  set to 0 -> exit selinux hide
  set to 1 -> init selinux hide -> 缺少 backup_sepolicy -> -EAGAIN
  => ksu_selinux_hide_running 保持 false，所有隐藏全部失效
     （Duck 报 context oracle=11 / LSPosed 卡片 DANGER）。

新版 SUSFS 的隐藏由内核侧 security/selinux/* 实现，enable() 根本不需要
backup policy。本脚本在「SUSFS 提供 manual hook」（KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
被定义）时把这个检查整段编译掉，使运行时开关可以反复生效。

用法
----
    python3 apply_syncup_reenable_fix.py <path/to/KernelSU/kernel/feature/selinux_hide.c>

退出码
------
    0  已注入 / 已存在 / 无需处理
    2  锚点不匹配
"""

import os
import sys

MARK = "hmt-syncup-reenable-fix"

BLOCK = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    if (!backup_sepolicy) {
        pr_err("no backup sepolicy available, please save feature and reboot to retry!\\n");
        return -EAGAIN;
    }
#else
    if (!backup_policydb) {
        pr_err("no backup policydb available, please save feature and reboot to retry!\\n");
        return -EAGAIN;
    }

    if (!backup_sidtab) {
        pr_err("no backup sidtab available, please save feature and reboot to retry!\\n");
        return -EAGAIN;
    }
#endif"""

GUARDED = """#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
/* hmt-syncup-reenable-fix: manual hook 模式下隐藏由内核侧实现，运行时开关
 * 不再依赖 backup policy；否则 boot-completed 丢弃 backup 后再次开启会
 * 返回 -EAGAIN 导致隐藏全部失效。 */
""" + BLOCK + """
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
        print("[reenable-fix] 已注入，跳过：%s" % path)
        return

    if "no backup sepolicy available" not in src:
        print("[reenable-fix] 不含 sync-up 的 backup policy 检查，跳过：%s" % path)
        return

    if src.count(BLOCK) != 1:
        fail("%s: backup 检查块匹配 %d 次（期望 1 次）" % (path, src.count(BLOCK)))

    patched = src.replace(BLOCK, GUARDED, 1)

    if patched.count("#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE") != \
            src.count("#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE") + 2:
        fail("注入后预处理指令数量异常")

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    print("[reenable-fix] 注入完成：%s" % path)
    print("[reenable-fix]   ksu_selinux_hide_enable(): backup policy 检查在 manual hook 模式下编译掉")


if __name__ == "__main__":
    main()
