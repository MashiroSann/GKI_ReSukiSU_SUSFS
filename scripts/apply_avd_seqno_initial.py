#!/usr/bin/env python3
"""让 /sys/fs/selinux/access 返回的 avd.seqno 保持 stock 初始值 1。

背景
----
sync-up 内核上的策略在启动过程中会被重载多次，live policy 的 latest_granting
变成 6，于是 SUSFS 的 susfs_security_compute_av_user() 返回的 avd.seqno=6。
Duck Detector Build 1110 的 DirtySepolicy 2.2 一致性检查把
    avdSeqNo != 1
当作「非初始策略代次（可能被重载/篡改）」：
    DirtySepolicy 2.2 compatibility=WARNING
    Non-initial avdSeqNo; may be a legitimate policy reload
最终把 SELinux 卡片判成 DANGER（"Enforcing with DirtySepolicy anomaly"）。

而 main 分支内核（策略只加载一次，avd.seqno=1）上 Duck 的该项是 OK 的。

修复
----
在 susfs_security_compute_av_user() 里 avd_init() 之后把 avd->seqno 强制设为 1，
让 app 侧 /access 查询看到 stock 初始代次。audit/allow 等其它字段不受影响。

用法
----
    python3 apply_avd_seqno_initial.py <kernel-source-root>
    root = $KERNEL_ROOT/common（含 security/selinux/ss/services.c）

退出码
------
    0  已注入 / 已存在（幂等）；或文件中没有 SUSFS 的 compute_av_user（跳过）
    2  锚点不匹配
"""

import os
import re
import sys

MARK = "hmt-avd-seqno-initial"

FUNC_RE = re.compile(r"void susfs_security_compute_av_user\(struct selinux_state \*state,")
AVD_INIT_RE = re.compile(r"(?m)^([ \t]*)avd_init\(policy, avd\);[ \t]*$")


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <kernel-source-root>\n" % sys.argv[0])
        sys.exit(2)

    root = sys.argv[1]
    path = os.path.join(root, "security", "selinux", "ss", "services.c")
    if not os.path.isfile(path):
        fail("找不到 %s" % path)

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARK in src:
        print("[avd-seqno] 已注入，跳过：%s" % path)
        return

    fm = FUNC_RE.search(src)
    if not fm:
        print("[avd-seqno] 不含 susfs_security_compute_av_user（SUSFS 版本不匹配？），跳过：%s" % path)
        return

    # 只在函数体内（开头后 2000 字符内）找 avd_init
    region_start = fm.start()
    region = src[region_start:region_start + 2000]
    am = AVD_INIT_RE.search(region)
    if not am:
        fail("%s: susfs_security_compute_av_user() 里找不到 avd_init(policy, avd);" % path)

    indent = am.group(1)
    insert = (
        "\n" + indent + "/* hmt-avd-seqno-initial: DirtySepolicy 2.2 视非 1 的 "
        "avd.seqno 为策略重载异常；这里保持 stock 初始代次 */\n"
        + indent + "avd->seqno = 1;\n"
    )
    abs_end = region_start + am.end()
    patched = src[:abs_end] + insert + src[abs_end:]

    if patched.count(MARK) != 1:
        fail("注入后标记数量异常")
    if "avd->seqno = 1;" not in patched:
        fail("注入后自检失败")

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    print("[avd-seqno] 注入完成：%s" % path)
    print("[avd-seqno]   susfs_security_compute_av_user(): avd->seqno = 1")


if __name__ == "__main__":
    main()
