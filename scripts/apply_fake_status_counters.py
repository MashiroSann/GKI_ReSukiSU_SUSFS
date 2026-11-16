#!/usr/bin/env python3
"""让伪造的 /sys/fs/selinux/status 页与真实策略代次保持同步。

背景
----
依赖 SUSFS selinux_hide 的 BakaSU 会把伪造 status 页交给普通 app
（SUSFS 补丁在 selinuxfs.c 的 sel_open_handle_status 里把 fake_status 返回）。
BakaSU 的 initialize_fake_status() 只在启动早期 memcpy 快照一次真实 status 页，
之后策略被 KernelSU / 模块 sepolicy 重载，真实页的 sequence/policyload 会前进
（sync-up 内核上实测 avdSeqNo=6），而伪造页仍是 0/0。

Duck Detector Build 1110 的 DirtySepolicy 2.2 一致性检查会把
    status.sequence / status.policyload      （伪造页：0/0）
与  /sys/fs/selinux/access 返回的 avd.seqno   （真实：6）
交叉比对，判定
    DirtySepolicy raw access protocol: DirtySepolicy WARNING
    Status baseline=Legacy initial status counters; avdSeqNo=6
最终把 SELinux 卡片判为 DANGER（"Enforcing with DirtySepolicy anomaly"）。

修复
----
在 sel_open_handle_status() 返回伪造页之前，用真实 status 页刷新
version/sequence/policyload/deny_unknown 四个字段，并保持 enforcing=1。
这样 app 看到的 status 计数与 access 返回的 avd.seqno 一致，DirtySepolicy
一致性检查即可通过；enforcing 仍然对外恒为 1（不暴露 permissive 状态）。

用法
----
    python3 apply_fake_status_counters.py <kernel-source-root>
    <kernel-source-root> = $KERNEL_ROOT/common（含 security/selinux/selinuxfs.c）

退出码
------
    0  已注入 / 已存在（幂等），或文件不含 SUSFS 的 fake status 代码（跳过）
    2  锚点不匹配（需要人工适配）
"""

import os
import re
import sys

MARK = "hmt-fake-status-sync"

BLOCK = """\t\tvoid *data = fake_status;
\t\tif (data) {
\t\t\t/* hmt-fake-status-sync: 用真实 status 页刷新计数，保持与 avd.seqno 一致 */
\t\t\tif (status) {
\t\t\t\tstruct selinux_kernel_status *fake_st = page_address(data);
\t\t\t\tstruct selinux_kernel_status *real_st = page_address(status);

\t\t\t\tfake_st->version = real_st->version;
\t\t\t\tfake_st->sequence = real_st->sequence;
\t\t\t\tfake_st->policyload = real_st->policyload;
\t\t\t\tfake_st->deny_unknown = real_st->deny_unknown;
\t\t\t\tfake_st->enforcing = 1;
\t\t\t}
\t\t\tfilp->private_data = data;
"""

ANCHOR_RE = re.compile(
    r"\t\tvoid \*data = fake_status;\n"
    r"\t\tif \(data\) \{\n"
    r"\t\t\tfilp->private_data = data;\n"
)


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <kernel-source-root>\n" % sys.argv[0])
        sys.exit(2)

    root = sys.argv[1]
    path = os.path.join(root, "security", "selinux", "selinuxfs.c")
    if not os.path.isfile(path):
        fail("找不到 %s" % path)

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARK in src:
        print("[fake-status] 已注入，跳过：%s" % path)
        return

    if "fake_status" not in src:
        print("[fake-status] 不含 SUSFS fake status 代码，跳过：%s" % path)
        return

    m = ANCHOR_RE.search(src)
    if not m:
        fail("%s: 找不到 sel_open_handle_status() 里的 fake_status 锚点" % path)

    patched = src[: m.start()] + BLOCK + src[m.end():]

    # 自检
    if patched.count(MARK) != 1:
        fail("注入后标记数量异常")
    if "fake_st->enforcing = 1;" not in patched:
        fail("注入后自检失败")
    # struct 定义来自 selinuxfs.c 已包含的 security.h
    if "struct selinux_kernel_status" not in patched:
        fail("注入后自检失败：缺少 struct selinux_kernel_status 引用")

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    print("[fake-status] 注入完成：%s" % path)
    print("[fake-status]   sel_open_handle_status(): 返回前用真实页刷新 sequence/policyload")


if __name__ == "__main__":
    main()
