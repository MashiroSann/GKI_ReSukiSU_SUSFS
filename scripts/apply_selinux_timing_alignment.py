#!/usr/bin/env python3
"""对齐 SUSFS selinux_hide 的 setprocattr A/B 路径，消除 Duck Detector 1110
新增的 app_zygote attr/current 时序判据。

背景
----
Duck Detector Build 1110 新增了一条实验性判据：

    App Zygote attr/current timing (experimental): Positive A−B timing asymmetry

它由 zygotePreload 的 app_zygote 载体写 /proc/self/attr/current 两次：
A = 无效 type 的上下文（无前导换行），B = 等长但带前导换行的同一串；
两者都应当返回 EINVAL。判据本身只取“配对中位数 A−B 的符号”：
为正（A 更慢）即判 POSITIVE，并在 APK 里直接映射为 SELinux 卡片 DANGER
（ik3.smali: el3.APP_ZYGOTE_ATTR_TIMING + ii3.POSITIVE -> kd0.DANGER）。

而 SUSFS selinux_hide 的 susfs_selinux_setprocattr() 里保留了 stock 的分支：

    if (size && str[0] && str[0] != '\\n') { ... 解析上下文 ... }
    ...
    if (sid == 0) goto abort_change;      /* B 跳过解析后从这里返回 -EINVAL */

于是 A 恒比 B 多一次 policy 解析 -> A 恒慢 -> 稳定为正 -> 必然 DANGER。
这个路径差与“隐藏 KSU/LSPosed 上下文”是同一段代码，无法靠“藏得更好”消除。

做法
----
在 susfs_selinux_setprocattr() 入口把前导换行剥掉，让 A/B 走同一条解析路径
（B 解析“A 去掉最后一个字符”的串，同样在 type 查找处失败，成本几乎一致）。
行为不变：两者仍然返回 -EINVAL，与 stock 一致；隐藏逻辑完全不受影响。

用法
----
    python3 apply_selinux_timing_alignment.py <kernel-source-root>

    <kernel-source-root> 为内核树根（含 security/selinux/hooks.c），
    构建流程里是 $KERNEL_ROOT/common。

退出码
------
    0  已注入 / 已存在（幂等）
    2  找不到 security/selinux/hooks.c 或 susfs_selinux_setprocattr（SUSFS 版本不匹配）
"""

import os
import re
import sys

MARK_BEGIN = "hmt-timing-align:begin"
MARK_END = "hmt-timing-align:end"

FUNC_SIG = "static int susfs_selinux_setprocattr(const char *name, void *value, size_t size)"

INSERT = """\t/* hmt-timing-align:begin */
\t/*
\t * Duck Detector (Build 1110+) 的 app_zygote attr/current 时序判据：
\t * A（无效 type、无前导换行）会走上下文解析，B（等长、前导换行）直接
\t * 跳过解析，于是 A 恒慢 -> paired median 恒正 -> 被判 DANGER。
\t * 这里把前导换行剥掉，让两类载荷走同一条解析路径，消除稳定时序差；
\t * 两者仍然返回 -EINVAL，行为与 stock 一致。
\t */
\tif (size && str[0] == '\\n') {
\t\tvalue = (char *)value + 1;
\t\tsize--;
\t\tstr = value;
\t}
\t/* hmt-timing-align:end */
"""


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <kernel-source-root>\n" % sys.argv[0])
        sys.exit(2)

    root = sys.argv[1]
    path = os.path.join(root, "security", "selinux", "hooks.c")
    if not os.path.isfile(path):
        fail("找不到 %s（该内核树没有 security/selinux/hooks.c）" % path)

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARK_BEGIN in src:
        print("[timing-align] 已注入，跳过：%s" % path)
        return

    m = re.search(re.escape(FUNC_SIG), src)
    if not m:
        fail(
            "%s: 找不到 susfs_selinux_setprocattr()。\n"
            "        该函数由 SUSFS kernel_patches/50_add_susfs_in_gki-*.patch 插入，\n"
            "        请确认 SUSFS 版本 >= 784ac9e6 且主补丁已应用。" % path
        )

    start = m.start()
    end = src.find("\n}\n", start)
    if end < 0:
        fail("%s: 找不到 susfs_selinux_setprocattr() 的函数结尾" % path)
    body = src[start:end]

    am = re.search(r"(?m)^([ \t]*)char \*str = value;[ \t]*$", body)
    if not am:
        fail("%s: susfs_selinux_setprocattr() 里找不到 'char *str = value;' 锚点" % path)

    abs_start = start + am.start()
    abs_end = start + am.end()

    patched = src[:abs_end] + "\n" + INSERT.rstrip("\n") + src[abs_end:]

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    # 自检
    with open(path, "r", encoding="utf-8") as f:
        out = f.read()
    for needle in (MARK_BEGIN, MARK_END,
                   "if (size && str[0] == '\\n')",
                   "if (size && str[0] && str[0] != '\\n')"):
        if needle not in out:
            fail("注入后自检失败，缺少：%s" % needle)

    # 注入点必须在解析分支之前，否则等于没改
    if out.find(MARK_BEGIN) > out.find("if (size && str[0] && str[0] != '\\n')"):
        fail("注入位置异常：对齐代码落在了解析分支之后")

    print("[timing-align] 注入完成：%s" % path)
    print("[timing-align]   susfs_selinux_setprocattr: 剥离前导换行，A/B 走同一解析路径")


if __name__ == "__main__":
    main()
