#!/usr/bin/env python3
"""对齐 SUSFS selinux_hide 的 setprocattr A/B 路径，消除 Duck Detector 1110
新增的 app_zygote attr/current 时序判据。

背景
----
Duck Detector Build 1110 新增了一条实验性判据（APK 里直接映射为 SELinux DANGER）：

    App Zygote attr/current timing (experimental): Positive A−B timing asymmetry

载荷（从 libduckdetector.so 里确认）：

    A = "u:r:__selinux_hide_probe_invalid__:s0"
    B = "\\n" + A[1:]        # 同长度，首字节换成换行

两者都应当返回 -EINVAL。判据只取“配对中位数 A−B 的符号”：为正（A 更慢）即
POSITIVE，ik3.smali 中 el3.APP_ZYGOTE_ATTR_TIMING + ii3.POSITIVE -> kd0.DANGER。

而 stock / 未对齐的 SUSFS 实现里：

    if (size && str[0] && str[0] != '\\n') { ... 解析上下文 ... }
    ...
    if (sid == 0) goto abort_change;      /* B 跳过解析，直接从这返回 -EINVAL */

A 恒比 B 多一次 policy 解析 -> A 恒慢 -> 稳定为正 -> 必然 DANGER。

做法
----
在 susfs_selinux_setprocattr() 入口把 B 的首字节 '\\n' 就地替换成 'u'
（A 的首字符），这样 B 变成与 A 完全相同的字节串，两者走完全相同的解析路径；
随后在解析块之后加一个判断，把“原本是前导换行”的写入仍按 stock 语义返回
-EINVAL（stock 对前导换行不做解析、直接按未指定上下文处理）。

效果：
  - A/B 解析成本一致 -> paired median ≈ 0 -> BASELINE/INCONCLUSIVE，不再 Danger；
  - 行为不变：前导换行的写入仍然返回 -EINVAL；
  - 隐藏逻辑（sus type EINVAL、AV 抹位、fake status）完全不受影响。

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
PARSE_ANCHOR = r"if (size && str[0] && str[0] != '\n')"

# 插在 `char *str = value;` 之后：把 B 的首字节换行换成 'u'，与 A 对齐
HEAD_INSERT = """\tint align_was_newline = 0;
\t/* hmt-timing-align:begin */
\t/*
\t * Duck Detector (Build 1110+) 的 app_zygote attr/current 时序判据：
\t *   A = "u:r:__selinux_hide_probe_invalid__:s0"
\t *   B = 同长度、首字节换行（即 A[0] 被替换成 '\\n'）
\t * stock 对 A 解析上下文、对 B 直接跳过解析，A 恒慢 -> paired median 恒正 ->
\t * 判 DANGER。这里把 B 的首个 '\\n' 就地替换成 'u'（与 A 首字符一致），
\t * 使 A/B 走完全相同的解析路径；随后仍按 stock 语义返回 -EINVAL。
\t */
\tif (size && str[0] == '\\n') {
\t\tstr[0] = 'u';
\t\talign_was_newline = 1;
\t}
\t/* hmt-timing-align:end */
"""

# 插在 `new = prepare_creds();` 之前：前导换行的写入保持 stock 的 -EINVAL 语义
TAIL_INSERT = """\t/* hmt-timing-align:begin */
\tif (align_was_newline) {
\t\t/* stock 对前导换行的载荷不做解析、直接 -EINVAL，这里保持同样结果 */
\t\treturn -EINVAL;
\t}
\t/* hmt-timing-align:end */
"""


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def function_body(src, what):
    m = re.search(re.escape(FUNC_SIG), src)
    if not m:
        return None
    start = m.start()
    end = src.find("\n}\n", start)
    if end < 0:
        fail("%s: 找不到 susfs_selinux_setprocattr() 的函数结尾" % what)
    return start, end


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

    fb = function_body(src, path)
    if not fb:
        fail(
            "%s: 找不到 susfs_selinux_setprocattr()。\n"
            "        该函数由 SUSFS kernel_patches/50_add_susfs_in_gki-*.patch 插入，\n"
            "        请确认 SUSFS 版本 >= 784ac9e6 且主补丁已应用。" % path
        )
    start, end = fb
    body = src[start:end]

    am = re.search(r"(?m)^([ \t]*)char \*str = value;[ \t]*$", body)
    if not am:
        fail("%s: susfs_selinux_setprocattr() 里找不到 'char *str = value;' 锚点" % path)
    head_pos = start + am.end()

    tm = re.search(r"(?m)^([ \t]*)new = prepare_creds\(\);[ \t]*$", body)
    if not tm:
        fail("%s: susfs_selinux_setprocattr() 里找不到 'new = prepare_creds();' 锚点" % path)
    tail_pos = start + tm.start()

    if head_pos >= tail_pos:
        fail("%s: 锚点顺序异常（char *str 在 prepare_creds 之后？）" % path)

    patched = (
        src[:head_pos]
        + "\n"
        + HEAD_INSERT.rstrip("\n")
        + src[head_pos:tail_pos]
        + "\n"
        + TAIL_INSERT.rstrip("\n")
        + "\n"
        + src[tail_pos:]
    )

    # 自检（内存中，通过后再落盘）
    fb2 = function_body(patched, path)
    if not fb2:
        fail("注入后自检失败：找不到 susfs_selinux_setprocattr()")
    s2, e2 = fb2
    fn = patched[s2:e2]
    p_head = fn.find("hmt-timing-align:begin")
    p_parse = fn.find(PARSE_ANCHOR)
    p_align = fn.find("if (align_was_newline) {")
    p_prep = fn.find("new = prepare_creds();")
    if not (0 <= p_head < p_parse < p_align < p_prep):
        fail(
            "注入位置异常（head=%d parse=%d tail=%d prepare=%d）"
            % (p_head, p_parse, p_align, p_prep)
        )
    for needle in ("align_was_newline = 1;", "str[0] == '\\n'", "str[0] = 'u';",
                   "return -EINVAL;"):
        if needle not in fn:
            fail("注入后自检失败，缺少：%s" % needle)

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(patched)

    print("[timing-align] 注入完成：%s" % path)
    print("[timing-align]   susfs_selinux_setprocattr: B 的首字节换行替换为 'u'，A/B 同路径")
    print("[timing-align]   前导换行写入仍返回 -EINVAL（stock 语义）")


if __name__ == "__main__":
    main()
