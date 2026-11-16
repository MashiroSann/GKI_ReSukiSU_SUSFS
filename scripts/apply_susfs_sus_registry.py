#!/usr/bin/env python3
"""把 KernelSU 注入的 sepolicy type / 规则登记进 SUSFS 的 sus 注册表。

背景
----
新版 SUSFS（kernel_patches 从 784ac9e6 起重写 selinux_hide）不再由 KernelSU
侧维护整份 backup policy，而是在内核侧直接接管
/sys/fs/selinux/{access,context,status} 与 setprocattr，并依赖两张注册表判断
“哪些 type / 规则是 KernelSU 注入的、需要对普通 app 隐藏”：

    susfs_add_sus_type(secctx, type_value)                    # add_type()
    susfs_add_sus_avd_allowed_by_type(s,t,c,orig_allowed)     # add_rule_raw()

官方 KernelSU 由 SUSFS 的 kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch
打上这两个点；但在本构建流程里，Next / SukiSU / BakaSU 变体走的是
“使用内置 SUSFS 支持”分支，不会应用该补丁 —— 结果是注册表永远为空：
即使 ksu_selinux_hide_running=1，selinux_hide 也什么都藏不住
（现象：Duck 的 Context validity oracle 返回 11、DirtySepolicy 相关边全部 Allowed）。

本脚本对 BakaSU 的 kernel/selinux/sepolicy.c 做幂等注入，补齐这两个打点。

用法
----
    python3 apply_susfs_sus_registry.py <path/to/KernelSU/kernel/selinux/sepolicy.c>

退出码
------
    0  已注入 / 已存在（幂等）
    2  目标文件或锚点不匹配（需要人工适配）
"""

import re
import sys

MARK_HEADER = "hmt-sus-registry:begin"
MARK_TYPE = "hmt-sus-registry:add-type"
MARK_RULE = "hmt-sus-registry:add-rule"

EXTERN_BLOCK = """#ifdef CONFIG_KSU_SUSFS
/* hmt-sus-registry:begin */
/*
 * BakaSU / Next / SukiSU 变体不会应用 SUSFS 的
 * kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch，这里手动补上
 * sus type / sus rule 的登记点；否则新版 SUSFS 的 selinux_hide 注册表
 * 永远为空，隐藏等于没开。
 */
extern int susfs_add_sus_type(const char *secctx, u32 type_value);
extern int susfs_add_sus_avd_allowed_by_type(u32 s_type, u32 t_type, u32 c_type, u32 orig_avd_allowed);
/* hmt-sus-registry:end */
#endif // #ifdef CONFIG_KSU_SUSFS
"""

TYPE_CALL = """    #ifdef CONFIG_KSU_SUSFS
    /* hmt-sus-registry:add-type */
    susfs_add_sus_type(type_name, type->value);
    #endif // #ifdef CONFIG_KSU_SUSFS
"""

RULE_CALL = """        #ifdef CONFIG_KSU_SUSFS
        /* hmt-sus-registry:add-rule */
        susfs_add_sus_avd_allowed_by_type(src->value, tgt->value, cls->value, node->datum.u.data);
        #endif // #ifdef CONFIG_KSU_SUSFS
"""


def fail(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(2)


def find_once(pattern, src, what):
    hits = list(re.finditer(pattern, src, re.MULTILINE))
    if len(hits) != 1:
        fail("%s: 锚点匹配 %d 次（需要恰好 1 次）: %s" % (what, len(hits), pattern))
    return hits[0]


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <sepolicy.c>\n" % sys.argv[0])
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
    except OSError as exc:
        fail("无法读取 %s: %s" % (path, exc))

    if "hmt-sus-registry:begin" in src and MARK_TYPE in src and MARK_RULE in src:
        print("[sus-registry] 已注入，跳过：%s" % path)
        return

    # 若上游/其它补丁已经打过同一个点（如 Official 变体应用了
    # 10_enable_susfs_for_ksu.patch），就不要重复注入。
    if "susfs_add_sus_type(" in src and "susfs_add_sus_type(type_name" in src:
        print("[sus-registry] 检测到已有 susfs_add_sus_type() 调用（上游补丁已应用），跳过：%s" % path)
        return

    # 1) 头部 extern 声明
    inc = find_once(r'^#include "ss/symtab\.h"[ \t]*$', src, "include 锚点")
    if MARK_HEADER in src:
        print("[sus-registry] 头部标记已存在，跳过 extern 注入")
    else:
        src = src[: inc.end()] + "\n" + EXTERN_BLOCK + src[inc.end():]

    # 2) add_type()：登记被注入的 type
    type_anchor = re.search(
        r"(?ms)^static bool add_type\(struct policydb \*db, const char \*type_name, bool attr\)\s*\{.*?"
        r"^    if \(symtab_insert\(&db->p_types, key, type\)\) \{\n"
        r"        pr_err\(\"add_type: insert symtab failed\.\\n\"\);\n"
        r"        return false;\n"
        r"    \}[ \t]*$",
        src,
    )
    if not type_anchor:
        fail("%s: 未找到 add_type() 的 symtab_insert 锚点" % path)
    if MARK_TYPE in src:
        print("[sus-registry] add_type 打点已存在，跳过")
    else:
        src = src[: type_anchor.end()] + "\n" + TYPE_CALL.rstrip("\n") + src[type_anchor.end():]

    # 3) add_rule_raw()：登记被注入规则的原始 allowed 位
    rule_anchor = re.search(
        r"(?m)^(?P<ind>[ \t]*)if \(invert\) \{\n"
        r"(?P=ind)    if \(perm\)\n"
        r"(?P=ind)        node->datum\.u\.data &= ~\(1U << \(perm->value - 1\)\);",
        src,
    )
    if not rule_anchor:
        fail("%s: 未找到 add_rule_raw() 的规则修改锚点" % path)
    if MARK_RULE in src:
        print("[sus-registry] add_rule_raw 打点已存在，跳过")
    else:
        src = src[: rule_anchor.start()] + RULE_CALL + src[rule_anchor.start():]

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(src)

    # 自检
    with open(path, "r", encoding="utf-8") as f:
        out = f.read()
    for needle in (MARK_HEADER, MARK_TYPE, MARK_RULE,
                   "susfs_add_sus_type(type_name, type->value);",
                   "susfs_add_sus_avd_allowed_by_type(src->value, tgt->value, cls->value, node->datum.u.data);"):
        if needle not in out:
            fail("注入后自检失败，缺少：%s" % needle)

    # 括号平衡自检（只对新增代码块做粗检）
    if out.count("/* hmt-sus-registry") != 4:
        fail("注入后标记数量异常：%d" % out.count("/* hmt-sus-registry"))

    print("[sus-registry] 注入完成：%s" % path)
    print("[sus-registry]   add_type      -> susfs_add_sus_type()")
    print("[sus-registry]   add_rule_raw  -> susfs_add_sus_avd_allowed_by_type()")


if __name__ == "__main__":
    main()
