#!/usr/bin/env python3
"""hide_memory_traces —— 内核侧“内存观测视图”补丁（GKI 5.10）

作用范围：只改 procfs 的**输出视图**，不改内存内容、不改 VMA 结构、
不动任何计数器（VmSize / statm / stat / smaps_rollup 全部保持真实）。

改了两处：
  1) fs/proc/task_mmu.c: pagemap_pte_range()  —— 把受保护代码页宣告为“文件页”
  2) fs/proc/task_mmu.c: show_smap()          —— 把脏页记账迁移成 clean

判定条件（幂等，正常系统零副作用）：
  文件映射 + 可执行 + 挂载为只读（/apex、/system、/vendor、/product、/odm）。
  没有被打补丁的页本来 dirty 就是 0，迁移不改变任何数值。

用法：
  python3 apply_hide_memory_traces.py <kernel_tree> [--check]

退出码：
  0 成功（或已打过，跳过）
  1 锚点缺失 / 结构与预期不符
"""

import sys
import os

BEGIN = "/* --- hide_memory_traces:begin --- */"
END = "/* --- hide_memory_traces:end --- */"

HELPERS = f"""{BEGIN}
#include <linux/mount.h>

/*
 * hide_memory_traces
 *
 * 本应始终与文件内容一致的代码页：文件映射 + 可执行 + 只读挂载。
 * 只读挂载覆盖 /apex、/system、/system_ext、/vendor、/product、/odm。
 */
static bool hmt_is_code_vma(const struct vm_area_struct *vma)
{{
	if (!vma->vm_file)
		return false;
	if (!(vma->vm_flags & VM_EXEC))
		return false;
	return !!(vma->vm_file->f_path.mnt->mnt_flags & MNT_READONLY);
}}

/* pagemap：宣告为文件页；比对型检测器依据该位整页跳过 */
static bool hmt_report_file(const struct vm_area_struct *vma)
{{
	return hmt_is_code_vma(vma);
}}

/*
 * smaps：把 Private_Dirty / Shared_Dirty 迁移到对应的 Clean 计数，
 * 并同步扣减 Anonymous。Rss 不变，因此不破坏任何求和校验。
 */
static void hmt_adjust_smap(struct vm_area_struct *vma,
			    struct mem_size_stats *mss)
{{
	unsigned long dirty;

	if (!hmt_is_code_vma(vma))
		return;

	dirty = mss->private_dirty + mss->shared_dirty;
	if (!dirty)
		return;

	mss->private_clean += mss->private_dirty;
	mss->shared_clean  += mss->shared_dirty;
	mss->private_dirty  = 0;
	mss->shared_dirty   = 0;
	if (mss->anonymous >= dirty)
		mss->anonymous -= dirty;
}}
{END}
"""

ANCHOR_HELPERS = "static int show_smap(struct seq_file *m, void *v)"

ANCHOR_SMAP = (
    "\tsmap_gather_stats(vma, &mss, 0);\n"
    "\n"
    "\tshow_map_vma(m, vma);"
)

ANCHOR_SMAP_PATCHED = (
    "\tsmap_gather_stats(vma, &mss, 0);\n"
    "\n"
    f"\t{BEGIN}\n"
    "\thmt_adjust_smap(vma, &mss);\n"
    f"\t{END}\n"
    "\n"
    "\tshow_map_vma(m, vma);"
)

ANCHOR_PAGEMAP = (
    "\tif (page && !PageAnon(page))\n"
    "\t\tflags |= PM_FILE;"
)

ANCHOR_PAGEMAP_PATCHED = (
    "\tif (page && !PageAnon(page))\n"
    "\t\tflags |= PM_FILE;\n"
    f"\t{BEGIN}\n"
    "\tif (hmt_report_file(vma))\n"
    "\t\tflags |= PM_FILE;\n"
    f"\t{END}"
)


def fail(msg):
    print(f"  [x] {msg}")
    sys.exit(1)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check_only = "--check" in sys.argv

    if len(args) != 1:
        fail("usage: apply_hide_memory_traces.py <kernel_tree> [--check]")

    root = args[0]
    path = os.path.join(root, "fs", "proc", "task_mmu.c")
    if not os.path.isfile(path):
        fail(f"not found: {path}")

    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        src = f.read()

    already = BEGIN in src
    if already:
        print("  [=] hide_memory_traces already applied, skipping")
        return 0

    # 1) helpers, inserted right before show_smap()
    if src.count(ANCHOR_HELPERS) != 1:
        fail(f"anchor show_smap() found {src.count(ANCHOR_HELPERS)} time(s), expected 1")
    src = src.replace(ANCHOR_HELPERS, HELPERS + "\n" + ANCHOR_HELPERS, 1)

    # 2) smaps adjustment, between gather and print
    if src.count(ANCHOR_SMAP) != 1:
        fail(f"anchor smap_gather_stats/show_map_vma found {src.count(ANCHOR_SMAP)} time(s), expected 1")
    src = src.replace(ANCHOR_SMAP, ANCHOR_SMAP_PATCHED, 1)

    # 3) pagemap: declare protected code pages as file pages
    if src.count(ANCHOR_PAGEMAP) != 1:
        fail(f"anchor pagemap PM_FILE found {src.count(ANCHOR_PAGEMAP)} time(s), expected 1")
    src = src.replace(ANCHOR_PAGEMAP, ANCHOR_PAGEMAP_PATCHED, 1)

    for marker in (BEGIN, END):
        if src.count(marker) < 2:
            fail(f"internal error: marker {marker} not inserted as expected")

    if check_only:
        print("  [ ] check pass: anchors match, patch would apply cleanly")
        return 0

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(src)

    print("  [+] fs/proc/task_mmu.c patched")
    print("      - pagemap: protected code pages reported as file pages")
    print("      - smaps  : dirty pages migrated to clean (Rss unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
