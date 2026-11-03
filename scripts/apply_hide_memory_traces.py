#!/usr/bin/env python3
"""hide_memory_traces —— 内核侧“内存观测视图”补丁（GKI 5.10 / ACK）

作用范围：只改 procfs 的**输出视图**，不改内存内容、不改 VMA 结构、
不动任何计数器（VmSize / statm / stat / smaps_rollup 全部保持真实）。

四块改动：
  A) 匿名 + 可执行 + 普通 anon 的 VMA：在 maps / smaps 里伪装成
     已删除的 memfd（/memfd:jit-cache (deleted)，dev 00:01，inode 非 0）。
     这是唯一能同时绕过“inode==0 判定”和“名字黑名单判定”的形态，
     因为 Android 13 的真实 ART jit cache 就是 memfd 长这样。
  B) pagemap：受保护代码页宣告为文件页（PM_FILE）。
  C) smaps：脏页记账迁移成 clean；伪 memfd 的 Anonymous 归零。
  D) smaps：伪 memfd 不再打印 Name:，避免和 maps 冲突。

判定条件（幂等，正常系统零副作用）：
  - A: vm_file == NULL && vm_ops == NULL && VM_EXEC &&
       非 VM_SPECIAL / 非栈 / 非 [heap]
  - B/C/D: 文件映射 + 可执行 + 只读挂载（/apex、/system、/vendor…），
           或 A 命中的 VMA

用法：
  python3 apply_hide_memory_traces.py <kernel_tree> [--check]

退出码：
  0 成功（或已打过，跳过）
  1 锚点缺失 / 结构与预期不符
"""

import sys
import os

MARK_BEGIN = "/* --- hide_memory_traces:begin --- */"
MARK_END = "/* --- hide_memory_traces:end --- */"

# 已经打过补丁的判定（只用 core 一段的标记）
CORE_BEGIN = "/* --- hmt:core:begin --- */"
CORE_END = "/* --- hmt:core:end --- */"
SMAP_BEGIN = "/* --- hmt:smap:begin --- */"
SMAP_END = "/* --- hmt:smap:end --- */"
MAPS_BEGIN = "/* --- hmt:maps:begin --- */"
MAPS_END = "/* --- hmt:maps:end --- */"

# ---------------------------------------------------------------- 核心谓词
# 放在 show_vma_header_prefix() 之前：它比 show_map_vma() 更早，
# 而这段又不依赖 mem_size_stats。
CORE = f"""{CORE_BEGIN}
#include <linux/kdev_t.h>
#include <linux/mount.h>

/*
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

/*
 * 匿名 + 可执行 + 普通 anon 段。
 *
 * 这些段没有 vm_file，也没有 vm_ops（所以不是 vdso/vvar 之类特殊映射），
 * 也不该是栈或堆——它们就是运行时 mmap(PROT_EXEC) 出来的代码。
 *
 * 只改它们“看起来是什么”，不动一个字节的内容和权限。
 */
static bool hmt_fake_memfd(const struct vm_area_struct *vma)
{{
	if (vma->vm_file)
		return false;
	if (vma->vm_ops)
		return false;
	if (!(vma->vm_flags & VM_EXEC))
		return false;
	if (vma->vm_flags & (VM_SPECIAL | VM_GROWSDOWN | VM_GROWSUP))
		return false;
	if (!vma->vm_mm)
		return false;
	/* 主线程栈 */
	if (vma->vm_start <= vma->vm_mm->start_stack &&
	    vma->vm_end >= vma->vm_mm->start_stack)
		return false;
	/* brk 堆（正常情况下不可执行，这里只是兜底） */
	if (vma->vm_start <= vma->vm_mm->brk &&
	    vma->vm_end >= vma->vm_mm->start_brk)
		return false;
	return true;
}}

/*
 * 伪 inode：同一进程里同一地址恒定，跨进程对同一段继承下来的映射也一致，
 * 看起来就像一个真被 mmap 过的 memfd inode。
 */
static unsigned long hmt_fake_ino(const struct vm_area_struct *vma)
{{
	return 0x20000UL + ((vma->vm_start >> PAGE_SHIFT) & 0x3ffffUL);
}}

/* pagemap：宣告为文件页；比对型检测器依据该位整页跳过 */
static bool hmt_report_file(const struct vm_area_struct *vma)
{{
	return hmt_is_code_vma(vma) || hmt_fake_memfd(vma);
}}
{CORE_END}
"""

# ---------------------------------------------------------------- smaps 记账
# 必须放在 struct mem_size_stats 定义之后（即 show_smap() 之前）。
SMAP = f"""{SMAP_BEGIN}
/*
 * 伪 memfd 段：Anonymous 归零、dirty 迁移成 clean，
 * 与真实 /memfd:jit-cache 的 smaps 形态保持一致。
 */
static void hmt_fake_memfd_smap(struct mem_size_stats *mss)
{{
	if (mss->private_dirty) {{
		mss->private_clean += mss->private_dirty;
		mss->private_dirty  = 0;
	}}
	if (mss->shared_dirty) {{
		mss->shared_clean += mss->shared_dirty;
		mss->shared_dirty  = 0;
	}}
	mss->anonymous = 0;
}}

/*
 * smaps：把 Private_Dirty / Shared_Dirty 迁移到对应的 Clean 计数，
 * 并同步扣减 Anonymous。Rss 不变，因此不破坏任何求和校验。
 */
static void hmt_adjust_smap(struct vm_area_struct *vma,
			    struct mem_size_stats *mss)
{{
	unsigned long dirty;

	if (hmt_fake_memfd(vma)) {{
		hmt_fake_memfd_smap(mss);
		return;
	}}

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
{SMAP_END}
"""

# ---------------------------------------------------------------- maps 改写
MAPS_BRANCH = f"""{MAPS_BEGIN}
	if (hmt_fake_memfd(vma)) {{
		/*
		 * 伪装成已删除的 memfd：dev 00:01、inode 非 0、
		 * 路径与 Android 13 真实的 ART jit cache 完全同形。
		 * VM_MAYSHARE 只影响这一行的 'p'/'s' 字符，不改映射语义。
		 */
		show_vma_header_prefix(m, start, end, flags | VM_MAYSHARE, 0,
				       MKDEV(0, 1), hmt_fake_ino(vma));
		seq_pad(m, ' ');
		seq_puts(m, "/memfd:jit-cache (deleted)");
		seq_putc(m, '\\n');
		return;
	}}
{MAPS_END}
"""

ANCHOR_CORE = "static void show_vma_header_prefix(struct seq_file *m,"

ANCHOR_MAPS = (
    "\tstart = vma->vm_start;\n"
    "\tend = VMA_PAD_START(vma);\n"
    "\tshow_vma_header_prefix(m, start, end, flags, pgoff, dev, ino);"
)

ANCHOR_MAPS_PATCHED = (
    "\tstart = vma->vm_start;\n"
    "\tend = VMA_PAD_START(vma);\n"
    f"{MAPS_BRANCH}"
    "\tshow_vma_header_prefix(m, start, end, flags, pgoff, dev, ino);"
)

ANCHOR_HELPERS = "static int show_smap(struct seq_file *m, void *v)"

ANCHOR_SMAP = (
    "\tsmap_gather_stats(vma, &mss, 0);\n"
    "\n"
    "\tshow_map_vma(m, vma);"
)

ANCHOR_SMAP_PATCHED = (
    "\tsmap_gather_stats(vma, &mss, 0);\n"
    "\n"
    f"\t{SMAP_BEGIN}\n"
    "\thmt_adjust_smap(vma, &mss);\n"
    f"\t{SMAP_END}\n"
    "\n"
    "\tshow_map_vma(m, vma);"
)

# smaps 的 Name: 行：伪 memfd 不该打印（真 memfd 也没有这一行）
ANCHOR_NAME = (
    "\tshow_map_vma(m, vma);\n"
    "\tif (vma_get_anon_name(vma)) {"
)

ANCHOR_NAME_PATCHED = (
    "\tshow_map_vma(m, vma);\n"
    "\tif (!hmt_fake_memfd(vma) && vma_get_anon_name(vma)) {"
)

ANCHOR_PAGEMAP = (
    "\tif (page && !PageAnon(page))\n"
    "\t\tflags |= PM_FILE;"
)

ANCHOR_PAGEMAP_PATCHED = (
    "\tif (page && !PageAnon(page))\n"
    "\t\tflags |= PM_FILE;\n"
    "\t/* --- hide_memory_traces:begin --- */\n"
    "\tif (hmt_report_file(vma))\n"
    "\t\tflags |= PM_FILE;\n"
    "\t/* --- hide_memory_traces:end --- */"
)


def fail(msg):
    print(f"  [x] {msg}")
    sys.exit(1)


def replace_once(src, anchor, new, what):
    n = src.count(anchor)
    if n != 1:
        fail(f"anchor {what} found {n} time(s), expected 1")
    return src.replace(anchor, new, 1)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check_only = "--check" in sys.argv

    if len(args) != 1:
        fail("usage: apply_hide_memory_traces.py <kernel_tree> [--check]")

    root = args[0]
    path = os.path.join(root, "fs", "proc", "task_mmu.c")
    if not os.path.isfile(path):
        fail(f"not found: {path}")

    with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:
        src = f.read()

    if CORE_BEGIN in src:
        print("  [=] hide_memory_traces already applied, skipping")
        return 0

    # 1) 核心谓词（必须在 show_map_vma / show_smap 之前）
    src = replace_once(src, ANCHOR_CORE, CORE + "\n" + ANCHOR_CORE, "show_vma_header_prefix")

    # 2) maps：伪 memfd 行
    src = replace_once(src, ANCHOR_MAPS, ANCHOR_MAPS_PATCHED, "show_map_vma header")

    # 3) smaps 记账辅助（需要 struct mem_size_stats）
    src = replace_once(src, ANCHOR_HELPERS, SMAP + "\n" + ANCHOR_HELPERS, "show_smap definition")

    # 4) smaps 调用点
    src = replace_once(src, ANCHOR_SMAP, ANCHOR_SMAP_PATCHED, "smap_gather_stats/show_map_vma")

    # 5) smaps Name: 行
    src = replace_once(src, ANCHOR_NAME, ANCHOR_NAME_PATCHED, "smaps Name line")

    # 6) pagemap
    src = replace_once(src, ANCHOR_PAGEMAP, ANCHOR_PAGEMAP_PATCHED, "pagemap PM_FILE")

    for marker, expect in ((CORE_BEGIN, 1), (CORE_END, 1),
                           (SMAP_BEGIN, 2), (SMAP_END, 2),
                           (MAPS_BEGIN, 1), (MAPS_END, 1)):
        if src.count(marker) != expect:
            fail(f"internal error: marker {marker} count={src.count(marker)}, expected {expect}")

    if check_only:
        print("  [ ] check pass: anchors match, patch would apply cleanly")
        return 0

    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(src)

    print("  [+] fs/proc/task_mmu.c patched")
    print("      - maps  : anonymous exec presented as /memfd:jit-cache (deleted)")
    print("      - smaps : Anonymous zeroed for those VMAs, Name: suppressed")
    print("      - pagemap: protected code pages reported as file pages")
    print("      - smaps : dirty pages migrated to clean (Rss unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
