# hide_memory_traces（Zygisk 模块）v2

把进程里的「匿名 + 可执行」映射**换成真正的 memfd 映射**。

## 为什么 v1 的改名不够

v1 用 `prctl(PR_SET_VMA_ANON_NAME)` 只改显示名。内核里没有对应的 `struct file`，所以：

```
# 真实 memfd
$ stat /proc/PID/map_files/9b5bb000-9d5bb000
  19 544306 symbolic link          ← 有条目

# 改名后的匿名段
$ stat /proc/PID/map_files/721d79e000-721d79f000
  No such file or directory        ← 没有条目
```

检测器（hunter）就是靠这个抓到的，它二进制里的字符串写着：

```
Map Files Hiding Detected
: map_files probe skipped because the maps entry is unavailable
memfd fstat unavailable errno=
```

## v2 做什么

对每个「只读可执行 + 没有真文件 backing」的段：

1. 从 `/proc/self/mem` 读出原内容
2. `memfd_create("jit-cache")`，`ftruncate` 到总大小
3. 把各段内容按各自偏移写进去
4. 先在临时地址试一次 `mmap(PROT_READ|PROT_EXEC, MAP_SHARED)`，确认本域允许
5. 用 `MAP_SHARED|MAP_FIXED` 在原地址重映射

换完之后这个段是**真的** file-backed：

| 检查项 | 结果 |
|---|---|
| `maps` | `r-xs 00000000 00:01 <真 inode> /memfd:jit-cache (deleted)` |
| `map_files` | 有条目，可 `stat` / `fstat` |
| 页内容 | 逐字节相同 |
| `smaps` | `Anonymous: 0`、`Shared_Clean` |
| inode 数量 | 一个进程一个 memfd，只有 1 个 jit-cache inode |

## 安全约束

- 只处理**只读可执行**段（`r-x`），绝不碰任何可写段
- 单段 > 4 MB、单进程总量 > 8 MB、段数 > 32 一律跳过
- 换载前先试映射；失败就**整体放弃**，原映射不动
- `MAP_FIXED` 失败时内核不会拆掉原映射
- 跳过 `usap*` / `*zygote*` 进程
- `postAppSpecialize` 里只 `pthread_create`，不做同步工作

## 开关（默认不动手）

```bash
# 只探测（默认）：什么都不改，只在 debug 打开时打日志
adb shell su -c 'setprop persist.sys.hmt.debug 1'

# 真正执行换载
adb shell su -c 'setprop persist.sys.hmt.convert 1'

# 全部关掉
adb shell su -c 'setprop persist.sys.hmt.convert 0; setprop persist.sys.hmt.debug 0'
```

看日志：

```bash
adb logcat -s hmt
```

会看到这几类行：

```
probe exec memfd ok, regions=N     ← 本域允许对 memfd 做 PROT_EXEC
probe mmap(PROT_EXEC) denied: 13   ← 被 SELinux/内核拒绝，整体放弃
converted 3/3                      ← 实际换载数量
```

## 时序

`400 / 1200 / 3000 / 8000 / 20000 / 40000 ms` 各扫一次，换到就停。

## 已知风险

1. **`MAP_FIXED` 有窗口期**：替换瞬间 PTE 短暂失效，若此刻正好有线程在那段代码上执行会崩。这些段都是只读的静态代码，概率低但不为零。
2. **内存占用**：内容会进 page cache，每进程约 1 MB。
3. **SELinux**：如果 app 域不允许对 memfd 做 `PROT_EXEC`，试映射会失败，模块自动放弃，不会破坏原有映射。

## 构建

`.github/workflows/build-zygisk-module.yml`，NDK r27c，arm64-v8a + armeabi-v7a。
