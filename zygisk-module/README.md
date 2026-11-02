# hide_memory_traces（Zygisk 模块）

把进程内「匿名 + 可执行」的 VMA 改名为 ART 代码缓存的名字，让基于匿名可执行段的启发式检测把它们当作 ART 自己的代码缓存跳过。

## 它做什么

启动后 **300ms**，扫描 `/proc/self/maps`，对满足以下条件的 VMA：

- 权限含 `x`
- `dev = 00:00`、`inode = 0`（匿名）
- 路径为空或 `[anon:*]`（不含 `[vdso]` / `[stack]`）
- 名字还不是 ART 代码缓存

调用：

```c
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, start, len, name);
```

名字按大小分档：

| 大小 | 名字 |
|---|---|
| ≥ 1 MB | `dalvik-jit-code-cache` |
| ≥ 64 KB | `jit-code-cache` |
| < 64 KB | `dalvik-data-code-cache` |

之后在 300/700/1200/2000/3500/6000/10000/16000/25000/40000 ms 各补扫一次，覆盖应用启动后才加载的 payload，然后线程退出。

## v1.1 的关键约束

`postAppSpecialize` **只做一件事：`pthread_create`**，不做任何同步工作。

原因：这个回调运行在 zygote 的 **specialization 窗口**内。窗口里每多一毫秒，都会放大系统 fork 请求的竞态（宿主 app 在此期间被杀 → 回包可能永远不来 → 全系统新进程启动排队）。所以第一次扫描故意延后到 300ms，等进程 attach 完成、`main` 已经在跑再动手。

同时：

- **跳过 `usap*` / `*zygote*` / `webview_zygote`**，一个 `prctl` 都不发
- 每轮最多改 **128 个 VMA**，单轮有硬上限，绝不做无界循环

## 现场开关（无需重启）

```bash
su -c 'mkdir -p /data/adb/hide_memory_traces && touch /data/adb/hide_memory_traces/off'
```

文件存在 → 所有扫描直接返回，模块等于没装。删掉文件即恢复。**只对之后启动的进程生效**，已在跑的进程需要重开。

## 它不做什么

- 不改权限、不改内容、不改 VMA 数量
- 不碰 file-backed 映射（含 ART 自己的 `/memfd:jit-cache`）
- 不碰 `[vdso]` / `[vvar]` / `[stack]`
- 不 hook 任何函数
- 不写 logcat（减少可观测面）

## 构建

CI：`.github/workflows/build-zygisk-module.yml`（NDK r27c，arm64-v8a + armeabi-v7a）。

本地：

```bash
cmake -S zygisk-module -B build \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 \
  -DOUTPUT_NAME=arm64-v8a
cmake --build build
```

## 安装

把 zip 放进 KernelSU / Magisk 安装，重启（或用 LSPosed 的"软重启"）。

## 验证

```bash
pid=$(pidof com.eltavine.duckdetector)
su -c "grep -E 'r-x' /proc/$pid/maps | grep anon"
```

应看到 `[anon:dalvik-jit-code-cache]` / `[anon:jit-code-cache]`，而不是空的或 `[anon:.bss]`。

## 兼容性

- **Zygisk API v4**：loader 只拒绝"比自己新"的版本，v4 在 v4/v5 上都能加载。
- 需要内核支持 `CONFIG_ANON_VMA_NAME`（Android 11+ GKI 默认开启，ART 自己就在用）。
- 32/64 位都编译；32 位应用走 `armeabi-v7a`。
