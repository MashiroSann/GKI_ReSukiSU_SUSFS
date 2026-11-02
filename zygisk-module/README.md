# hide_memory_traces（Zygisk 模块）

把进程内「匿名 + 可执行」的 VMA 改名为 ART 代码缓存的名字，让基于匿名可执行段的启发式检测把它们当作 ART 自己的代码缓存跳过。

## 它做什么

在 `postAppSpecialize` 里扫描 `/proc/self/maps`，对满足以下条件的 VMA：

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

之后在 0/60/200/500/1200/2500/5000/10000/20000/35000 ms 各补扫一次，覆盖应用启动后才加载的 payload，然后线程退出。

## 它不做什么

- 不改权限、不改内容、不改 VMA 数量
- 不碰 file-backed 映射（含 ART 自己的 `/memfd:jit-cache`）
- 不碰 `[vdso]` / `[vvar]` / `[stack]`
- 不 hook 任何函数

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

把 zip 放进 KernelSU / Magisk 安装，重启。

## 验证

```bash
pid=$(pidof com.eltavine.duckdetector)
su -c "grep -E 'r-x' /proc/$pid/maps | grep anon"
```

应看到 `[anon:dalvik-jit-code-cache]` / `[anon:jit-code-cache]`，而不是空的或 `[anon:.bss]`。

## 兼容性

- **Zygisk API v4**：loader 只拒绝“比自己新”的版本，v4 在 v4/v5 上都能加载。
- 需要内核支持 `CONFIG_ANON_VMA_NAME`（Android 11+ GKI 默认开启，ART 自己就在用）。
- 32/64 位都编译；32 位应用走 `armeabi-v7a`。
