// SPDX-License-Identifier: GPL-3.0-or-later
//
// hide_memory_traces (Zygisk module)
//
// 目的：把本进程里「匿名 + 可执行」的 VMA 改名成 ART 代码缓存的名字。
//
// 只改“名字”，不改权限、不改内容、不改 VMA 数量。
// 因此对进程行为零影响，但基于“匿名可执行段”的启发式检测会把它们
// 当成 ART 自己的 jit / data code cache 而跳过。
//
// 覆盖对象：
//   - Zygisk / LSPosed 注入器在进程内匿名映射的 ELF
//   - 应用自己的 native payload（常见命名 [anon:.bss] 且 r-x，属于异常组合）
//   - 任何 dev=00:00、inode=0、无路径或 [anon:*] 的可执行段
//
// 不碰：file-backed 映射、[vdso]/[vvar]/[stack]、已经叫 ART 缓存名的段。

#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "zygisk.hpp"

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

namespace {

constexpr size_t kMiB = 1u << 20;
constexpr size_t k64KiB = 1u << 16;
constexpr size_t kMaxNameLen = 64;

bool contains_any(const char *haystack, const char *const *needles, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (strstr(haystack, needles[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

// 已经是 ART 代码缓存名就不再处理，避免重复改名与覆盖 ART 自己的命名。
bool already_art_cache(const char *path) {
    static const char *const kNames[] = {
            "dalvik-jit-code-cache",
            "dalvik-data-code-cache",
            "dalvik-zygote-jit-code-cache",
            "dalvik-zygote-data-code-cache",
            "jit-code-cache",
            "jit-cache",
            "jit-zygote-cache",
            "zygote-jit-code-cache",
            "data-code-cache",
            "zygote-data-code-cache",
    };
    return contains_any(path, kNames, sizeof(kNames) / sizeof(kNames[0]));
}

// 名字要与大小档位匹配，避免“4 KB 的 jit-code-cache”这种不自然组合。
const char *pick_name(size_t bytes) {
    if (bytes >= kMiB) {
        return "dalvik-jit-code-cache";
    }
    if (bytes >= k64KiB) {
        return "jit-code-cache";
    }
    return "dalvik-data-code-cache";
}

void rename_pass() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return;
    }

    char *line = nullptr;
    size_t cap = 0;
    ssize_t len = 0;

    while ((len = getline(&line, &cap, fp)) > 0) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        unsigned long inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        int path_off = 0;

        int parsed = sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                            &start, &end, perms, &offset, dev, &inode, &path_off);
        if (parsed < 6) {
            continue;
        }
        if (perms[2] != 'x') {
            continue;                       /* 只看可执行段 */
        }
        if (strcmp(dev, "00:00") != 0) {
            continue;                       /* 只看匿名段 */
        }
        if (inode != 0) {
            continue;
        }

        const char *path = "";
        if (path_off > 0 && path_off < len) {
            path = line + path_off;
            /* 去掉行尾换行，strstr 比较更干净 */
            char *nl = strchr(const_cast<char *>(path), '\n');
            if (nl != nullptr) {
                *nl = '\0';
            }
        }

        if (path[0] == '/') {
            continue;                       /* file-backed */
        }
        if (path[0] == '[' && strncmp(path, "[anon", 5) != 0) {
            continue;                       /* [vdso] / [vvar] / [stack] 等 */
        }
        if (already_art_cache(path)) {
            continue;
        }

        size_t bytes = end > start ? static_cast<size_t>(end - start) : 0;
        if (bytes == 0) {
            continue;
        }

        const char *name = pick_name(bytes);
        if (strlen(name) > kMaxNameLen) {
            continue;
        }

        /* 失败无所谓：可能刚好被 munmap，或内核不支持 ANON_VMA_NAME */
        prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
              static_cast<unsigned long>(start),
              static_cast<unsigned long>(bytes),
              static_cast<unsigned long>(reinterpret_cast<uintptr_t>(name)));
    }

    free(line);
    fclose(fp);
}

void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        /* 被信号打断就继续睡 */
    }
}

// 应用自己的 payload 通常在主线程启动后才映射，
// 所以名字要在前 30 秒内分几次补齐，之后线程退出。
void *worker(void *) {
    static const long kScheduleMs[] = {0, 60, 200, 500, 1200, 2500, 5000, 10000, 20000, 35000};
    long elapsed = 0;
    for (size_t i = 0; i < sizeof(kScheduleMs) / sizeof(kScheduleMs[0]); ++i) {
        long target = kScheduleMs[i];
        if (target > elapsed) {
            sleep_ms(target - elapsed);
        }
        elapsed = target;
        rename_pass();
    }
    return nullptr;
}

class HideMemoryTraces : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        (void) api;
        (void) env;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        (void) args;

        /* 先同步跑一遍，覆盖已有的 Zygisk / LSPosed 映射 */
        rename_pass();

        pthread_t thread;
        if (pthread_create(&thread, nullptr, worker, nullptr) == 0) {
            pthread_detach(thread);
        }
    }
};

}  // namespace

REGISTER_ZYGISK_MODULE(HideMemoryTraces)
