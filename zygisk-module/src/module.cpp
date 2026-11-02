// SPDX-License-Identifier: GPL-3.0-or-later
//
// hide_memory_traces (Zygisk module)
//
// 目的：把本进程里「匿名 + 可执行」的 VMA 改名成 ART 代码缓存的名字。
//
// 只改“名字”，不改权限、不改内容、不改 VMA 数量。
//
// v1.1 设计约束（针对 zygote fork 竞态）：
//   1) postAppSpecialize 里**不做任何工作**，只创建一个线程。
//      specialty 窗口内多一毫秒，都可能放大系统的 fork 竞态，
//      所以这一步只允许 pthread_create。
//   2) 线程先睡 300ms，等进程 attach 完成、main 已经在跑，再开始扫描。
//   3) 跳过 usap* / *zygote* 等特殊进程，完全不碰。
//   4) /data/adb/hide_memory_traces/off 存在时完全不动作（现场开关，无需重启）。
//   5) 每轮最多改 128 个 VMA，避免极端进程把单轮耗时拉长。

#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/system_properties.h>
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
constexpr int kMaxRenamesPerPass = 128;

// 现场开关：属性为 1 或文件存在就完全不动手。
// 用属性是因为 app 进程读属性没有 SELinux 限制；
// /data/adb 是 0700，app 根本进不去，所以文件放 /data/local/tmp。
constexpr const char *kOffProp = "persist.sys.hmt.off";
constexpr const char *kOffFile = "/data/local/tmp/hide_memory_traces.off";

// 第一次扫描故意延后，避开 zygote 的 specialization 窗口。
constexpr long kFirstPassDelayMs = 300;

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

bool switch_is_off() {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(kOffProp, value) > 0 && value[0] == '1') {
        return true;
    }
    return access(kOffFile, F_OK) == 0;
}

// 读 /proc/self/cmdline 的第一个字段（进程名）。
bool read_process_name(char *buf, size_t cap) {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';
    return true;
}

// usap64 / usap32 / xxx_zygote / zygote / zygote64 / webview_zygote 一律不碰。
bool is_special_process(const char *name) {
    if (name[0] == '\0') {
        return false;
    }
    if (strncmp(name, "usap", 4) == 0) {
        return true;
    }
    if (strstr(name, "zygote") != nullptr) {
        return true;
    }
    return false;
}

void rename_pass() {
    if (switch_is_off()) {
        return;
    }

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return;
    }

    char *line = nullptr;
    size_t cap = 0;
    ssize_t len = 0;
    int renamed = 0;

    while ((len = getline(&line, &cap, fp)) > 0) {
        if (renamed >= kMaxRenamesPerPass) {
            break;                          /* 单轮有上限，绝不做无界循环 */
        }

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
        ++renamed;
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
// 所以名字要在前 40 秒内分几次补齐，之后线程退出。
void *worker(void *) {
    static const long kScheduleMs[] = {
            300, 700, 1200, 2000, 3500, 6000, 10000, 16000, 25000, 40000,
    };

    sleep_ms(kFirstPassDelayMs);

    char proc_name[128] = {0};
    if (!read_process_name(proc_name, sizeof(proc_name))) {
        return nullptr;
    }
    if (is_special_process(proc_name)) {
        return nullptr;                     /* usap / zygote 一律不碰 */
    }

    long elapsed = kFirstPassDelayMs;
    for (size_t i = 0; i < sizeof(kScheduleMs) / sizeof(kScheduleMs[0]); ++i) {
        long target = kScheduleMs[i];
        if (target > elapsed) {
            sleep_ms(target - elapsed);
            elapsed = target;
        }
        if (switch_is_off()) {
            return nullptr;                 /* 现场开关：随时能停 */
        }
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

        /*
         * 这里只创建线程，绝不做任何同步工作。
         * 该函数运行在 zygote specialization 窗口内，
         * 窗口里任何额外耗时都会放大系统的 fork 竞态。
         */
        pthread_t thread;
        if (pthread_create(&thread, nullptr, worker, nullptr) == 0) {
            pthread_detach(thread);
        }
    }
};

}  // namespace

REGISTER_ZYGISK_MODULE(HideMemoryTraces)
