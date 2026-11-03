// SPDX-License-Identifier: GPL-3.0-or-later
//
// hide_memory_traces (Zygisk module) v2
//
// 目的：把进程里的「匿名 + 可执行」映射换成**真正的 memfd 映射**。
//
// 为什么不再改名：
//   改名（PR_SET_VMA_ANON_NAME）只改显示名，内核里没有对应 struct file，
//   检测器只要 open("/proc/pid/map_files/<range>") 就会发现条目不存在
//   （hunter 的 "Map Files Hiding Detected" 就是这么抓到的）。
//
//   这里改的是**事实**：内容原样搬进一个 memfd(memfd:jit-cache)，
//   再用 MAP_SHARED|MAP_FIXED 在同一地址重新映射。换完之后：
//     - maps 显示 r-xs 00:01 <真 inode> /memfd:jit-cache (deleted)
//     - /proc/pid/map_files 有条目，可 fstat
//     - 页内容逐字节相同
//
// 一个进程只用一个 memfd，所有被换的段都是它的不同 offset 窗口，
//   所以进程里 jit-cache 的 inode 只有一个（和真实 ART 一致）。
//
// 安全约束：
//   - 只处理只读可执行段（r-x），绝不碰可写段
//   - 单个段 > 4 MB、总量 > 8 MB、段数 > 32 一律跳过
//   - 换载前先在临时地址试映射，失败就整体放弃，不动原映射
//   - MAP_FIXED 失败时内核不会拆掉原映射
//
// 开关：
//   persist.sys.hmt.convert = 1   才真正执行换载（默认 0，只看不换）
//   persist.sys.hmt.debug   = 1   向 logcat 打结果（默认 0）

#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include "zygisk.hpp"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace {

constexpr size_t kPage = 4096;
constexpr size_t kMaxRegion = 4u << 20;      /* 单段上限 4 MB */
constexpr size_t kMaxTotal = 8u << 20;       /* 单进程上限 8 MB */
constexpr int kMaxRegions = 32;
constexpr long kFirstPassDelayMs = 400;

struct Region {
    uintptr_t start;
    size_t size;
    off_t moff;          /* 该段在 memfd 里的偏移 */
};

bool prop_is(const char *name, char what) {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get(name, v) <= 0) {
        return false;
    }
    return v[0] == what;
}

bool debug_on() { return prop_is("persist.sys.hmt.debug", '1'); }
bool convert_on() { return prop_is("persist.sys.hmt.convert", '1'); }
bool probe_on() { return prop_is("persist.sys.hmt.probe", '1'); }

void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void logmsg(const char *fmt, ...) {
    if (!debug_on()) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, "hmt", fmt, ap);
    va_end(ap);
}

void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

/*
 * 读 /proc/self/cmdline 第一个字段。
 */
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

/*
 * 是否是「真文件映射」——直接看 map_files 有没有对应条目。
 * 这比解析名字可靠：内核补丁伪造的 memfd 名字也没有条目。
 */
bool has_map_file(uintptr_t start, uintptr_t end) {
    char path[80];
    snprintf(path, sizeof(path), "/proc/self/map_files/%lx-%lx",
             (unsigned long) start, (unsigned long) end);
    struct stat st;
    /* stat 走链接解析：有条目且指向真实文件才成功 */
    return stat(path, &st) == 0;
}

bool is_excluded_name(const char *path, size_t len) {
    static const char *const kNames[] = {
            "[vdso]", "[vvar]", "[vsyscall]", "[stack]", "[heap]",
    };
    for (const char *n : kNames) {
        size_t nl = strlen(n);
        if (len >= nl && strncmp(path, n, nl) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * 扫描候选段：r-x、无真文件 backing、不是栈/堆/vdso、尺寸合规。
 */
int collect(Region *out, int max) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return 0;
    }

    char *line = nullptr;
    size_t cap = 0;
    ssize_t len = 0;
    int n = 0;
    size_t total = 0;

    while ((len = getline(&line, &cap, fp)) > 0 && n < max) {
        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        int path_off = 0;

        int parsed = sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                            &start, &end, perms, &offset, dev, &inode, &path_off);
        if (parsed < 6) {
            continue;
        }

        /* 只要只读可执行：有 r 有 x，没有 w */
        if (perms[0] != 'r' || perms[2] != 'x' || perms[1] == 'w') {
            continue;
        }

        const char *path = "";
        size_t path_len = 0;
        if (path_off > 0 && (size_t) path_off < (size_t) len) {
            path = line + path_off;
            const char *nl = strchr(path, '\n');
            path_len = nl ? (size_t) (nl - path) : strlen(path);
        }

        if (is_excluded_name(path, path_len)) {
            continue;
        }

        /* 有真文件就直接跳过（ART 自己的 memfd jit cache 也是这种） */
        if (has_map_file(start, end)) {
            continue;
        }

        size_t size = end > start ? (size_t) (end - start) : 0;
        if (size == 0 || size > kMaxRegion) {
            continue;
        }
        if (total + size > kMaxTotal) {
            break;
        }

        out[n].start = start;
        out[n].size = size;
        out[n].moff = 0;
        total += size;
        ++n;
    }

    free(line);
    fclose(fp);
    return n;
}

int create_memfd() {
#ifdef SYS_memfd_create
    return (int) syscall(SYS_memfd_create, "jit-cache", MFD_CLOEXEC);
#else
    errno = ENOSYS;
    return -1;
#endif
}

/*
 * 把候选段搬进一个 memfd 并在原地址重映射。
 * 返回成功换载的段数。
 */
int convert_once() {
    Region regions[kMaxRegions];
    int n = collect(regions, kMaxRegions);
    if (n <= 0) {
        return 0;
    }

    size_t total = 0;
    for (int i = 0; i < n; ++i) {
        regions[i].size = (regions[i].size + kPage - 1) & ~(kPage - 1);
        total += regions[i].size;
    }

    int fd = create_memfd();
    if (fd < 0) {
        logmsg("memfd_create failed: %d", errno);
        return 0;
    }
    if (ftruncate(fd, (off_t) total) != 0) {
        logmsg("ftruncate failed: %d", errno);
        close(fd);
        return 0;
    }

    /* 先把内容全部写进 memfd */
    int mem = open("/proc/self/mem", O_RDONLY);
    if (mem < 0) {
        logmsg("open /proc/self/mem failed: %d", errno);
        close(fd);
        return 0;
    }

    char *buf = (char *) malloc(kMaxRegion);
    if (buf == nullptr) {
        close(mem);
        close(fd);
        return 0;
    }

    size_t off = 0;
    int ready = 0;
    for (int i = 0; i < n; ++i) {
        size_t size = regions[i].size;
        ssize_t got = pread(mem, buf, size, (off_t) regions[i].start);
        if (got <= 0) {
            logmsg("read %lx failed: %d", (unsigned long) regions[i].start, errno);
            regions[i].size = 0;
            continue;
        }
        if (pwrite(fd, buf, (size_t) got, (off_t) off) != got) {
            logmsg("write memfd failed: %d", errno);
            regions[i].size = 0;
            continue;
        }
        regions[i].moff = (off_t) off;
        off += size;
        ++ready;
    }
    free(buf);
    close(mem);

    if (ready == 0) {
        close(fd);
        return 0;
    }

    /* 先试一次，确认本域允许对 memfd 做 PROT_EXEC */
    void *probe = mmap(nullptr, kPage, PROT_READ | PROT_EXEC,
                       MAP_SHARED, fd, 0);
    if (probe == MAP_FAILED) {
        logmsg("probe mmap(PROT_EXEC) denied: %d", errno);
        close(fd);
        return 0;
    }
    munmap(probe, kPage);
    logmsg("probe exec memfd ok, regions=%d", ready);

    int done = 0;
    for (int i = 0; i < n; ++i) {
        if (regions[i].size == 0) {
            continue;
        }
        void *p = mmap((void *) regions[i].start, regions[i].size,
                       PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd,
                       regions[i].moff);
        if (p == MAP_FAILED) {
            logmsg("MAP_FIXED %lx failed: %d", (unsigned long) regions[i].start, errno);
            continue;
        }
        ++done;
    }

    close(fd);
    logmsg("converted %d/%d", done, ready);
    return done;
}

/*
 * 只探测：确认本域允许对 memfd 做 PROT_EXEC，并数一下有多少候选段。
 * 不改任何映射。
 */
void probe_once() {
    int fd = create_memfd();
    if (fd < 0) {
        logmsg("memfd_create failed errno=%d", errno);
        return;
    }
    if (ftruncate(fd, (off_t) kPage) != 0) {
        logmsg("ftruncate failed errno=%d", errno);
        close(fd);
        return;
    }
    void *p = mmap(nullptr, kPage, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        logmsg("probe denied errno=%d", errno);
    } else {
        logmsg("probe ok");
        munmap(p, kPage);
    }
    close(fd);

    Region regions[kMaxRegions];
    int n = collect(regions, kMaxRegions);
    size_t total = 0;
    for (int i = 0; i < n; ++i) {
        total += regions[i].size;
    }
    logmsg("candidates=%d total=%zu", n, total);
}

void *worker(void *) {
    sleep_ms(kFirstPassDelayMs);

    char name[128] = {0};
    if (!read_process_name(name, sizeof(name))) {
        return nullptr;
    }
    /* usap / zygote 不碰 */
    if (strncmp(name, "usap", 4) == 0 || strstr(name, "zygote") != nullptr) {
        return nullptr;
    }

    logmsg("start pid=%d name=%s convert=%d", (int) getpid(), name,
           convert_on() ? 1 : 0);

    static const long kScheduleMs[] = {
            kFirstPassDelayMs, 1200, 3000, 8000, 20000, 40000,
    };
    long elapsed = kFirstPassDelayMs;

    for (size_t i = 0; i < sizeof(kScheduleMs) / sizeof(kScheduleMs[0]); ++i) {
        long target = kScheduleMs[i];
        if (target > elapsed) {
            sleep_ms(target - elapsed);
            elapsed = target;
        }
        if (convert_on()) {
            int done = convert_once();
            if (done > 0) {
                break;                   /* 换完就收工 */
            }
        } else if (probe_on()) {
            probe_once();
            break;                       /* 探测只做一次 */
        }
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
        /* 这里只创建线程，不做任何同步工作 */
        pthread_t thread;
        if (pthread_create(&thread, nullptr, worker, nullptr) == 0) {
            pthread_detach(thread);
        }
    }
};

}  // namespace

REGISTER_ZYGISK_MODULE(HideMemoryTraces)
