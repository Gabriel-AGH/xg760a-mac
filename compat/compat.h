/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Minimal Linux-kernel compatibility layer.
 *
 * It lets the chip and RF files of the Linux zd1211rw driver
 * (vendor/zd1211rw/) be compiled unmodified as a macOS user-space program.
 * Only what those files actually use is provided.
 */
#ifndef XG_COMPAT_H
#define XG_COMPAT_H

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* Every Intel Mac is little-endian; the build refuses anything else. */
#if !defined(__LITTLE_ENDIAN__)
#error "This driver assumes a little-endian host"
#endif
typedef u16 __le16;
typedef u32 __le32;
typedef u16 __be16;
#define cpu_to_le16(x) ((u16)(x))
#define le16_to_cpu(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define le32_to_cpu(x) ((u32)(x))

#define __nocast
#define __packed __attribute__((packed))
#define __user
#define __force

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(n) (1UL << (n))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)

#define ETH_ALEN 6
#define FCS_LEN 4

#define BUG_ON(cond) \
	do { \
		if (unlikely(cond)) { \
			fprintf(stderr, "BUG at %s:%d\n", __FILE__, __LINE__); \
			abort(); \
		} \
	} while (0)
#define BUILD_BUG_ON(cond) _Static_assert(!(cond), "BUILD_BUG_ON: " #cond)

/* memory */
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define kmalloc(size, flags) malloc(size)
#define kzalloc(size, flags) calloc(1, (size))
#define kfree(p) free(p)

/* time */
#include <time.h>
#define msleep(ms) usleep((useconds_t)(ms) * 1000)
#define udelay(us) usleep((useconds_t)(us))
static inline long long ktime_get_seconds(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* mutex: recursive-free pthread mutex that remembers whether it is held */
struct mutex {
	pthread_mutex_t m;
	int locked;
};
static inline void mutex_init(struct mutex *mu)
{
	pthread_mutex_init(&mu->m, NULL);
	mu->locked = 0;
}
static inline void mutex_destroy(struct mutex *mu)
{
	pthread_mutex_destroy(&mu->m);
}
static inline void mutex_lock(struct mutex *mu)
{
	pthread_mutex_lock(&mu->m);
	mu->locked = 1;
}
static inline void mutex_unlock(struct mutex *mu)
{
	mu->locked = 0;
	pthread_mutex_unlock(&mu->m);
}
static inline int mutex_is_locked(struct mutex *mu)
{
	return mu->locked;
}

/* work items are not used in user space: everything runs on our own threads */
struct work_struct {
	int unused;
};
#define cancel_work_sync(w) ((void)(w))

/* logging (implemented in src/log.c) */
enum xg_log_level { XG_LOG_ERR = 0, XG_LOG_WARN, XG_LOG_INFO, XG_LOG_DBG, XG_LOG_TRACE };
extern int xg_log_level;
void xg_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void xg_hexdump(int level, const char *title, const void *data, size_t len);

struct device {
	int unused;
};
#define dev_err(dev, fmt, ...) do { (void)(dev); xg_log(XG_LOG_ERR, fmt, ##__VA_ARGS__); } while (0)
#define dev_warn(dev, fmt, ...) do { (void)(dev); xg_log(XG_LOG_WARN, fmt, ##__VA_ARGS__); } while (0)
#define dev_info(dev, fmt, ...) do { (void)(dev); xg_log(XG_LOG_INFO, fmt, ##__VA_ARGS__); } while (0)
#define dev_dbg(dev, fmt, ...) do { (void)(dev); xg_log(XG_LOG_DBG, fmt, ##__VA_ARGS__); } while (0)
#define dev_printk(level, dev, fmt, ...) do { (void)(dev); xg_log(XG_LOG_DBG, fmt, ##__VA_ARGS__); } while (0)
#define pr_debug(fmt, ...) xg_log(XG_LOG_DBG, fmt, ##__VA_ARGS__)
#define KERN_DEBUG ""
#define dump_stack() do { } while (0)
#define net_ratelimit() 1

/*
 * scnprintf: like snprintf but returns the number of characters really
 * written. Understands the one kernel-only format the vendor code uses
 * ("%3phD": three bytes as hex separated by dashes).
 */
int scnprintf(char *buf, size_t size, const char *fmt, ...);

/* the few mac80211 / nl80211 names the chip code refers to */
enum nl80211_iftype {
	NL80211_IFTYPE_UNSPECIFIED,
	NL80211_IFTYPE_ADHOC,
	NL80211_IFTYPE_STATION,
	NL80211_IFTYPE_AP,
	NL80211_IFTYPE_AP_VLAN,
	NL80211_IFTYPE_WDS,
	NL80211_IFTYPE_MONITOR,
	NL80211_IFTYPE_MESH_POINT,
};

struct wiphy {
	char fw_version[32];
	u8 perm_addr[ETH_ALEN];
};

struct ieee80211_hw {
	struct wiphy *wiphy;
	void *priv;
};

struct usb_interface {
	struct device dev;
};

#endif /* XG_COMPAT_H */
