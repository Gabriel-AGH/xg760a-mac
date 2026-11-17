/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "compat.h"

int xg_log_level = XG_LOG_INFO;

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void xg_log(int level, const char *fmt, ...)
{
	static const char *const tags[] = { "ERREUR", "ALERTE", "info", "debug",
					    "trace" };
	struct timeval tv;
	struct tm tm;
	va_list ap;

	if (level > xg_log_level)
		return;
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	pthread_mutex_lock(&log_lock);
	fprintf(stderr, "%02d:%02d:%02d.%03d [%s] ", tm.tm_hour, tm.tm_min,
		tm.tm_sec, (int)(tv.tv_usec / 1000),
		tags[level < 0 ? 0 : (level > 4 ? 4 : level)]);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (fmt[0] && fmt[strlen(fmt) - 1] != '\n')
		fputc('\n', stderr);
	fflush(stderr);
	pthread_mutex_unlock(&log_lock);
}

void xg_hexdump(int level, const char *title, const void *data, size_t len)
{
	const unsigned char *p = data;
	char line[3 * 16 + 1];

	if (level > xg_log_level)
		return;
	xg_log(level, "%s (%zu octets)\n", title, len);
	for (size_t i = 0; i < len; i += 16) {
		size_t n = len - i < 16 ? len - i : 16;

		for (size_t j = 0; j < n; j++)
			snprintf(line + 3 * j, 4, "%02x ", p[i + j]);
		xg_log(level, "  %04zx: %s\n", i, line);
	}
}

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (size == 0)
		return 0;
	va_start(ap, fmt);
	if (strcmp(fmt, "%3phD") == 0) {
		/* kernel extension: 3 bytes as dash-separated hex */
		const unsigned char *p = va_arg(ap, const unsigned char *);

		n = snprintf(buf, size, "%02x-%02x-%02x", p[0], p[1], p[2]);
	} else {
		n = vsnprintf(buf, size, fmt, ap);
	}
	va_end(ap);
	if (n < 0)
		return 0;
	return (size_t)n >= size ? (int)size - 1 : n;
}
