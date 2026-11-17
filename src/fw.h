/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/* ZD1211 firmware images, embedded in the binary at build time. */
#ifndef XG_FW_H
#define XG_FW_H

#include <stddef.h>
#include <stdint.h>

struct zd_fw {
	const uint8_t *data;
	size_t size;
};

/* postfix is "ub", "ur" or "uphr"; returns NULL if unknown */
const struct zd_fw *zd_fw_get(int is_zd1211b, const char *postfix);

#endif
