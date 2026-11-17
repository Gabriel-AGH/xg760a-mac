/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Client side of the control socket: what the command line tool and the
 * menu bar application need to talk to the service.
 */
#include "service.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

void hex_encode(const uint8_t *in, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";

	for (size_t i = 0; i < len; i++) {
		out[2 * i] = digits[in[i] >> 4];
		out[2 * i + 1] = digits[in[i] & 15];
	}
	out[2 * len] = 0;
}

int hex_decode(const char *in, uint8_t *out, size_t max)
{
	size_t n = strlen(in);

	if (n % 2 || n / 2 > max)
		return -1;
	for (size_t i = 0; i < n / 2; i++) {
		unsigned int v;
		char pair[3] = { in[2 * i], in[2 * i + 1], 0 };
		char *end;

		v = (unsigned int)strtoul(pair, &end, 16);
		if (*end)
			return -1;
		out[i] = (uint8_t)v;
	}
	return (int)(n / 2);
}

char *service_request(const char *socket_path, const char *line)
{
	struct sockaddr_un sa;
	struct timeval tv = { 30, 0 };
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int fd;
	int saved;

	if (strlen(socket_path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return NULL;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, socket_path, sizeof(sa.sun_path));
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		saved = errno;
		close(fd);
		errno = saved;
		return NULL;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (write(fd, line, strlen(line)) < 0 || write(fd, "\n", 1) < 0) {
		saved = errno;
		close(fd);
		errno = saved;
		return NULL;
	}
	for (;;) {
		ssize_t n;

		if (len + 1024 > cap) {
			char *nb = realloc(buf, cap + 4096);

			if (!nb)
				break;
			buf = nb;
			cap += 4096;
		}
		n = read(fd, buf + len, cap - len - 1);
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	close(fd);
	if (!buf) {
		errno = EIO;
		return NULL;
	}
	buf[len] = 0;
	return buf;
}
