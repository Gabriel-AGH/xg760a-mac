/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * The background service ("xg760a daemon"): owns the stick and the system
 * network interface, remembers the known networks and answers the command
 * line tool over a local socket.
 */
#ifndef XG_SERVICE_H
#define XG_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include "wlan.h"

#define XG_SOCKET_PATH "/var/run/xg760a.sock"
#define XG_CONFIG_DIR "/Library/Application Support/XG760A"
#define XG_CONFIG_FILE XG_CONFIG_DIR "/reseaux.conf"
#define XG_VERSION "1.0"

struct service_options {
	const char *socket_path;
	/* NULL: nothing is read or saved (one-shot run) */
	const char *config_path;
	/* networks to start with when there is no configuration file */
	const struct wlan_network *initial;
	int n_initial;
};

/* Runs until SIGINT/SIGTERM. Returns a process exit code. */
int service_run(const struct service_options *opt);

/*
 * Client side: sends one request line to the service and returns its whole
 * answer (to be freed), or NULL with errno set (ENOENT / ECONNREFUSED when
 * the service is not running).
 */
char *service_request(const char *socket_path, const char *line);

/* hexadecimal helpers shared by both sides */
void hex_encode(const uint8_t *in, size_t len, char *out);
int hex_decode(const char *in, uint8_t *out, size_t max);

/* known-network file */
int config_load(const char *path, struct wlan_network *nets, int max,
		int *autoconnect);
int config_save(const char *path, const struct wlan_network *nets, int n,
		int autoconnect);

#endif
