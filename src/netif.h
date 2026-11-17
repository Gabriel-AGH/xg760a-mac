/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * The system side of the driver: a network interface macOS can use.
 *
 * No kernel extension: macOS ships a "fake Ethernet" interface type (feth)
 * that can be created in pairs. Whatever is sent on one end comes out of
 * the other. The system gets the first end (it carries the stick's MAC
 * address, DHCP, IPv6...), this program holds the second one and shuttles
 * the frames to and from the radio. Needs administrator rights.
 */
#ifndef XG_NETIF_H
#define XG_NETIF_H

#include <stddef.h>
#include <stdint.h>

struct netif;
struct wlan;

struct netif *netif_new(void);
/* must be called before the interface is first created */
void netif_set_wlan(struct netif *n, struct wlan *w);

/* All three only queue the work: they can be called from wlan callbacks. */
void netif_device(struct netif *n, int present, const uint8_t *mac);
void netif_link(struct netif *n, int up);
/* an Ethernet frame for the system */
void netif_rx(struct netif *n, const uint8_t *eth, size_t len);

/* Name of the system interface ("" while it does not exist) and its IPv4
 * address ("" if none yet). */
void netif_get_info(struct netif *n, char *name, size_t name_len, char *ipv4,
		    size_t ipv4_len);

/* Removes the interface and frees everything. */
void netif_free(struct netif *n);

#endif
