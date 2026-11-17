/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * A few lines of IPv4 (DHCP client, ARP, ICMP echo) to prove that the link
 * carries traffic without creating a system network interface, hence
 * without administrator rights. Only used by "xg760a test".
 */
#ifndef XG_MINISTACK_H
#define XG_MINISTACK_H

#include <stddef.h>
#include <stdint.h>

struct wlan;
struct ministack;

struct ministack *ministack_new(const uint8_t mac[6]);
void ministack_free(struct ministack *m);
void ministack_attach(struct ministack *m, struct wlan *w);

/* to be called for every Ethernet frame received from the network */
void ministack_rx(struct ministack *m, const uint8_t *eth, size_t len);

/*
 * Runs the whole check and prints its progress on stdout: address by
 * DHCP, ARP of the router, pings of the router and of an Internet host,
 * then a short load test. Returns 0 if the essential steps passed.
 */
int ministack_run(struct ministack *m);

#endif
