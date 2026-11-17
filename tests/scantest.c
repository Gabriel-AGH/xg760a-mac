/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/* Development check: active scan through the station layer. */
#include <stdio.h>
#include <stdlib.h>

#include "compat.h"
#include "device.h"
#include "wlan.h"

static void on_device(void *ctx, int present, const uint8_t *addr)
{
	if (present)
		printf("clé présente, MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void on_link(void *ctx, int up)
{
	printf("liaison %s\n", up ? "établie" : "coupée");
}

static void on_packet(void *ctx, const uint8_t *eth, size_t len)
{
}

static const struct wlan_callbacks cbs = {
	.device = on_device,
	.link = on_link,
	.rx_packet = on_packet,
};

int main(int argc, char **argv)
{
	static struct wlan_bss list[WLAN_MAX_BSS];
	struct wlan *w;
	int rounds = argc > 2 ? atoi(argv[2]) : 1;

	xg_log_level = argc > 1 ? atoi(argv[1]) : XG_LOG_INFO;
	w = wlan_create(&cbs, NULL);
	if (wlan_wait_device(w, 15000)) {
		fprintf(stderr, "pas de clé\n");
		return 1;
	}
	for (int k = 0; k < rounds; k++) {
		int n = wlan_scan(w, list, WLAN_MAX_BSS);

		printf("--- balayage %d: %d réseaux\n", k + 1, n);
		for (int i = 0; i < n; i++) {
			int usable;
			const char *sec = wlan_bss_security(&list[i], &usable);

			printf("%-32.*s %02x:%02x:%02x:%02x:%02x:%02x canal %2d signal %3d %%  %s%s%s\n",
			       list[i].ssid_len ? list[i].ssid_len : 8,
			       list[i].ssid_len ? (const char *)list[i].ssid :
						  "(masque)",
			       list[i].bssid[0], list[i].bssid[1],
			       list[i].bssid[2], list[i].bssid[3],
			       list[i].bssid[4], list[i].bssid[5],
			       list[i].channel, list[i].signal, sec,
			       usable ? "" : " [non pris en charge]",
			       list[i].has_ht ? "  (n)" : "");
		}
	}
	wlan_destroy(w);
	return 0;
}
