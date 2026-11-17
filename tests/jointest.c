/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/* Development check: join a network and report what happens.
 * usage: jointest <log level> <ssid> [passphrase] [seconds] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "crypto.h"
#include "wlan.h"

static unsigned long rx_count;

static void on_device(void *ctx, int present, const uint8_t *addr)
{
}

static void on_link(void *ctx, int up)
{
	printf(">>> liaison %s\n", up ? "ETABLIE" : "coupée");
}

static void on_packet(void *ctx, const uint8_t *eth, size_t len)
{
	if (rx_count++ < 5)
		printf(">>> paquet reçu: %zu octets, type %02x%02x, de %02x:%02x:%02x:%02x:%02x:%02x\n",
		       len, eth[12], eth[13], eth[6], eth[7], eth[8], eth[9],
		       eth[10], eth[11]);
}

static const struct wlan_callbacks cbs = {
	.device = on_device,
	.link = on_link,
	.rx_packet = on_packet,
};

int main(int argc, char **argv)
{
	struct wlan_network net;
	struct wlan_status st;
	struct wlan *w;
	int seconds = argc > 4 ? atoi(argv[4]) : 15;

	if (argc < 3) {
		fprintf(stderr, "usage: jointest <niveau> <ssid> [phrase] [secondes]\n");
		return 2;
	}
	xg_log_level = atoi(argv[1]);
	memset(&net, 0, sizeof(net));
	net.ssid_len = (uint8_t)strlen(argv[2]);
	memcpy(net.ssid, argv[2], net.ssid_len);
	if (argc > 3 && argv[3][0]) {
		net.has_psk = 1;
		if (wpa_passphrase_to_pmk(argv[3], net.ssid, net.ssid_len,
					  net.pmk)) {
			fprintf(stderr, "phrase invalide (8 à 63 caractères)\n");
			return 2;
		}
	}

	w = wlan_create(&cbs, NULL);
	if (wlan_wait_device(w, 15000)) {
		fprintf(stderr, "pas de clé\n");
		return 1;
	}
	wlan_set_networks(w, &net, 1);
	for (int i = 0; i < seconds * 2; i++) {
		usleep(500 * 1000);
		wlan_get_status(w, &st);
		if (i % 4 == 3 || st.state == WLAN_CONNECTED)
			printf("[%2d.%d s] %s signal %d %% tx %g Mbit/s rx %g Mbit/s paquets rx %llu tx %llu reprises %llu pertes %llu %s%s\n",
			       i / 2, (i % 2) * 5, wlan_state_name(st.state),
			       st.signal, st.tx_rate / 2.0, st.rx_rate / 2.0,
			       st.rx_packets, st.tx_packets, st.tx_retried,
			       st.tx_failed, st.last_error[0] ? "| " : "",
			       st.last_error);
	}
	wlan_destroy(w);
	return 0;
}
