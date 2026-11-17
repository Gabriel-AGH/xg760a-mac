/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Development check of the chip's transmit reports: sends a few unicast
 * frames to an address nobody owns (never acknowledged) and a few to a real
 * access point (acknowledged), and shows what the chip reports.
 * usage: txreport <channel> <bssid of a real AP, aa:bb:cc:dd:ee:ff>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "device.h"
#include "ieee80211.h"

static int reports;

static void on_rx(void *ctx, const uint8_t *f, size_t len,
		  const struct xg_rx_info *info)
{
}

static void on_report(void *ctx, const uint8_t *dest, int rate, int retries,
		      int failed)
{
	reports++;
	printf("  rapport: vers %02x:%02x:%02x:%02x:%02x:%02x débit final %g Mbit/s, reprises %d, %s\n",
	       dest[0], dest[1], dest[2], dest[3], dest[4], dest[5],
	       rate >= 0 ? xg_rates[rate].ieee / 2.0 : -1.0, retries,
	       failed ? "ÉCHEC" : "réussi après reprise");
}

static void on_gone(void *ctx)
{
}

static const struct xg_dev_ops ops = { on_rx, on_report, on_gone };

static void send_probe(struct xg_dev *dev, const uint8_t *dest, int rate,
		       uint16_t seq)
{
	uint8_t f[64];
	uint8_t *p = f + 24;

	/* a directed probe request: harmless, and acknowledged by a real AP */
	put_le16(f, FC_PROBE_REQ);
	f[2] = f[3] = 0;
	memcpy(f + 4, dest, 6);
	memcpy(f + 10, xg_dev_addr(dev), 6);
	memcpy(f + 16, dest, 6);
	put_le16(f + 22, (uint16_t)(seq << 4));
	*p++ = IE_SSID;
	*p++ = 0;
	*p++ = IE_SUPP_RATES;
	*p++ = 4;
	*p++ = 0x02;
	*p++ = 0x04;
	*p++ = 0x0b;
	*p++ = 0x16;
	xg_dev_tx(dev, f, (size_t)(p - f), rate, 0);
}

int main(int argc, char **argv)
{
	static const uint8_t nobody[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	static const int rates[] = { XG_RATE_1M, XG_RATE_11M, 8, XG_RATE_54M };
	struct xg_dev *dev;
	uint8_t ap[6];
	unsigned int v[6];
	uint16_t seq = 100;
	int r;

	if (argc < 3 || sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2],
			       &v[3], &v[4], &v[5]) != 6) {
		fprintf(stderr, "usage: txreport <canal> <bssid>\n");
		return 2;
	}
	for (int i = 0; i < 6; i++)
		ap[i] = (uint8_t)v[i];
	xg_log_level = XG_LOG_WARN;
	r = xg_dev_open(&dev, &ops, NULL);
	if (!r)
		r = xg_dev_start(dev);
	if (r) {
		fprintf(stderr, "clé indisponible (%d)\n", r);
		return 1;
	}
	xg_dev_set_channel(dev, atoi(argv[1]));
	usleep(50 * 1000);

	for (unsigned int k = 0; k < ARRAY_SIZE(rates); k++) {
		struct xg_dev_stats st;

		printf("débit %g Mbit/s, 5 trames vers une adresse inexistante:\n",
		       xg_rates[rates[k]].ieee / 2.0);
		reports = 0;
		for (int i = 0; i < 5; i++) {
			send_probe(dev, nobody, rates[k], seq++);
			usleep(150 * 1000);
		}
		usleep(300 * 1000);
		printf("  => %d rapports\n", reports);

		printf("débit %g Mbit/s, 5 trames vers le point d'accès:\n",
		       xg_rates[rates[k]].ieee / 2.0);
		reports = 0;
		for (int i = 0; i < 5; i++) {
			send_probe(dev, ap, rates[k], seq++);
			usleep(150 * 1000);
		}
		usleep(300 * 1000);
		xg_dev_get_stats(dev, &st);
		printf("  => %d rapports (cumul: émises %llu, erreurs USB %llu)\n",
		       reports, st.tx_frames, st.tx_errors);
	}
	xg_dev_close(dev);
	return 0;
}
