/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Development check: loads the firmware, initialises the chip and its RF
 * transceiver, then listens passively on a few channels and prints the
 * frames it hears. Nothing is transmitted.
 */
#include <stdio.h>
#include <stdlib.h>

#include "compat.h"
#include "usbdev.h"
#include "zd_chip.h"
#include "zd_mac.h"
#include "zd_usb.h"

static int n_rx, n_bad;

static void on_rx(void *ctx, const u8 *buffer, unsigned int length)
{
	const struct rx_status *st;
	const u8 *f;
	unsigned int flen;

	(void)ctx;
	if (length < ZD_PLCP_HEADER_SIZE + 10 + FCS_LEN + sizeof(*st))
		return;
	st = (const struct rx_status *)(buffer + length - sizeof(*st));
	if (st->frame_status & ZD_RX_ERROR) {
		n_bad++;
		return;
	}
	n_rx++;
	f = buffer + ZD_PLCP_HEADER_SIZE;
	flen = length - ZD_PLCP_HEADER_SIZE - (unsigned int)sizeof(*st) - FCS_LEN;
	if ((f[0] & 0xfc) == 0x80 && flen > 38) { /* beacon */
		const u8 *ie = f + 36;
		char ssid[33] = "";

		if (ie[0] == 0 && ie[1] <= 32 && 38 + ie[1] <= flen)
			snprintf(ssid, sizeof(ssid), "%.*s", ie[1], ie + 2);
		printf("  balise %02x:%02x:%02x:%02x:%02x:%02x signal %3u \"%s\"\n",
		       f[10], f[11], f[12], f[13], f[14], f[15],
		       st->signal_strength, ssid);
	}
}

static void on_gone(void *ctx)
{
	(void)ctx;
	fprintf(stderr, "clé débranchée\n");
}

static const struct zd_usb_ops ops = { .rx = on_rx, .gone = on_gone };

int main(int argc, char **argv)
{
	static const uint16_t ids[][2] = { { 0x079b, 0x004a } };
	static struct zd_mac mac;
	struct zd_chip *chip = &mac.chip;
	struct usbdev *d;
	struct zd_mc_hash hash;
	u8 regdomain = 0;
	int r;

	xg_log_level = argc > 1 ? atoi(argv[1]) : XG_LOG_INFO;
	r = usbdev_open(&d, ids, 1);
	if (r) {
		fprintf(stderr, "usbdev_open: %d\n", r);
		return 1;
	}
	r = usbdev_reset_and_reopen(&d, ids, 1);
	if (r) {
		fprintf(stderr, "reset: %d\n", r);
		return 1;
	}

	mac.hw = &mac.hw_storage;
	mac.hw->wiphy = &mac.wiphy_storage;
	mac.hw->priv = &mac;
	zd_chip_init(chip, mac.hw, NULL);
	zd_usb_attach(&chip->usb, d, 0, &ops, &mac);

	r = zd_chip_read_mac_addr_fw(chip, mac.wiphy_storage.perm_addr);
	printf("adresse MAC: r=%d\n", r);

	r = zd_usb_bring_up(&chip->usb);
	printf("bring_up: r=%d\n", r);
	if (r)
		return 1;

	r = zd_chip_enable_int(chip);
	if (!r)
		r = zd_chip_init_hw(chip);
	printf("init_hw: r=%d\n", r);
	if (r)
		return 1;
	r = zd_read_regdomain(chip, &regdomain);
	printf("regdomain: r=%d %#x\n", r, regdomain);
	r = zd_set_encryption_type(chip, ENC_SNIFFER);
	printf("encryption type: r=%d\n", r);

	/* zd_op_start */
	r = zd_chip_set_basic_rates(chip, CR_RATES_80211B | CR_RATES_80211G);
	printf("basic rates: r=%d\n", r);
	r = zd_write_mac_addr(chip, mac.wiphy_storage.perm_addr);
	printf("write mac: r=%d\n", r);
	r = zd_iowrite32(chip, CR_RX_FILTER, STA_RX_FILTER);
	printf("rx filter: r=%d\n", r);
	zd_mc_clear(&hash);
	r = zd_chip_set_multicast_hash(chip, &hash);
	msleep(10);
	r = zd_chip_switch_radio_on(chip);
	printf("radio on: r=%d\n", r);
	r = zd_chip_enable_rxtx(chip);
	printf("rxtx: r=%d\n", r);
	r = zd_chip_enable_hwint(chip);
	printf("hwint: r=%d\n", r);

	for (int ch = 1; ch <= 13; ch += 5) {
		r = zd_chip_set_channel(chip, (u8)ch);
		printf("canal %d: r=%d\n", ch, r);
		n_rx = n_bad = 0;
		msleep(600);
		printf("  -> %d trames valides, %d en erreur\n", n_rx, n_bad);
	}

	zd_chip_disable_rxtx(chip);
	zd_chip_disable_hwint(chip);
	zd_chip_switch_radio_off(chip);
	zd_chip_control_leds(chip, ZD_LED_OFF);
	zd_chip_disable_int(chip);
	usbdev_close(d);
	return 0;
}
