/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Smallest possible check that the stick can be reached from user space:
 * opens it, reads the MAC address through the boot-code interface and lists
 * the endpoints. Changes nothing on the device.
 */
#include <stdio.h>

#include "compat.h"
#include "usbdev.h"

int main(void)
{
	static const uint16_t ids[][2] = { { 0x079b, 0x004a } };
	struct usbdev *d;
	uint8_t mac[6];
	int r;

	xg_log_level = XG_LOG_DBG;
	r = usbdev_open(&d, ids, 1);
	if (r) {
		fprintf(stderr, "usbdev_open: %d\n", r);
		return 1;
	}
	printf("ouvert: %04x:%04x bcdDevice %04x %s\n", usbdev_vid(d),
	       usbdev_pid(d), usbdev_bcd(d),
	       usbdev_is_high_speed(d) ? "high-speed" : "full-speed");

	/* USB_REQ_FIRMWARE_READ_DATA (0x32), E2P_MAC_ADDR_P1 = 0xf81b */
	r = usbdev_control(d, 0xc0, 0x32, 0xf800 + 0x17 + 0x04, 0, mac, 6, 5000);
	printf("lecture MAC: r=%d  %02x:%02x:%02x:%02x:%02x:%02x\n", r, mac[0],
	       mac[1], mac[2], mac[3], mac[4], mac[5]);

	r = usbdev_configure(d);
	printf("configure: r=%d\n", r);
	for (int ep = 1; ep < 16; ep++) {
		if (usbdev_ep_type(d, ep, 1) >= 0)
			printf("  EP%d IN  type %d mps %d\n", ep,
			       usbdev_ep_type(d, ep, 1),
			       usbdev_ep_max_packet(d, ep, 1));
		if (usbdev_ep_type(d, ep, 0) >= 0)
			printf("  EP%d OUT type %d mps %d\n", ep,
			       usbdev_ep_type(d, ep, 0),
			       usbdev_ep_max_packet(d, ep, 0));
	}
	usbdev_close(d);
	return 0;
}
