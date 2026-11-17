/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/* ZD1211 USB-WLAN driver - macOS user-space port of the USB layer.
 *
 * The protocol definitions come from the Linux zd1211rw driver:
 * Copyright (C) 2005-2007 Ulrich Kunitz <kune@deine-taler.de>
 * Copyright (C) 2006-2007 Daniel Drake <dsd@gentoo.org>
 *
 * This file replaces zd1211rw's zd_usb.h: it keeps the interface that the
 * unmodified chip/RF files (vendor/zd1211rw/) expect, on top of IOKit.
 */

#ifndef _ZD_USB_H
#define _ZD_USB_H

#include "compat.h"
#include "usbdev.h"
#include "zd_def.h"

enum devicetype {
	DEVICE_ZD1211 = 0,
	DEVICE_ZD1211B = 1,
};

enum endpoints {
	EP_CTRL = 0,
	EP_DATA_OUT = 1,
	EP_DATA_IN = 2,
	EP_INT_IN = 3,
	EP_REGS_OUT = 4,
};

enum {
	USB_MAX_TRANSFER_SIZE = 4096, /* bytes */
	USB_MAX_RX_SIZE = 4800, /* bytes */
	USB_MAX_IOWRITE16_COUNT = 15,
	USB_MAX_IOWRITE32_COUNT = USB_MAX_IOWRITE16_COUNT / 2,
	USB_MAX_IOREAD16_COUNT = 15,
	USB_MAX_IOREAD32_COUNT = USB_MAX_IOREAD16_COUNT / 2,
	USB_MIN_RFWRITE_BIT_COUNT = 16,
	USB_MAX_RFWRITE_BIT_COUNT = 28,
	USB_MAX_EP_INT_BUFFER = 64,
	USB_ZD1211B_BCD_DEVICE = 0x4810,
};

enum control_requests {
	USB_REQ_WRITE_REGS = 0x21,
	USB_REQ_READ_REGS = 0x22,
	USB_REQ_WRITE_RF = 0x23,
	USB_REQ_PROG_FLASH = 0x24,
	USB_REQ_FIRMWARE_DOWNLOAD = 0x30,
	USB_REQ_FIRMWARE_CONFIRM = 0x31,
	USB_REQ_FIRMWARE_READ_DATA = 0x32,
};

struct usb_req_read_regs {
	__le16 id;
	__le16 addr[];
} __packed;

struct reg_data {
	__le16 addr;
	__le16 value;
} __packed;

struct usb_req_write_regs {
	__le16 id;
	struct reg_data reg_writes[];
} __packed;

enum {
	RF_IF_LE = 0x02,
	RF_CLK = 0x04,
	RF_DATA = 0x08,
};

struct usb_req_rfwrite {
	__le16 id;
	__le16 value;
	/* 1: 3683a */
	/* 2: other (default) */
	__le16 bits;
	/* RF2595: 24 */
	__le16 bit_values[];
	/* (ZD_CR203 & ~(RF_IF_LE | RF_CLK | RF_DATA)) | (bit ? RF_DATA : 0) */
} __packed;

/* USB interrupt */

enum usb_int_id {
	USB_INT_TYPE = 0x01,
	USB_INT_ID_REGS = 0x90,
	USB_INT_ID_RETRY_FAILED = 0xa0,
};

struct usb_int_header {
	u8 type; /* must always be 1 */
	u8 id;
} __packed;

struct usb_int_regs {
	struct usb_int_header hdr;
	struct reg_data regs[];
} __packed;

struct zd_ioreq16 {
	zd_addr_t addr;
	u16 value;
};

struct zd_ioreq32 {
	zd_addr_t addr;
	u32 value;
};

/* Callbacks from the USB event thread to the layer above. */
struct zd_usb_ops {
	/* one received frame: PLCP header + 802.11 frame + FCS + rx_status */
	void (*rx)(void *ctx, const u8 *buffer, unsigned int length);
	/* USB_INT_ID_RETRY_FAILED report (struct tx_status) */
	void (*tx_status)(void *ctx, const u8 *buffer, unsigned int length);
	/* the chip raised CR_INTERRUPT and wants its interrupts re-armed */
	void (*hw_interrupt)(void *ctx, u16 status);
	/* the device was unplugged */
	void (*gone)(void *ctx);
};

struct zd_usb {
	/* only there for the zd_chip_dev() macro of the chip code */
	struct usb_interface *intf;
	struct usb_interface intf_storage;

	struct usbdev *dev;
	const struct zd_usb_ops *ops;
	void *ops_ctx;

	/* rendez-vous between a register read and its interrupt reply */
	pthread_mutex_t intr_lock;
	pthread_cond_t intr_cond;
	int int_enabled;
	int read_regs_enabled;
	int read_regs_done;
	int read_regs_overridden;
	const struct usb_req_read_regs *read_regs_req;
	unsigned int read_regs_count;
	u8 read_regs_buffer[USB_MAX_EP_INT_BUFFER];
	int read_regs_length;

	/* reassembly of frames split over two USB transfers */
	u8 fragment[2 * USB_MAX_RX_SIZE];
	unsigned int fragment_length;
	unsigned int usb_packet_size;

	int rx_enabled;
	int tx_enabled;
	int cmd_error;
	u8 req_buf[64]; /* zd_usb_iowrite16v needs 62 bytes */
	u8 is_zd1211b : 1, initialized : 1, in_async : 1, readers_started : 1;
};

#define zd_usb_dev(usb) (&(usb)->intf->dev)

void zd_usb_init(struct zd_usb *usb, struct ieee80211_hw *hw,
		 struct usb_interface *intf);
void zd_usb_clear(struct zd_usb *usb);

/* Attaches an opened USB device and the callbacks of the upper layer. */
void zd_usb_attach(struct zd_usb *usb, struct usbdev *dev, int is_zd1211b,
		   const struct zd_usb_ops *ops, void *ops_ctx);

/* Uploads the firmware, selects the configuration and starts the readers. */
int zd_usb_bring_up(struct zd_usb *usb);

int zd_usb_scnprint_id(struct zd_usb *usb, char *buffer, size_t size);

void zd_tx_watchdog_enable(struct zd_usb *usb);
void zd_tx_watchdog_disable(struct zd_usb *usb);

int zd_usb_enable_int(struct zd_usb *usb);
void zd_usb_disable_int(struct zd_usb *usb);

int zd_usb_enable_rx(struct zd_usb *usb);
void zd_usb_disable_rx(struct zd_usb *usb);

void zd_usb_enable_tx(struct zd_usb *usb);
void zd_usb_disable_tx(struct zd_usb *usb);

/* Sends one frame (control set + 802.11 frame) and waits until the device
 * has taken it. Returns 0 or -errno. */
int zd_usb_tx(struct zd_usb *usb, const u8 *data, unsigned int length);

int zd_usb_ioread16v(struct zd_usb *usb, u16 *values,
		     const zd_addr_t *addresses, unsigned int count);

static inline int zd_usb_ioread16(struct zd_usb *usb, u16 *value,
				  const zd_addr_t addr)
{
	return zd_usb_ioread16v(usb, value, &addr, 1);
}

void zd_usb_iowrite16v_async_start(struct zd_usb *usb);
int zd_usb_iowrite16v_async_end(struct zd_usb *usb, unsigned int timeout);
int zd_usb_iowrite16v_async(struct zd_usb *usb, const struct zd_ioreq16 *ioreqs,
			    unsigned int count);
int zd_usb_iowrite16v(struct zd_usb *usb, const struct zd_ioreq16 *ioreqs,
		      unsigned int count);

int zd_usb_rfwrite(struct zd_usb *usb, u32 value, u8 bits);

int zd_usb_read_fw(struct zd_usb *usb, zd_addr_t addr, u8 *data, u16 len);

#endif /* _ZD_USB_H */
