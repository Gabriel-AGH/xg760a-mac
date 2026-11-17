/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * User-space access to a USB device on macOS through IOKit (IOUSBLib).
 * No kernel extension is involved: the device is simply opened by this
 * process, which works because no macOS driver claims the ZD1211.
 */
#ifndef XG_USBDEV_H
#define XG_USBDEV_H

#include <stddef.h>
#include <stdint.h>

struct usbdev;

enum {
	USBDEV_XFER_CONTROL = 0,
	USBDEV_XFER_ISOC = 1,
	USBDEV_XFER_BULK = 2,
	USBDEV_XFER_INT = 3,
};

/* status passed to read callbacks */
enum {
	USBDEV_OK = 0,
	USBDEV_ERR_IO = -1,	/* transient error, the reader keeps running */
	USBDEV_ERR_GONE = -2,	/* device unplugged or reader stopped */
};

typedef void (*usbdev_read_cb)(void *ctx, const uint8_t *data, size_t len,
			       int status);

/*
 * Looks for the first attached device matching one of the vid/pid pairs
 * (ids is a list of {vid, pid}, count entries). Returns 0 and the opened
 * device, -ENODEV if none is plugged in, another -errno on failure.
 */
int usbdev_open(struct usbdev **out, const uint16_t (*ids)[2], size_t count);
void usbdev_close(struct usbdev *d);

uint16_t usbdev_vid(const struct usbdev *d);
uint16_t usbdev_pid(const struct usbdev *d);
uint16_t usbdev_bcd(const struct usbdev *d);
int usbdev_is_high_speed(const struct usbdev *d);
int usbdev_is_gone(const struct usbdev *d);

/* Control transfer on endpoint 0. Returns bytes transferred or -errno. */
int usbdev_control(struct usbdev *d, uint8_t request_type, uint8_t request,
		   uint16_t value, uint16_t index, void *data, uint16_t len,
		   unsigned int timeout_ms);

/*
 * (Re)selects configuration 1 and opens interface 0 with all its pipes.
 * Must be called before any endpoint I/O.
 */
int usbdev_configure(struct usbdev *d);

/* Port reset + re-enumeration. The handle is unusable afterwards: close it
 * and call usbdev_open() again once the device has come back. */
int usbdev_reenumerate(struct usbdev *d);

/* Port reset, then waits for the device to come back and re-opens it.
 * *dp is replaced (NULL on failure). This puts the stick back into its
 * boot code whatever a previous run left behind. */
int usbdev_reset_and_reopen(struct usbdev **dp, const uint16_t (*ids)[2],
			    size_t count);

/* Endpoint properties (ep is the endpoint number, 1..15). -1 if absent. */
int usbdev_ep_type(const struct usbdev *d, int ep, int dir_in);
int usbdev_ep_max_packet(const struct usbdev *d, int ep, int dir_in);

/* Blocking write on an OUT endpoint (bulk or interrupt) with a timeout.
 * Returns 0 or -errno. Must not be called from a read callback. */
int usbdev_write(struct usbdev *d, int ep, const void *data, size_t len,
		 unsigned int timeout_ms);

/*
 * Starts a permanent reader on an IN endpoint: nbufs transfers of bufsize
 * bytes are kept queued; cb is called (on the USB event thread) for each
 * completed one, in order.
 */
int usbdev_start_reader(struct usbdev *d, int ep, size_t bufsize, int nbufs,
			usbdev_read_cb cb, void *ctx);
void usbdev_stop_readers(struct usbdev *d);

#endif /* XG_USBDEV_H */
