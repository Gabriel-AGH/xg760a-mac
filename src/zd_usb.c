// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Gabriel-AGH
/* ZD1211 USB-WLAN driver - macOS user-space port of the USB layer.
 *
 * Derived from the Linux zd1211rw driver (zd_usb.c):
 * Copyright (C) 2005-2007 Ulrich Kunitz <kune@deine-taler.de>
 * Copyright (C) 2006-2007 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2006-2007 Michael Wu <flamingice@sourmilk.net>
 *
 * The protocol (firmware upload, register access through endpoints 4 and
 * 3, frame reassembly) is the one of the Linux driver. The plumbing is
 * different: IOKit instead of URBs, plain threads instead of work queues.
 */

#include <sys/time.h>

#include "fw.h"
#include "zd_chip.h"
#include "zd_mac.h"
#include "zd_usb.h"

/* Linux uses 50 ms; a user-space process can be scheduled out for longer. */
#define REG_IO_TIMEOUT_MS 500
#define TX_TIMEOUT_MS 2000

/* --- firmware ----------------------------------------------------------- */

enum upload_code_flags {
	REBOOT = 1,
};

/* Ensures that MAX_TRANSFER_SIZE is even. */
#define MAX_TRANSFER_SIZE (USB_MAX_TRANSFER_SIZE & ~1)

static int upload_code(struct usbdev *udev, const u8 *data, size_t size,
		       u16 code_offset, int flags)
{
	u8 *p;
	int r;

	p = malloc(MAX_TRANSFER_SIZE);
	if (!p)
		return -ENOMEM;

	size &= ~1;
	while (size > 0) {
		size_t transfer_size = size <= MAX_TRANSFER_SIZE ?
			size : MAX_TRANSFER_SIZE;

		memcpy(p, data, transfer_size);
		r = usbdev_control(udev, 0x40 /* out, vendor, device */,
				   USB_REQ_FIRMWARE_DOWNLOAD, code_offset, 0, p,
				   (u16)transfer_size, 1000);
		if (r < 0) {
			xg_log(XG_LOG_ERR,
			       "micrologiciel: envoi refusé par la clé (%d)\n", r);
			goto error;
		}
		transfer_size = r & ~1;
		if (transfer_size == 0) {
			r = -EIO;
			goto error;
		}

		size -= transfer_size;
		data += transfer_size;
		code_offset += transfer_size / sizeof(u16);
	}

	if (flags & REBOOT) {
		u8 ret;

		r = usbdev_control(udev, 0xc0 /* in, vendor, device */,
				   USB_REQ_FIRMWARE_CONFIRM, 0, 0, p, sizeof(ret),
				   5000);
		if (r != sizeof(ret)) {
			xg_log(XG_LOG_ERR,
			       "micrologiciel: pas de confirmation (%d)\n", r);
			if (r >= 0)
				r = -ENODEV;
			goto error;
		}
		ret = p[0];
		if (ret & 0x80) {
			xg_log(XG_LOG_ERR,
			       "micrologiciel: erreur interne de la clé (%#04x)\n",
			       (unsigned int)ret);
			r = -ENODEV;
			goto error;
		}
		xg_log(XG_LOG_DBG, "micrologiciel: confirmation %#04x\n",
		       (unsigned int)ret);
	}

	r = 0;
error:
	free(p);
	return r;
}

static u16 get_word(const void *data, u16 offset)
{
	const u8 *p = (const u8 *)data + 2 * (size_t)offset;

	return (u16)(p[0] | (p[1] << 8));
}

static int handle_version_mismatch(struct zd_usb *usb,
				   const struct zd_fw *ub_fw)
{
	const struct zd_fw *ur_fw = zd_fw_get(usb->is_zd1211b, "ur");
	int offset;
	int r;

	if (!ur_fw)
		return -ENOENT;
	r = upload_code(usb->dev, ur_fw->data, ur_fw->size, FW_START, REBOOT);
	if (r)
		return r;

	offset = (E2P_BOOT_CODE_OFFSET * sizeof(u16));
	return upload_code(usb->dev, ub_fw->data + offset, ub_fw->size - offset,
			   E2P_START + E2P_BOOT_CODE_OFFSET, REBOOT);
}

static int upload_firmware(struct zd_usb *usb)
{
	const struct zd_fw *ub_fw = zd_fw_get(usb->is_zd1211b, "ub");
	const struct zd_fw *uph_fw = zd_fw_get(usb->is_zd1211b, "uphr");
	u16 bcdDevice = usbdev_bcd(usb->dev);
	u16 fw_bcdDevice;
	int r;

	if (!ub_fw || !uph_fw)
		return -ENOENT;

	fw_bcdDevice = get_word(ub_fw->data, E2P_DATA_OFFSET);
	if (fw_bcdDevice != bcdDevice) {
		xg_log(XG_LOG_INFO,
		       "micrologiciel %#06x différent du code d'amorce de la clé %#06x: mise à niveau en mémoire\n",
		       fw_bcdDevice, bcdDevice);
		r = handle_version_mismatch(usb, ub_fw);
		if (r)
			return r;
	} else {
		xg_log(XG_LOG_DBG,
		       "micrologiciel: version %#06x identique à celle de la clé\n",
		       fw_bcdDevice);
	}

	r = upload_code(usb->dev, uph_fw->data, uph_fw->size, FW_START, REBOOT);
	if (r)
		xg_log(XG_LOG_ERR,
		       "micrologiciel: chargement du code principal impossible (%d)\n",
		       r);
	return r;
}

/* Read data from device address space using "firmware interface" which does
 * not require firmware to be loaded. */
int zd_usb_read_fw(struct zd_usb *usb, zd_addr_t addr, u8 *data, u16 len)
{
	int r;

	r = usbdev_control(usb->dev, 0xc0, USB_REQ_FIRMWARE_READ_DATA, addr, 0,
			   data, len, 5000);
	if (r < 0) {
		xg_log(XG_LOG_ERR,
		       "lecture par l'interface d'amorce impossible: %d\n", r);
		return r;
	}
	if (r != len) {
		xg_log(XG_LOG_ERR,
		       "lecture incomplete par l'interface d'amorce: %d/%d\n", r,
		       len);
		return -EIO;
	}
	return 0;
}

/* --- interrupt endpoint: register replies and tx reports ---------------- */

static bool check_read_regs(struct zd_usb *usb,
			    const struct usb_req_read_regs *req,
			    unsigned int count)
{
	const struct usb_int_regs *regs =
		(const struct usb_int_regs *)usb->read_regs_buffer;

	/* The created block size seems to be larger than expected.
	 * However results appear to be correct. */
	if (usb->read_regs_length <
	    (int)(sizeof(*regs) + count * sizeof(struct reg_data)))
		return false;
	if (usb->read_regs_length > (int)sizeof(usb->read_regs_buffer))
		return false;

	for (unsigned int i = 0; i < count; i++) {
		const struct reg_data *rd = &regs->regs[i];

		if (rd->addr != req->addr[i])
			return false;
	}
	return true;
}

/* called with intr_lock held */
static void regs_int_override(struct zd_usb *usb)
{
	if (usb->read_regs_enabled) {
		usb->read_regs_enabled = 0;
		usb->read_regs_overridden = 1;
		usb->read_regs_done = 1;
		pthread_cond_broadcast(&usb->intr_cond);
	}
}

static void int_cb(void *ctx, const uint8_t *data, size_t len, int status)
{
	struct zd_usb *usb = ctx;
	const struct usb_int_header *hdr;
	int hw_int = 0, report = 0;
	u16 hw_status = 0;

	if (status == USBDEV_ERR_GONE) {
		pthread_mutex_lock(&usb->intr_lock);
		regs_int_override(usb);
		pthread_mutex_unlock(&usb->intr_lock);
		if (usb->ops && usb->ops->gone)
			usb->ops->gone(usb->ops_ctx);
		return;
	}
	if (status != USBDEV_OK || len < sizeof(*hdr))
		return;
	hdr = (const struct usb_int_header *)data;
	if (hdr->type != USB_INT_TYPE)
		return;

	pthread_mutex_lock(&usb->intr_lock);
	switch (hdr->id) {
	case USB_INT_ID_REGS:
		if (len < 4)
			break;
		if ((u16)(data[2] | (data[3] << 8)) == (u16)CR_INTERRUPT) {
			/* hardware interrupt notification; it might have
			 * replaced the answer to a pending register read */
			hw_int = 1;
			if (len >= 6)
				hw_status = (u16)(data[4] | (data[5] << 8));
			regs_int_override(usb);
		} else if (usb->read_regs_enabled) {
			size_t n = len;

			usb->read_regs_length = (int)len;
			if (n > sizeof(usb->read_regs_buffer))
				n = sizeof(usb->read_regs_buffer);
			memcpy(usb->read_regs_buffer, data, n);

			/* Sometimes USB_INT_ID_REGS is not overridden, but
			 * comes after USB_INT_ID_RETRY_FAILED. Read-reg retry
			 * then gets this delayed USB_INT_ID_REGS, but leaves
			 * USB_INT_ID_REGS of retry unhandled. Next read-reg
			 * command then might catch this wrong USB_INT_ID_REGS.
			 * Fix by ignoring wrong reads. */
			if (check_read_regs(usb, usb->read_regs_req,
					    usb->read_regs_count)) {
				usb->read_regs_enabled = 0;
				usb->read_regs_overridden = 0;
				usb->read_regs_done = 1;
				pthread_cond_broadcast(&usb->intr_cond);
			}
		}
		break;
	case USB_INT_ID_RETRY_FAILED:
		/* USB_INT_ID_RETRY_FAILED triggered by a transmission can
		 * override a pending USB_INT_ID_REGS, causing a read
		 * command timeout. */
		regs_int_override(usb);
		report = 1;
		break;
	default:
		xg_log(XG_LOG_DBG, "interruption USB inconnue %#x\n", hdr->id);
		break;
	}
	pthread_mutex_unlock(&usb->intr_lock);

	if (hw_int && usb->ops && usb->ops->hw_interrupt)
		usb->ops->hw_interrupt(usb->ops_ctx, hw_status);
	if (report && usb->ops && usb->ops->tx_status)
		usb->ops->tx_status(usb->ops_ctx, data, (unsigned int)len);
}

/* --- bulk in: received frames ------------------------------------------- */

static void handle_rx_packet(struct zd_usb *usb, const u8 *buffer,
			     unsigned int length)
{
	const u8 *li;
	u16 tag;

	if (length < sizeof(struct rx_length_info))
		return; /* It's not a complete packet anyhow. */
	li = buffer + length - sizeof(struct rx_length_info);

	/* It might be that three frames are merged into a single USB
	 * transaction. We have to check for the length info tag. The
	 * length info might be unaligned. */
	tag = (u16)(li[6] | (li[7] << 8));
	if (tag == RX_LENGTH_INFO_TAG) {
		unsigned int l = 0, k, n;

		for (int i = 0;; i++) {
			k = (unsigned int)(li[2 * i] | (li[2 * i + 1] << 8));
			if (k == 0)
				return;
			n = l + k;
			if (n > length)
				return;
			usb->ops->rx(usb->ops_ctx, buffer + l, k);
			if (i >= 2)
				return;
			l = (n + 3) & ~3u;
		}
	} else {
		usb->ops->rx(usb->ops_ctx, buffer, length);
	}
}

static void rx_cb(void *ctx, const uint8_t *buffer, size_t len, int status)
{
	struct zd_usb *usb = ctx;
	unsigned int length = (unsigned int)len;

	if (status == USBDEV_ERR_GONE) {
		if (usb->ops && usb->ops->gone)
			usb->ops->gone(usb->ops_ctx);
		return;
	}
	if (status != USBDEV_OK || !usb->rx_enabled || !usb->ops || !usb->ops->rx)
		return;

	if (length % usb->usb_packet_size > usb->usb_packet_size - 4) {
		/* First fragment. If there is an old one, we don't care. */
		if (length <= sizeof(usb->fragment)) {
			memcpy(usb->fragment, buffer, length);
			usb->fragment_length = length;
		}
		return;
	}

	if (usb->fragment_length > 0) {
		/* We are on a second fragment, we believe */
		if (length + usb->fragment_length <= sizeof(usb->fragment)) {
			memcpy(usb->fragment + usb->fragment_length, buffer,
			       length);
			handle_rx_packet(usb, usb->fragment,
					 usb->fragment_length + length);
		}
		usb->fragment_length = 0;
	} else {
		handle_rx_packet(usb, buffer, length);
	}
}

/* --- life cycle --------------------------------------------------------- */

void zd_usb_init(struct zd_usb *usb, struct ieee80211_hw *hw,
		 struct usb_interface *intf)
{
	(void)hw;
	(void)intf;
	memset(usb, 0, sizeof(*usb));
	usb->intf = &usb->intf_storage;
	pthread_mutex_init(&usb->intr_lock, NULL);
	pthread_cond_init(&usb->intr_cond, NULL);
}

void zd_usb_clear(struct zd_usb *usb)
{
	pthread_mutex_destroy(&usb->intr_lock);
	pthread_cond_destroy(&usb->intr_cond);
}

void zd_usb_attach(struct zd_usb *usb, struct usbdev *dev, int is_zd1211b,
		   const struct zd_usb_ops *ops, void *ops_ctx)
{
	usb->dev = dev;
	usb->is_zd1211b = is_zd1211b ? 1 : 0;
	usb->ops = ops;
	usb->ops_ctx = ops_ctx;
}

int zd_usb_bring_up(struct zd_usb *usb)
{
	int r;

	r = upload_firmware(usb);
	if (r)
		return r;

	/* same as usb_reset_configuration() in the Linux driver: tells the
	 * freshly started firmware that it is configured */
	r = usbdev_configure(usb->dev);
	if (r) {
		xg_log(XG_LOG_ERR,
		       "USB: sélection de la configuration impossible (%d)\n", r);
		return r;
	}
	if (usbdev_ep_type(usb->dev, EP_DATA_OUT, 0) < 0 ||
	    usbdev_ep_type(usb->dev, EP_DATA_IN, 1) < 0 ||
	    usbdev_ep_type(usb->dev, EP_INT_IN, 1) < 0 ||
	    usbdev_ep_type(usb->dev, EP_REGS_OUT, 0) < 0) {
		xg_log(XG_LOG_ERR, "USB: points de terminaison inattendus\n");
		return -ENODEV;
	}
	usb->usb_packet_size = usbdev_is_high_speed(usb->dev) ? 512 : 64;
	usb->fragment_length = 0;

	r = usbdev_start_reader(usb->dev, EP_INT_IN, USB_MAX_EP_INT_BUFFER, 4,
				int_cb, usb);
	if (r)
		return r;
	r = usbdev_start_reader(usb->dev, EP_DATA_IN, USB_MAX_RX_SIZE, 8, rx_cb,
				usb);
	if (r)
		return r;
	usb->readers_started = 1;
	usb->initialized = 1;
	return 0;
}

int zd_usb_scnprint_id(struct zd_usb *usb, char *buffer, size_t size)
{
	return scnprintf(buffer, size, "%04hx:%04hx v%04hx %s",
			 usbdev_vid(usb->dev), usbdev_pid(usb->dev),
			 usbdev_bcd(usb->dev),
			 usbdev_is_high_speed(usb->dev) ? "high" : "full");
}

/* The readers run permanently; these switches only gate what is done with
 * the data, which keeps the calling sequence of the chip code unchanged. */
int zd_usb_enable_int(struct zd_usb *usb)
{
	usb->int_enabled = 1;
	return usb->readers_started ? 0 : -ENODEV;
}

void zd_usb_disable_int(struct zd_usb *usb)
{
	usb->int_enabled = 0;
}

int zd_usb_enable_rx(struct zd_usb *usb)
{
	usb->fragment_length = 0;
	usb->rx_enabled = 1;
	return usb->readers_started ? 0 : -ENODEV;
}

void zd_usb_disable_rx(struct zd_usb *usb)
{
	usb->rx_enabled = 0;
}

void zd_usb_enable_tx(struct zd_usb *usb)
{
	usb->tx_enabled = 1;
}

void zd_usb_disable_tx(struct zd_usb *usb)
{
	usb->tx_enabled = 0;
}

void zd_tx_watchdog_enable(struct zd_usb *usb)
{
	(void)usb;
}

void zd_tx_watchdog_disable(struct zd_usb *usb)
{
	(void)usb;
}

int zd_usb_tx(struct zd_usb *usb, const u8 *data, unsigned int length)
{
	if (!usb->tx_enabled)
		return -ENOENT;
	return usbdev_write(usb->dev, EP_DATA_OUT, data, length, TX_TIMEOUT_MS);
}

/* --- register access ---------------------------------------------------- */

int zd_usb_ioread16v(struct zd_usb *usb, u16 *values,
		     const zd_addr_t *addresses, unsigned int count)
{
	struct usb_req_read_regs *req = (void *)usb->req_buf;
	const struct usb_int_regs *regs =
		(const struct usb_int_regs *)usb->read_regs_buffer;
	struct timespec deadline;
	struct timeval now;
	int r, req_len, try_count = 0;
	bool retry;

	if (count < 1 || count > USB_MAX_IOREAD16_COUNT)
		return -EINVAL;
	if (!usb->int_enabled)
		return -EWOULDBLOCK;

	req_len = (int)(sizeof(struct usb_req_read_regs) + count * sizeof(__le16));
	req->id = cpu_to_le16(USB_REQ_READ_REGS);
	for (unsigned int i = 0; i < count; i++)
		req->addr[i] = cpu_to_le16((u16)addresses[i]);

retry_read:
	try_count++;
	pthread_mutex_lock(&usb->intr_lock);
	usb->read_regs_enabled = 1;
	usb->read_regs_done = 0;
	usb->read_regs_overridden = 0;
	usb->read_regs_req = req;
	usb->read_regs_count = count;
	pthread_mutex_unlock(&usb->intr_lock);

	r = usbdev_write(usb->dev, EP_REGS_OUT, req, (size_t)req_len,
			 REG_IO_TIMEOUT_MS);
	if (r) {
		pthread_mutex_lock(&usb->intr_lock);
		usb->read_regs_enabled = 0;
		pthread_mutex_unlock(&usb->intr_lock);
		xg_log(XG_LOG_DBG, "lecture de registres: envoi impossible (%d)\n",
		       r);
		return r;
	}

	gettimeofday(&now, NULL);
	deadline.tv_sec = now.tv_sec;
	deadline.tv_nsec = (long)now.tv_usec * 1000 +
			   (long)REG_IO_TIMEOUT_MS * 1000000L;
	deadline.tv_sec += deadline.tv_nsec / 1000000000L;
	deadline.tv_nsec %= 1000000000L;

	pthread_mutex_lock(&usb->intr_lock);
	while (!usb->read_regs_done) {
		if (pthread_cond_timedwait(&usb->intr_cond, &usb->intr_lock,
					   &deadline) != 0)
			break;
	}
	if (!usb->read_regs_done) {
		usb->read_regs_enabled = 0;
		pthread_mutex_unlock(&usb->intr_lock);
		xg_log(XG_LOG_DBG, "lecture de registres: délai dépassé\n");
		return -ETIMEDOUT;
	}

	/* Read failed because firmware bug? */
	retry = usb->read_regs_overridden;
	r = -EIO;
	if (!retry && check_read_regs(usb, req, count)) {
		for (unsigned int i = 0; i < count; i++)
			values[i] = le16_to_cpu(regs->regs[i].value);
		r = 0;
	}
	pthread_mutex_unlock(&usb->intr_lock);

	if (usbdev_is_gone(usb->dev))
		return -ENODEV;
	if (retry && try_count < 20)
		goto retry_read;
	return r;
}

void zd_usb_iowrite16v_async_start(struct zd_usb *usb)
{
	usb->in_async = 1;
	usb->cmd_error = 0;
}

int zd_usb_iowrite16v_async_end(struct zd_usb *usb, unsigned int timeout)
{
	(void)timeout;
	usb->in_async = 0;
	return usb->cmd_error;
}

/* Unlike Linux nothing is queued here: each batch is written at once. */
int zd_usb_iowrite16v_async(struct zd_usb *usb, const struct zd_ioreq16 *ioreqs,
			    unsigned int count)
{
	u8 buf[sizeof(struct usb_req_write_regs) +
	       USB_MAX_IOWRITE16_COUNT * sizeof(struct reg_data)];
	struct usb_req_write_regs *req = (void *)buf;
	int r, req_len;

	if (count == 0)
		return 0;
	if (count > USB_MAX_IOWRITE16_COUNT)
		return -EINVAL;

	req_len = (int)(sizeof(*req) + count * sizeof(struct reg_data));
	req->id = cpu_to_le16(USB_REQ_WRITE_REGS);
	for (unsigned int i = 0; i < count; i++) {
		struct reg_data *rw = &req->reg_writes[i];

		rw->addr = cpu_to_le16((u16)ioreqs[i].addr);
		rw->value = cpu_to_le16(ioreqs[i].value);
	}

	r = usbdev_write(usb->dev, EP_REGS_OUT, req, (size_t)req_len,
			 REG_IO_TIMEOUT_MS);
	if (r) {
		xg_log(XG_LOG_DBG, "écriture de registres impossible (%d)\n", r);
		if (!usb->cmd_error)
			usb->cmd_error = r;
	}
	return r;
}

int zd_usb_iowrite16v(struct zd_usb *usb, const struct zd_ioreq16 *ioreqs,
		      unsigned int count)
{
	int r;

	zd_usb_iowrite16v_async_start(usb);
	r = zd_usb_iowrite16v_async(usb, ioreqs, count);
	if (r) {
		zd_usb_iowrite16v_async_end(usb, 0);
		return r;
	}
	return zd_usb_iowrite16v_async_end(usb, 50 /* ms */);
}

int zd_usb_rfwrite(struct zd_usb *usb, u32 value, u8 bits)
{
	struct usb_req_rfwrite *req = (void *)usb->req_buf;
	u16 bit_value_template;
	int r, req_len;

	if (bits < USB_MIN_RFWRITE_BIT_COUNT || bits > USB_MAX_RFWRITE_BIT_COUNT)
		return -EINVAL;

	r = zd_usb_ioread16(usb, &bit_value_template, ZD_CR203);
	if (r) {
		xg_log(XG_LOG_DBG, "radio: lecture de CR203 impossible (%d)\n", r);
		return r;
	}
	bit_value_template &= ~(RF_IF_LE | RF_CLK | RF_DATA);

	BUILD_BUG_ON(sizeof(struct usb_req_rfwrite) +
		     USB_MAX_RFWRITE_BIT_COUNT * sizeof(__le16) >
		     sizeof(usb->req_buf));

	req_len = (int)(sizeof(struct usb_req_rfwrite) + bits * sizeof(__le16));
	req->id = cpu_to_le16(USB_REQ_WRITE_RF);
	/* 1: 3683a, but not used in ZYDAS driver */
	req->value = cpu_to_le16(2);
	req->bits = cpu_to_le16(bits);

	for (int i = 0; i < bits; i++) {
		u16 bv = bit_value_template;

		if (value & (1 << (bits - 1 - i)))
			bv |= RF_DATA;
		req->bit_values[i] = cpu_to_le16(bv);
	}

	r = usbdev_write(usb->dev, EP_REGS_OUT, req, (size_t)req_len,
			 REG_IO_TIMEOUT_MS);
	if (r)
		xg_log(XG_LOG_DBG, "radio: écriture impossible (%d)\n", r);
	return r;
}
