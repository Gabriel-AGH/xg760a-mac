// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Gabriel-AGH
/* ZD1211 USB-WLAN driver - macOS user-space port: device glue.
 *
 * The bring-up sequence, the transmit control set and the receive status
 * handling follow the Linux zd1211rw driver (zd_mac.c):
 * Copyright (C) 2005-2007 Ulrich Kunitz <kune@deine-taler.de>
 * Copyright (C) 2006-2007 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2006-2007 Michael Wu <flamingice@sourmilk.net>
 * Copyright (C) 2007-2008 Luis R. Rodriguez <mcgrof@winlab.rutgers.edu>
 */
#include "device.h"

#include <sys/time.h>

#include "ieee80211.h"
#include "usbdev.h"
#include "zd_chip.h"
#include "zd_mac.h"
#include "zd_rf.h"
#include "zd_usb.h"

#define TX_QUEUE_MAX 128
#define TX_QUEUE_HARD_MAX 256

const struct xg_rate xg_rates[XG_N_RATES] = {
	{ 2, ZD_CCK_RATE_1M, 0 },    { 4, ZD_CCK_RATE_2M, 0 },
	{ 11, ZD_CCK_RATE_5_5M, 0 }, { 22, ZD_CCK_RATE_11M, 0 },
	{ 12, ZD_OFDM_RATE_6M, 1 },  { 18, ZD_OFDM_RATE_9M, 1 },
	{ 24, ZD_OFDM_RATE_12M, 1 }, { 36, ZD_OFDM_RATE_18M, 1 },
	{ 48, ZD_OFDM_RATE_24M, 1 }, { 72, ZD_OFDM_RATE_36M, 1 },
	{ 96, ZD_OFDM_RATE_48M, 1 }, { 108, ZD_OFDM_RATE_54M, 1 },
};

/* Sticks this driver knows how to talk to: { vendor, product, is ZD1211B }.
 * Only the Sagem XG-760A has been tested. */
static const struct {
	uint16_t vid, pid;
	int is_b;
} supported[] = {
	{ 0x079b, 0x004a, 0 }, /* Sagem XG-760A */
	{ 0x079b, 0x0062, 1 }, /* Sagem XG-76NA */
	{ 0x0ace, 0x1211, 0 }, /* ZyDAS ZD1211 reference design */
	{ 0x0ace, 0x1215, 1 }, /* ZyDAS ZD1211B reference design */
};

struct txbuf {
	struct txbuf *next;
	unsigned int len;
	u8 data[];
};

struct xg_dev {
	struct zd_mac mac;
	struct usbdev *usb;
	const struct xg_dev_ops *ops;
	void *ctx;
	u8 addr[ETH_ALEN];
	char desc[160];
	int started;
	int gone;

	pthread_mutex_t lock;
	pthread_cond_t tx_cond;
	pthread_cond_t svc_cond;
	pthread_t tx_thread, svc_thread;
	int threads_started;
	int stopping;
	struct txbuf *tx_head, *tx_tail;
	int tx_len;
	int hwint_pending;
	enum xg_led led;
	struct xg_dev_stats stats;
};

int xg_rate_index(uint8_t ieee)
{
	ieee &= 0x7f;
	for (int i = 0; i < XG_N_RATES; i++)
		if (xg_rates[i].ieee == ieee)
			return i;
	return -1;
}

int xg_rate_index_from_zd(uint8_t zd)
{
	for (int i = 0; i < XG_N_RATES; i++)
		if (xg_rates[i].zd == ZD_RATE(zd))
			return i;
	return -1;
}

/* --- callbacks from the USB event thread -------------------------------- */

static void dev_rx(void *ctx, const u8 *buffer, unsigned int length)
{
	struct xg_dev *dev = ctx;
	const struct rx_status *status;
	struct xg_rx_info info;

	if (length < ZD_PLCP_HEADER_SIZE + 10 /* shortest frame */ + FCS_LEN +
			     sizeof(struct rx_status))
		return;
	status = (const struct rx_status *)(buffer + length - sizeof(*status));
	if (status->frame_status & ZD_RX_ERROR) {
		dev->stats.rx_errors++;
		return;
	}
	dev->stats.rx_frames++;

	info.signal = status->signal_strength > 100 ? 100 :
						       status->signal_strength;
	info.rate = xg_rate_index_from_zd(zd_rx_rate(buffer, status));
	dev->ops->rx(dev->ctx, buffer + ZD_PLCP_HEADER_SIZE,
		     length - ZD_PLCP_HEADER_SIZE - sizeof(*status) - FCS_LEN,
		     &info);
}

static void dev_tx_status(void *ctx, const u8 *buffer, unsigned int length)
{
	struct xg_dev *dev = ctx;
	const struct tx_status *st = (const struct tx_status *)buffer;

	if (length < sizeof(*st))
		return;
	if (st->failure)
		dev->stats.tx_failed++;
	else
		dev->stats.tx_retried++;
	if (dev->ops->tx_report)
		dev->ops->tx_report(dev->ctx, st->mac,
				    xg_rate_index_from_zd(st->rate), st->retry,
				    st->failure);
}

static void dev_hw_interrupt(void *ctx, u16 status)
{
	struct xg_dev *dev = ctx;

	xg_log(XG_LOG_TRACE, "interruption matérielle %#06x\n", status);
	pthread_mutex_lock(&dev->lock);
	dev->hwint_pending = 1;
	pthread_cond_signal(&dev->svc_cond);
	pthread_mutex_unlock(&dev->lock);
}

static void dev_gone(void *ctx)
{
	struct xg_dev *dev = ctx;
	int first;

	pthread_mutex_lock(&dev->lock);
	first = !dev->gone;
	dev->gone = 1;
	pthread_cond_broadcast(&dev->tx_cond);
	pthread_cond_broadcast(&dev->svc_cond);
	pthread_mutex_unlock(&dev->lock);
	if (first && dev->ops->gone)
		dev->ops->gone(dev->ctx);
}

static const struct zd_usb_ops usb_ops = {
	.rx = dev_rx,
	.tx_status = dev_tx_status,
	.hw_interrupt = dev_hw_interrupt,
	.gone = dev_gone,
};

/* --- worker threads ----------------------------------------------------- */

static void *tx_main(void *arg)
{
	struct xg_dev *dev = arg;

	pthread_setname_np("xg760a-tx");
	pthread_mutex_lock(&dev->lock);
	while (!dev->stopping && !dev->gone) {
		struct txbuf *b = dev->tx_head;
		int r;

		if (!b) {
			pthread_cond_wait(&dev->tx_cond, &dev->lock);
			continue;
		}
		dev->tx_head = b->next;
		if (!dev->tx_head)
			dev->tx_tail = NULL;
		dev->tx_len--;
		pthread_mutex_unlock(&dev->lock);

		r = zd_usb_tx(&dev->mac.chip.usb, b->data, b->len);
		free(b);

		pthread_mutex_lock(&dev->lock);
		if (r) {
			dev->stats.tx_errors++;
			xg_log(XG_LOG_DBG, "émission: erreur USB %d\n", r);
		} else {
			dev->stats.tx_frames++;
		}
	}
	pthread_mutex_unlock(&dev->lock);
	return NULL;
}

/* Slow housekeeping kept away from the data path: re-arming the chip's
 * interrupts and driving the LED (which blinks while scanning). */
static void *svc_main(void *arg)
{
	struct xg_dev *dev = arg;
	struct zd_chip *chip = &dev->mac.chip;

	pthread_setname_np("xg760a-svc");
	pthread_mutex_lock(&dev->lock);
	while (!dev->stopping && !dev->gone) {
		struct timespec deadline;
		struct timeval now;
		int hwint;
		enum xg_led led;

		gettimeofday(&now, NULL);
		deadline.tv_sec = now.tv_sec + 1;
		deadline.tv_nsec = (long)now.tv_usec * 1000;
		if (!dev->hwint_pending)
			pthread_cond_timedwait(&dev->svc_cond, &dev->lock,
					       &deadline);
		if (dev->stopping || dev->gone)
			break;
		hwint = dev->hwint_pending;
		dev->hwint_pending = 0;
		led = dev->led;
		pthread_mutex_unlock(&dev->lock);

		if (dev->started) {
			if (hwint)
				zd_chip_enable_hwint(chip);
			zd_chip_control_leds(chip,
					     led == XG_LED_ASSOCIATED ?
						     ZD_LED_ASSOCIATED :
					     led == XG_LED_SCANNING ?
						     ZD_LED_SCANNING :
						     ZD_LED_OFF);
		}
		pthread_mutex_lock(&dev->lock);
	}
	pthread_mutex_unlock(&dev->lock);
	return NULL;
}

/* --- life cycle --------------------------------------------------------- */

int xg_dev_open(struct xg_dev **out, const struct xg_dev_ops *ops, void *ctx)
{
	uint16_t ids[ARRAY_SIZE(supported)][2];
	struct xg_dev *dev;
	struct zd_chip *chip;
	int is_b = 0;
	int r;

	*out = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(supported); i++) {
		ids[i][0] = supported[i].vid;
		ids[i][1] = supported[i].pid;
	}

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;
	dev->ops = ops;
	dev->ctx = ctx;
	pthread_mutex_init(&dev->lock, NULL);
	pthread_cond_init(&dev->tx_cond, NULL);
	pthread_cond_init(&dev->svc_cond, NULL);
	chip = &dev->mac.chip;

	r = usbdev_open(&dev->usb, ids, ARRAY_SIZE(ids));
	if (r)
		goto err_free;
	/* Back to the boot code, whatever state a previous run left. Linux
	 * does the same (usb_reset_device) before loading the firmware. */
	r = usbdev_reset_and_reopen(&dev->usb, ids, ARRAY_SIZE(ids));
	if (r) {
		xg_log(XG_LOG_ERR, "réinitialisation USB de la clé impossible (%d)\n",
		       r);
		goto err_free;
	}
	for (size_t i = 0; i < ARRAY_SIZE(supported); i++)
		if (supported[i].vid == usbdev_vid(dev->usb) &&
		    supported[i].pid == usbdev_pid(dev->usb))
			is_b = supported[i].is_b;

	dev->mac.hw = &dev->mac.hw_storage;
	dev->mac.hw->wiphy = &dev->mac.wiphy_storage;
	dev->mac.hw->priv = &dev->mac;
	zd_chip_init(chip, dev->mac.hw, NULL);
	zd_usb_attach(&chip->usb, dev->usb, is_b, &usb_ops, dev);

	r = zd_chip_read_mac_addr_fw(chip, dev->addr);
	if (r)
		goto err_usb;
	memcpy(dev->mac.wiphy_storage.perm_addr, dev->addr, ETH_ALEN);

	r = zd_usb_bring_up(&chip->usb);
	if (r)
		goto err_usb;

	/* zd_mac_init_hw() */
	r = zd_chip_enable_int(chip);
	if (!r)
		r = zd_chip_init_hw(chip);
	if (!r)
		r = zd_read_regdomain(chip, &dev->mac.regdomain);
	/* We must inform the device that we are doing encryption/decryption
	 * in software at the moment. */
	if (!r)
		r = zd_set_encryption_type(chip, ENC_SNIFFER);
	if (r) {
		xg_log(XG_LOG_ERR, "initialisation de la puce impossible (%d)\n", r);
		goto err_usb;
	}

	snprintf(dev->desc, sizeof(dev->desc),
		 "ZD1211%s (USB %04x:%04x, %s), radio %s, micrologiciel %s",
		 is_b ? "B" : "", usbdev_vid(dev->usb), usbdev_pid(dev->usb),
		 usbdev_is_high_speed(dev->usb) ? "USB 2.0" : "USB 1.1",
		 zd_rf_name(chip->rf.type), dev->mac.wiphy_storage.fw_version);

	if (pthread_create(&dev->tx_thread, NULL, tx_main, dev) != 0 ||
	    pthread_create(&dev->svc_thread, NULL, svc_main, dev) != 0) {
		r = -EAGAIN;
		goto err_usb;
	}
	dev->threads_started = 1;
	*out = dev;
	return 0;

err_usb:
	usbdev_close(dev->usb);
err_free:
	pthread_mutex_destroy(&dev->lock);
	pthread_cond_destroy(&dev->tx_cond);
	pthread_cond_destroy(&dev->svc_cond);
	free(dev);
	return r;
}

/* zd_op_start() */
int xg_dev_start(struct xg_dev *dev)
{
	struct zd_chip *chip = &dev->mac.chip;
	struct zd_mc_hash hash;
	int r;

	r = zd_chip_set_basic_rates(chip, CR_RATES_80211B | CR_RATES_80211G);
	if (r < 0)
		return r;
	r = zd_write_mac_addr(chip, dev->addr);
	if (r)
		return r;
	/* Management frames a station cares about, no control frames: the
	 * retry reports of the chip are enough for rate control, so the ACKs
	 * themselves need not travel over USB. */
	r = zd_iowrite32(chip, CR_RX_FILTER,
			 RX_FILTER_ASSOC_RESPONSE | RX_FILTER_REASSOC_RESPONSE |
			 RX_FILTER_PROBE_RESPONSE | RX_FILTER_BEACON |
			 RX_FILTER_DISASSOC | RX_FILTER_AUTH |
			 RX_FILTER_DEAUTH | (1 << 13) /* action */);
	if (r)
		return r;
	/* all multicast groups: IPv6 and Bonjour need them, the system
	 * filters what it does not want */
	zd_mc_add_all(&hash);
	r = zd_chip_set_multicast_hash(chip, &hash);
	if (r)
		return r;

	/* Wait after setting the multicast hash table and powering on
	 * the radio otherwise interface bring up will fail. This matches
	 * what the vendor driver did. */
	msleep(10);

	r = zd_chip_switch_radio_on(chip);
	if (r < 0) {
		xg_log(XG_LOG_ERR, "mise en marche de la radio impossible (%d)\n", r);
		return r;
	}
	r = zd_chip_enable_rxtx(chip);
	if (r < 0)
		goto disable_radio;
	r = zd_chip_enable_hwint(chip);
	if (r < 0)
		goto disable_rxtx;
	dev->started = 1;
	return 0;

disable_rxtx:
	zd_chip_disable_rxtx(chip);
disable_radio:
	zd_chip_switch_radio_off(chip);
	return r;
}

void xg_dev_stop(struct xg_dev *dev)
{
	struct zd_chip *chip = &dev->mac.chip;

	if (!dev->started)
		return;
	dev->started = 0;
	zd_chip_disable_rxtx(chip);
	if (dev->gone)
		return;
	zd_chip_disable_hwint(chip);
	zd_chip_switch_radio_off(chip);
	zd_chip_control_leds(chip, ZD_LED_OFF);
}

void xg_dev_close(struct xg_dev *dev)
{
	struct txbuf *b;

	if (!dev)
		return;
	xg_dev_stop(dev);

	pthread_mutex_lock(&dev->lock);
	dev->stopping = 1;
	pthread_cond_broadcast(&dev->tx_cond);
	pthread_cond_broadcast(&dev->svc_cond);
	pthread_mutex_unlock(&dev->lock);
	if (dev->threads_started) {
		pthread_join(dev->tx_thread, NULL);
		pthread_join(dev->svc_thread, NULL);
	}
	while ((b = dev->tx_head)) {
		dev->tx_head = b->next;
		free(b);
	}

	zd_chip_disable_int(&dev->mac.chip);
	usbdev_close(dev->usb);
	zd_chip_clear(&dev->mac.chip);
	pthread_mutex_destroy(&dev->lock);
	pthread_cond_destroy(&dev->tx_cond);
	pthread_cond_destroy(&dev->svc_cond);
	free(dev);
}

const uint8_t *xg_dev_addr(const struct xg_dev *dev)
{
	return dev->addr;
}

const char *xg_dev_description(const struct xg_dev *dev)
{
	return dev->desc;
}

int xg_dev_max_channel(const struct xg_dev *dev)
{
	switch (dev->mac.regdomain) {
	case ZD_REGDOMAIN_FCC:
	case ZD_REGDOMAIN_IC:
		return 11;
	case ZD_REGDOMAIN_JAPAN:
	case ZD_REGDOMAIN_JAPAN_2:
	case ZD_REGDOMAIN_JAPAN_3:
		return 14;
	default:
		return 13;
	}
}

const char *xg_dev_regdomain_name(const struct xg_dev *dev)
{
	switch (dev->mac.regdomain) {
	case ZD_REGDOMAIN_FCC:
		return "FCC (États-Unis)";
	case ZD_REGDOMAIN_IC:
		return "IC (Canada)";
	case ZD_REGDOMAIN_ETSI:
		return "ETSI (Europe)";
	case ZD_REGDOMAIN_SPAIN:
		return "Espagne";
	case ZD_REGDOMAIN_FRANCE:
		return "France";
	case ZD_REGDOMAIN_JAPAN:
	case ZD_REGDOMAIN_JAPAN_2:
	case ZD_REGDOMAIN_JAPAN_3:
		return "Japon";
	default:
		return "inconnu";
	}
}

int xg_dev_set_channel(struct xg_dev *dev, int channel)
{
	if (channel < MIN_CHANNEL24 || channel > MAX_CHANNEL24)
		return -EINVAL;
	return zd_chip_set_channel(&dev->mac.chip, (u8)channel);
}

int xg_dev_channel(const struct xg_dev *dev)
{
	return dev->mac.chip.rf.channel;
}

int xg_dev_set_short_preamble(struct xg_dev *dev, int enabled)
{
	struct zd_chip *chip = &dev->mac.chip;
	int r;

	mutex_lock(&chip->mutex);
	r = zd_chip_set_rts_cts_rate_locked(chip, enabled ? 1 : 0);
	mutex_unlock(&chip->mutex);
	return r;
}

void xg_dev_set_led(struct xg_dev *dev, enum xg_led state)
{
	pthread_mutex_lock(&dev->lock);
	dev->led = state;
	pthread_mutex_unlock(&dev->lock);
}

/* --- transmission ------------------------------------------------------- */

static int zd_calc_tx_length_us(u8 *service, u8 zd_rate, u16 tx_length)
{
	/* ZD_PURE_RATE() must be used to remove the modulation type flag of
	 * the zd-rate values.
	 */
	static const u8 rate_divisor[] = {
		[ZD_PURE_RATE(ZD_CCK_RATE_1M)] = 1,
		[ZD_PURE_RATE(ZD_CCK_RATE_2M)] = 2,
		/* Bits must be doubled. */
		[ZD_PURE_RATE(ZD_CCK_RATE_5_5M)] = 11,
		[ZD_PURE_RATE(ZD_CCK_RATE_11M)] = 11,
		[ZD_PURE_RATE(ZD_OFDM_RATE_6M)] = 6,
		[ZD_PURE_RATE(ZD_OFDM_RATE_9M)] = 9,
		[ZD_PURE_RATE(ZD_OFDM_RATE_12M)] = 12,
		[ZD_PURE_RATE(ZD_OFDM_RATE_18M)] = 18,
		[ZD_PURE_RATE(ZD_OFDM_RATE_24M)] = 24,
		[ZD_PURE_RATE(ZD_OFDM_RATE_36M)] = 36,
		[ZD_PURE_RATE(ZD_OFDM_RATE_48M)] = 48,
		[ZD_PURE_RATE(ZD_OFDM_RATE_54M)] = 54,
	};

	u32 bits = (u32)tx_length * 8;
	u32 divisor;

	divisor = rate_divisor[ZD_PURE_RATE(zd_rate)];
	if (divisor == 0)
		return -EINVAL;

	switch (zd_rate) {
	case ZD_CCK_RATE_5_5M:
		bits = (2 * bits) + 10; /* round up to the next integer */
		break;
	case ZD_CCK_RATE_11M:
		if (service) {
			u32 t = bits % 11;
			*service &= ~ZD_PLCP_SERVICE_LENGTH_EXTENSION;
			if (0 < t && t <= 3) {
				*service |= ZD_PLCP_SERVICE_LENGTH_EXTENSION;
			}
		}
		bits += 10; /* round up to the next integer */
		break;
	}

	return bits / divisor;
}

int xg_dev_tx(struct xg_dev *dev, const uint8_t *frame, size_t len, int rate,
	      unsigned int flags)
{
	struct zd_ctrlset *cs;
	struct txbuf *b;
	unsigned int frag_len = (unsigned int)len + FCS_LEN;
	unsigned int packet_length;
	u16 fc;
	int r;

	if (!dev->started || dev->gone)
		return -ENODEV;
	if (len < 10 || len > IEEE80211_MAX_FRAME_LEN || rate < 0 ||
	    rate >= XG_N_RATES)
		return -EINVAL;

	b = malloc(sizeof(*b) + sizeof(*cs) + len);
	if (!b)
		return -ENOMEM;
	b->next = NULL;
	b->len = (unsigned int)(sizeof(*cs) + len);
	cs = (struct zd_ctrlset *)b->data;
	memcpy(b->data + sizeof(*cs), frame, len);
	fc = get_le16(frame);

	/*
	 * Firmware computes the duration itself (for all frames except PSPoll)
	 * and needs the field set to 0 at input, otherwise firmware messes up
	 * duration_id and sets bits 14 and 15 on.
	 */
	if ((fc & (FC_TYPE_MASK | FC_SUBTYPE_MASK)) != 0x00a4) {
		b->data[sizeof(*cs) + 2] = 0;
		b->data[sizeof(*cs) + 3] = 0;
	}

	cs->modulation = xg_rates[rate].zd;
	if (!xg_rates[rate].ofdm && rate != XG_RATE_1M &&
	    (flags & XG_TX_SHORT_PREAMBLE))
		cs->modulation |= ZD_CCK_PREA_SHORT;
	cs->tx_length = cpu_to_le16(frag_len);

	cs->control = ZD_CS_NEED_RANDOM_BACKOFF;
	if (flags & XG_TX_NO_ACK)
		cs->control |= ZD_CS_NO_ACK;
	if ((fc & (FC_TYPE_MASK | FC_SUBTYPE_MASK)) == 0x00a4)
		cs->control |= ZD_CS_PS_POLL_FRAME;
	if (flags & XG_TX_RTS)
		cs->control |= ZD_CS_RTS;
	if ((flags & XG_TX_CTS_PROTECT) && xg_rates[rate].ofdm)
		cs->control |= ZD_CS_SELF_CTS;

	packet_length = frag_len + sizeof(struct zd_ctrlset) + 10;
	/* ZD1211B: Computing the length difference this way, gives us
	 * flexibility to compute the packet length. */
	cs->packet_length = cpu_to_le16(zd_chip_is_zd1211b(&dev->mac.chip) ?
			packet_length - frag_len : packet_length);

	cs->service = 0;
	r = zd_calc_tx_length_us(&cs->service, ZD_RATE(cs->modulation),
				 le16_to_cpu(cs->tx_length));
	if (r < 0) {
		free(b);
		return r;
	}
	cs->current_length = cpu_to_le16(r);
	cs->next_frame_length = 0;

	pthread_mutex_lock(&dev->lock);
	if (dev->tx_len >= ((flags & XG_TX_URGENT) ? TX_QUEUE_HARD_MAX :
						     TX_QUEUE_MAX)) {
		dev->stats.tx_dropped++;
		pthread_mutex_unlock(&dev->lock);
		free(b);
		return -ENOBUFS;
	}
	if (dev->tx_tail)
		dev->tx_tail->next = b;
	else
		dev->tx_head = b;
	dev->tx_tail = b;
	dev->tx_len++;
	pthread_cond_signal(&dev->tx_cond);
	pthread_mutex_unlock(&dev->lock);
	return 0;
}

int xg_dev_tx_queue_len(struct xg_dev *dev)
{
	int n;

	pthread_mutex_lock(&dev->lock);
	n = dev->tx_len;
	pthread_mutex_unlock(&dev->lock);
	return n;
}

void xg_dev_get_stats(struct xg_dev *dev, struct xg_dev_stats *st)
{
	pthread_mutex_lock(&dev->lock);
	*st = dev->stats;
	pthread_mutex_unlock(&dev->lock);
}
