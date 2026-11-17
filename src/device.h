/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * The stick as a plain 802.11 radio: bring-up, channel, raw frame
 * transmission and reception. Everything ZD1211-specific stops here.
 */
#ifndef XG_DEVICE_H
#define XG_DEVICE_H

#include <stddef.h>
#include <stdint.h>

struct xg_dev;

/* 802.11b/g rates, slowest first (index into xg_rates[]) */
#define XG_N_RATES 12
#define XG_RATE_1M 0
#define XG_RATE_11M 3
#define XG_RATE_6M 4
#define XG_RATE_54M 11

struct xg_rate {
	uint8_t ieee;	/* in units of 500 kbit/s */
	uint8_t zd;	/* chip encoding */
	uint8_t ofdm;
};
extern const struct xg_rate xg_rates[XG_N_RATES];

/* index for a rate given in 500 kbit/s units (basic-rate flag ignored), -1 */
int xg_rate_index(uint8_t ieee);
int xg_rate_index_from_zd(uint8_t zd);

struct xg_rx_info {
	int signal;	/* 0..100, as reported by the chip */
	int rate;	/* index into xg_rates, -1 if unknown */
};

struct xg_dev_ops {
	/* one received 802.11 frame, without FCS (USB event thread) */
	void (*rx)(void *ctx, const uint8_t *frame, size_t len,
		   const struct xg_rx_info *info);
	/* the chip had to retry a frame, or gave up (USB event thread) */
	void (*tx_report)(void *ctx, const uint8_t *dest, int final_rate,
			  int retries, int failed);
	/* the stick was unplugged (any thread, at most once) */
	void (*gone)(void *ctx);
};

/* tx flags */
#define XG_TX_NO_ACK 0x01		/* group addressed */
#define XG_TX_SHORT_PREAMBLE 0x02	/* CCK rates above 1 Mbit/s */
#define XG_TX_CTS_PROTECT 0x04		/* CTS-to-self before an OFDM frame */
#define XG_TX_RTS 0x08
#define XG_TX_URGENT 0x10		/* never dropped when the queue is full */

/* Finds the stick, loads its firmware and initialises it.
 * -ENODEV when no supported stick is plugged in. */
int xg_dev_open(struct xg_dev **out, const struct xg_dev_ops *ops, void *ctx);
void xg_dev_close(struct xg_dev *dev);

/* Radio on, reception and transmission enabled. */
int xg_dev_start(struct xg_dev *dev);
void xg_dev_stop(struct xg_dev *dev);

const uint8_t *xg_dev_addr(const struct xg_dev *dev);
const char *xg_dev_description(const struct xg_dev *dev);
/* highest 2.4 GHz channel allowed by the stick's regulatory domain */
int xg_dev_max_channel(const struct xg_dev *dev);
const char *xg_dev_regdomain_name(const struct xg_dev *dev);

int xg_dev_set_channel(struct xg_dev *dev, int channel);
int xg_dev_channel(const struct xg_dev *dev);
/* preamble used for the RTS/CTS frames the chip generates itself */
int xg_dev_set_short_preamble(struct xg_dev *dev, int enabled);

enum xg_led { XG_LED_OFF, XG_LED_SCANNING, XG_LED_ASSOCIATED };
void xg_dev_set_led(struct xg_dev *dev, enum xg_led state);

/*
 * Queues one 802.11 frame (header + body, no FCS) for transmission at the
 * given rate. The duration field is filled in by the chip. Returns 0,
 * -ENOBUFS when the queue is full, or another -errno.
 */
int xg_dev_tx(struct xg_dev *dev, const uint8_t *frame, size_t len,
	      int rate, unsigned int flags);
int xg_dev_tx_queue_len(struct xg_dev *dev);

struct xg_dev_stats {
	uint64_t rx_frames, rx_errors;
	uint64_t tx_frames, tx_dropped, tx_errors;
	uint64_t tx_retried, tx_failed;
};
void xg_dev_get_stats(struct xg_dev *dev, struct xg_dev_stats *st);

#endif /* XG_DEVICE_H */
