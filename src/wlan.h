/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * 802.11 station: scanning, joining a network, WPA key handshake, data
 * path. One internal thread owns all the state; the functions below can be
 * called from any thread.
 */
#ifndef XG_WLAN_H
#define XG_WLAN_H

#include <stddef.h>
#include <stdint.h>

#define WLAN_MAX_BSS 64
#define WLAN_MAX_NETWORKS 16

struct wlan;

enum wlan_state {
	WLAN_NO_DEVICE = 0,	/* stick not plugged in */
	WLAN_IDLE,		/* stick ready, not connected */
	WLAN_SCANNING,
	WLAN_AUTHENTICATING,
	WLAN_ASSOCIATING,
	WLAN_HANDSHAKE,		/* WPA key negotiation */
	WLAN_CONNECTED,
};

/* cipher / key management bit masks: bit n = suite type n of the standard */
#define WLAN_CIPHER_TKIP (1u << 2)
#define WLAN_CIPHER_CCMP (1u << 4)
#define WLAN_AKM_8021X (1u << 1)
#define WLAN_AKM_PSK (1u << 2)
#define WLAN_AKM_PSK_SHA256 (1u << 6)
#define WLAN_AKM_SAE (1u << 8)

struct wlan_bss {
	uint8_t bssid[6];
	uint8_t ssid[32];
	uint8_t ssid_len;
	uint8_t channel;
	int signal;		/* 0..100 */
	uint16_t capab;
	uint16_t beacon_int;
	uint16_t rate_mask;	/* bit n = xg_rates[n] supported */
	uint16_t basic_mask;
	uint8_t erp;
	uint8_t has_erp, has_ht;
	uint8_t has_rsn, has_wpa;
	unsigned int rsn_pairwise, rsn_akm, wpa_pairwise, wpa_akm;
	uint8_t rsn_group, wpa_group;	/* suite type */
	uint16_t rsn_caps;
	uint64_t last_seen;	/* ms, monotonic clock */
};

/* Short description of the protection of a network ("WPA2", "ouvert"...).
 * *usable is set to 0 when this driver cannot join it. */
const char *wlan_bss_security(const struct wlan_bss *b, int *usable);

struct wlan_network {
	uint8_t ssid[32];
	uint8_t ssid_len;
	int has_psk;		/* 0 = open network */
	uint8_t pmk[32];	/* PBKDF2(passphrase, ssid) */
};

struct wlan_status {
	enum wlan_state state;
	int device_present;
	char device[160];
	char regdomain[32];
	uint8_t addr[6];
	uint8_t ssid[32];
	uint8_t ssid_len;
	uint8_t bssid[6];
	int channel;
	int signal;
	int tx_rate;		/* 500 kbit/s units */
	int rx_rate;
	char security[24];
	char last_error[160];
	uint64_t connected_ms;	/* how long the link has been up */
	uint64_t rx_packets, tx_packets, rx_dropped, tx_dropped;
	uint64_t tx_retried, tx_failed, rx_crypt_errors;
};

struct wlan_callbacks {
	/* The stick appeared (addr = its MAC address) or went away. */
	void (*device)(void *ctx, int present, const uint8_t *addr);
	/* The network is usable (keys installed) or not any more. */
	void (*link)(void *ctx, int up);
	/* One Ethernet frame received from the network. */
	void (*rx_packet)(void *ctx, const uint8_t *eth, size_t len);
};

/*
 * The callbacks run on the station thread: they must return quickly and
 * must not call back into this API, except wlan_send().
 */
struct wlan *wlan_create(const struct wlan_callbacks *cb, void *ctx);
void wlan_destroy(struct wlan *w);

/*
 * Known networks, most preferred first. The station keeps itself connected
 * to the first one in range. An empty list disconnects.
 */
void wlan_set_networks(struct wlan *w, const struct wlan_network *nets, int n);

/* Runs a full scan and copies the result, strongest first.
 * Returns the number of networks, or -errno (-ENODEV: no stick). */
int wlan_scan(struct wlan *w, struct wlan_bss *out, int max);

void wlan_get_status(struct wlan *w, struct wlan_status *st);

/* Waits until the state is reached. Returns 0, or -ETIMEDOUT. */
int wlan_wait_state(struct wlan *w, enum wlan_state state, int timeout_ms);
int wlan_wait_device(struct wlan *w, int timeout_ms);

/*
 * Sleep support. wlan_suspend() leaves the network, releases the stick and
 * returns once that is done (or after 3 s); wlan_resume() lets the station
 * find the stick again and reconnect.
 */
void wlan_suspend(struct wlan *w);
void wlan_resume(struct wlan *w);

/* Queues one Ethernet frame for transmission. Returns 0 or -errno. */
int wlan_send(struct wlan *w, const uint8_t *eth, size_t len);

/* Frames accepted by wlan_send() that have not reached the stick yet. */
int wlan_tx_backlog(struct wlan *w);

const char *wlan_state_name(enum wlan_state s);

#endif /* XG_WLAN_H */
