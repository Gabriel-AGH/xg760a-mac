/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * WPA / WPA2-Personal supplicant: the EAPOL-Key 4-way and group key
 * handshakes (IEEE 802.11-2012, 11.6).
 */
#ifndef XG_WPA_H
#define XG_WPA_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

enum wpa_proto {
	WPA_PROTO_WPA = 1,	/* WPA (TKIP era), vendor IE */
	WPA_PROTO_RSN = 2,	/* WPA2, RSN IE */
};

struct wpa_callbacks {
	/* sends an EAPOL frame (starting at the 802.1X header) to the AP */
	int (*send_eapol)(void *ctx, const uint8_t *eapol, size_t len);
	/* installs a pairwise (key_idx 0) or group key */
	int (*set_key)(void *ctx, int pairwise, int key_idx,
		       enum xg_cipher cipher, const uint8_t *key, size_t len,
		       const uint8_t *rsc);
	/* all keys are in place: the port can be opened */
	void (*completed)(void *ctx);
	/* the handshake cannot succeed (text is for the user) */
	void (*failed)(void *ctx, const char *text);
};

struct wpa_params {
	enum wpa_proto proto;
	enum xg_cipher pairwise;
	enum xg_cipher group;
	uint8_t pmk[32];
	uint8_t own_addr[6];
	uint8_t bssid[6];
	/* the WPA/RSN element we put in the association request */
	uint8_t own_ie[64];
	size_t own_ie_len;
};

struct wpa_sm {
	const struct wpa_callbacks *cb;
	void *ctx;
	struct wpa_params p;
	int active;
	int ptk_installed;
	int completed;
	int msg1_count;		/* message 1 seen since the last message 3 */
	int have_tptk;
	int replay_valid;
	uint8_t replay[8];
	uint8_t snonce[32];
	uint8_t anonce[32];
	uint8_t tptk[64];	/* being negotiated */
	uint8_t ptk[64];	/* installed: KCK(16) KEK(16) TK(32) */
};

void wpa_sm_init(struct wpa_sm *sm, const struct wpa_callbacks *cb, void *ctx);
/* (re)starts for a new association */
void wpa_sm_start(struct wpa_sm *sm, const struct wpa_params *p);
void wpa_sm_stop(struct wpa_sm *sm);
/* one EAPOL frame from the AP, starting at the 802.1X header */
void wpa_sm_rx_eapol(struct wpa_sm *sm, const uint8_t *buf, size_t len);

/* Builds the WPA or RSN element for an association request.
 * Returns its length (0 on error). */
size_t wpa_build_ie(enum wpa_proto proto, enum xg_cipher pairwise,
		    enum xg_cipher group, uint8_t *out, size_t max);

#endif /* XG_WPA_H */
