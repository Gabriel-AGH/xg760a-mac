/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * WPA / WPA2-Personal supplicant: 4-way and group key handshakes.
 */
#include "wpa.h"

#include <string.h>

#include "compat.h"
#include "ieee80211.h"

#define KEY_INFO_VER_MASK 0x0007
#define KEY_INFO_PAIRWISE 0x0008
#define KEY_INFO_INDEX_MASK 0x0030
#define KEY_INFO_INSTALL 0x0040
#define KEY_INFO_ACK 0x0080
#define KEY_INFO_MIC 0x0100
#define KEY_INFO_SECURE 0x0200
#define KEY_INFO_ERROR 0x0400
#define KEY_INFO_REQUEST 0x0800
#define KEY_INFO_ENCRYPTED 0x1000

/* offsets in an EAPOL-Key frame, 802.1X header included */
#define OFF_DESC_TYPE 4
#define OFF_INFO 5
#define OFF_KEY_LEN 7
#define OFF_REPLAY 9
#define OFF_NONCE 17
#define OFF_IV 49
#define OFF_RSC 65
#define OFF_MIC 81
#define OFF_DATA_LEN 97
#define OFF_DATA 99

#define EAPOL_TYPE_KEY 3
#define DESC_TYPE_RSN 2
#define DESC_TYPE_WPA 254

#define MAX_EAPOL 1024

void wpa_sm_init(struct wpa_sm *sm, const struct wpa_callbacks *cb, void *ctx)
{
	memset(sm, 0, sizeof(*sm));
	sm->cb = cb;
	sm->ctx = ctx;
}

void wpa_sm_start(struct wpa_sm *sm, const struct wpa_params *p)
{
	const struct wpa_callbacks *cb = sm->cb;
	void *ctx = sm->ctx;

	memset(sm, 0, sizeof(*sm));
	sm->cb = cb;
	sm->ctx = ctx;
	sm->p = *p;
	sm->active = 1;
	/* one SNonce per association: retransmitted message 1 frames must
	 * lead to the same PTK */
	xg_random(sm->snonce, sizeof(sm->snonce));
}

void wpa_sm_stop(struct wpa_sm *sm)
{
	const struct wpa_callbacks *cb = sm->cb;
	void *ctx = sm->ctx;

	memset(sm, 0, sizeof(*sm));
	sm->cb = cb;
	sm->ctx = ctx;
}

size_t wpa_build_ie(enum wpa_proto proto, enum xg_cipher pairwise,
		    enum xg_cipher group, uint8_t *out, size_t max)
{
	static const uint8_t rsn_oui[3] = { 0x00, 0x0f, 0xac };
	static const uint8_t wpa_oui[3] = { 0x00, 0x50, 0xf2 };
	const uint8_t *oui = proto == WPA_PROTO_RSN ? rsn_oui : wpa_oui;
	uint8_t *p = out;
	uint8_t pw = pairwise == XG_CIPHER_CCMP ? 4 : 2;
	uint8_t gr = group == XG_CIPHER_CCMP ? 4 : 2;

	if (max < 32)
		return 0;
	if (proto == WPA_PROTO_RSN) {
		*p++ = IE_RSN;
		*p++ = 20;
	} else {
		*p++ = IE_VENDOR;
		*p++ = 22;
		memcpy(p, wpa_oui, 3);
		p += 3;
		*p++ = 1;
	}
	*p++ = 1; /* version */
	*p++ = 0;
	memcpy(p, oui, 3);
	p += 3;
	*p++ = gr;
	*p++ = 1; /* one pairwise suite */
	*p++ = 0;
	memcpy(p, oui, 3);
	p += 3;
	*p++ = pw;
	*p++ = 1; /* one key management suite: PSK */
	*p++ = 0;
	memcpy(p, oui, 3);
	p += 3;
	*p++ = 2;
	if (proto == WPA_PROTO_RSN) {
		*p++ = 0; /* RSN capabilities */
		*p++ = 0;
	}
	return (size_t)(p - out);
}

static int eapol_mic(const uint8_t *kck, int ver, const uint8_t *frame,
		     size_t len, uint8_t mic[16])
{
	uint8_t hash[20];

	if (ver == 1) {
		hmac_md5(kck, 16, frame, len, hash);
	} else if (ver == 2) {
		hmac_sha1(kck, 16, frame, len, hash);
	} else {
		return -1;
	}
	memcpy(mic, hash, 16);
	return 0;
}

static int eapol_check_mic(const uint8_t *kck, int ver, const uint8_t *frame,
			   size_t len)
{
	uint8_t tmp[MAX_EAPOL];
	uint8_t mic[16];

	if (len > sizeof(tmp))
		return -1;
	memcpy(tmp, frame, len);
	memset(tmp + OFF_MIC, 0, 16);
	if (eapol_mic(kck, ver, tmp, len, mic))
		return -1;
	return memcmp(mic, frame + OFF_MIC, 16) == 0 ? 0 : -1;
}

/* builds and sends a reply; data may be NULL */
static int send_key_frame(struct wpa_sm *sm, const uint8_t *kck, int ver,
			  uint8_t desc_type, uint16_t info, uint16_t key_len,
			  const uint8_t *replay, const uint8_t *nonce,
			  const uint8_t *data, size_t data_len)
{
	uint8_t f[OFF_DATA + 128];

	if (data_len > 128)
		return -1;
	memset(f, 0, sizeof(f));
	f[0] = 1; /* 802.1X-2001, understood by every access point */
	f[1] = EAPOL_TYPE_KEY;
	put_be16(f + 2, (uint16_t)(OFF_DATA - 4 + data_len));
	f[OFF_DESC_TYPE] = desc_type;
	put_be16(f + OFF_INFO, info);
	put_be16(f + OFF_KEY_LEN, key_len);
	memcpy(f + OFF_REPLAY, replay, 8);
	if (nonce)
		memcpy(f + OFF_NONCE, nonce, 32);
	put_be16(f + OFF_DATA_LEN, (uint16_t)data_len);
	if (data_len)
		memcpy(f + OFF_DATA, data, data_len);
	if (eapol_mic(kck, ver, f, OFF_DATA + data_len, f + OFF_MIC))
		return -1;
	return sm->cb->send_eapol(sm->ctx, f, OFF_DATA + data_len);
}

static void derive_ptk(struct wpa_sm *sm)
{
	uint8_t data[76];
	const uint8_t *aa = sm->p.bssid, *spa = sm->p.own_addr;

	if (memcmp(aa, spa, 6) < 0) {
		memcpy(data, aa, 6);
		memcpy(data + 6, spa, 6);
	} else {
		memcpy(data, spa, 6);
		memcpy(data + 6, aa, 6);
	}
	if (memcmp(sm->anonce, sm->snonce, 32) < 0) {
		memcpy(data + 12, sm->anonce, 32);
		memcpy(data + 44, sm->snonce, 32);
	} else {
		memcpy(data + 12, sm->snonce, 32);
		memcpy(data + 44, sm->anonce, 32);
	}
	/* PRF-384 (CCMP) is the beginning of PRF-512 (TKIP) */
	wpa_prf(sm->p.pmk, 32, "Pairwise key expansion", data, sizeof(data),
		sm->tptk, 64);
	sm->have_tptk = 1;
}

static size_t cipher_key_len(enum xg_cipher c)
{
	return c == XG_CIPHER_CCMP ? 16 : 32;
}

static void install_gtk(struct wpa_sm *sm, int idx, const uint8_t *gtk,
			size_t len, const uint8_t *rsc)
{
	if (len != cipher_key_len(sm->p.group)) {
		xg_log(XG_LOG_WARN,
		       "WPA: clé de groupe de longueur inattendue (%zu octets)\n",
		       len);
		return;
	}
	xg_log(XG_LOG_DBG, "WPA: clé de groupe %d installée\n", idx);
	sm->cb->set_key(sm->ctx, 0, idx, sm->p.group, gtk, len, rsc);
}

/* looks for the GTK KDE in decrypted RSN key data */
static int find_gtk_kde(const uint8_t *d, size_t len, const uint8_t **gtk,
			size_t *gtk_len, int *idx)
{
	size_t pos = 0;

	while (pos + 2 <= len) {
		uint8_t type = d[pos], l = d[pos + 1];

		if (type == 0xdd && l == 0)
			break; /* padding */
		if (pos + 2 + l > len)
			break;
		if (type == 0xdd && l >= 6 && d[pos + 2] == 0x00 &&
		    d[pos + 3] == 0x0f && d[pos + 4] == 0xac &&
		    d[pos + 5] == 1) {
			*idx = d[pos + 6] & 0x03;
			*gtk = d + pos + 8;
			*gtk_len = (size_t)l - 6;
			return 0;
		}
		pos += 2 + (size_t)l;
	}
	return -1;
}

/*
 * Decrypts the key data of an EAPOL-Key frame with the key encryption key:
 * AES key wrap for descriptor version 2 (AES-CCMP networks), RC4 keyed
 * with the frame's IV for version 1 (TKIP networks). Returns the length of
 * the clear text, or -1.
 */
static int decrypt_key_data(const uint8_t *kek, int ver, const uint8_t *f,
			    uint16_t data_len, uint8_t *plain)
{
	if (ver == 2) {
		if (data_len < 16 || data_len % 8 ||
		    aes_unwrap(kek, data_len / 8 - 1, f + OFF_DATA, plain))
			return -1;
		return data_len - 8;
	}
	if (ver == 1) {
		uint8_t rc4key[32];

		if (data_len == 0 || data_len > MAX_EAPOL)
			return -1;
		memcpy(rc4key, f + OFF_IV, 16);
		memcpy(rc4key + 16, kek, 16);
		memcpy(plain, f + OFF_DATA, data_len);
		rc4_skip(rc4key, 32, 256, plain, data_len);
		memset(rc4key, 0, sizeof(rc4key));
		return data_len;
	}
	return -1;
}

static void process_msg1(struct wpa_sm *sm, const uint8_t *f, int ver)
{
	uint16_t info = (uint16_t)(ver | KEY_INFO_PAIRWISE | KEY_INFO_MIC);
	uint16_t key_len = sm->p.proto == WPA_PROTO_RSN ?
		0 : get_be16(f + OFF_KEY_LEN);

	sm->msg1_count++;
	xg_log(XG_LOG_DBG, "WPA: message 1/4 reçu (n. %d)\n", sm->msg1_count);
	memcpy(sm->anonce, f + OFF_NONCE, 32);
	derive_ptk(sm);
	send_key_frame(sm, sm->tptk, ver, f[OFF_DESC_TYPE], info, key_len,
		       f + OFF_REPLAY, sm->snonce, sm->p.own_ie,
		       sm->p.own_ie_len);
	xg_log(XG_LOG_DBG, "WPA: message 2/4 envoyé\n");
}

static void process_msg3(struct wpa_sm *sm, const uint8_t *f, size_t len,
			 int ver)
{
	uint16_t info = get_be16(f + OFF_INFO);
	uint16_t data_len = get_be16(f + OFF_DATA_LEN);
	uint16_t key_len = sm->p.proto == WPA_PROTO_RSN ?
		0 : get_be16(f + OFF_KEY_LEN);
	uint8_t plain[MAX_EAPOL];
	const uint8_t *gtk = NULL;
	size_t gtk_len = 0;
	int gtk_idx = 0;
	int same_ptk;

	if (!sm->have_tptk) {
		xg_log(XG_LOG_DBG, "WPA: message 3/4 sans message 1 préalable\n");
		return;
	}
	if (memcmp(f + OFF_NONCE, sm->anonce, 32) != 0) {
		xg_log(XG_LOG_DBG, "WPA: message 3/4 avec un ANonce différent\n");
		return;
	}
	if (eapol_check_mic(sm->tptk, ver, f, len)) {
		xg_log(XG_LOG_WARN, "WPA: message 3/4 avec un MIC invalide\n");
		return;
	}
	memcpy(sm->replay, f + OFF_REPLAY, 8);
	sm->replay_valid = 1;
	xg_log(XG_LOG_DBG, "WPA: message 3/4 reçu et vérifié\n");

	if (sm->p.proto == WPA_PROTO_RSN) {
		int n = (info & KEY_INFO_ENCRYPTED) ?
			decrypt_key_data(sm->tptk + 16, ver, f, data_len, plain) :
			-1;

		if (n < 0) {
			sm->cb->failed(sm->ctx,
				       "données de clé illisibles dans le message 3/4");
			return;
		}
		if (find_gtk_kde(plain, (size_t)n, &gtk, &gtk_len,
				 &gtk_idx)) {
			sm->cb->failed(sm->ctx,
				       "pas de clé de groupe dans le message 3/4");
			return;
		}
	}

	send_key_frame(sm, sm->tptk, ver, f[OFF_DESC_TYPE],
		       (uint16_t)(ver | KEY_INFO_PAIRWISE | KEY_INFO_MIC |
				  (info & KEY_INFO_SECURE)),
		       key_len, f + OFF_REPLAY, NULL, NULL, 0);
	xg_log(XG_LOG_DBG, "WPA: message 4/4 envoyé\n");

	/* Never re-install a key that is already in use: that would reset
	 * its packet numbers (key reinstallation attack). */
	same_ptk = sm->ptk_installed && memcmp(sm->ptk, sm->tptk, 64) == 0;
	if ((info & KEY_INFO_INSTALL) && !same_ptk) {
		sm->cb->set_key(sm->ctx, 1, 0, sm->p.pairwise, sm->tptk + 32,
				cipher_key_len(sm->p.pairwise), NULL);
		memcpy(sm->ptk, sm->tptk, 64);
		sm->ptk_installed = 1;
		xg_log(XG_LOG_DBG, "WPA: clé de session installée\n");
	}
	if (gtk && !same_ptk)
		install_gtk(sm, gtk_idx, gtk, gtk_len, f + OFF_RSC);
	sm->msg1_count = 0;

	if (sm->p.proto == WPA_PROTO_RSN && !sm->completed) {
		sm->completed = 1;
		sm->cb->completed(sm->ctx);
	}
	memset(plain, 0, sizeof(plain));
}

static void process_group1(struct wpa_sm *sm, const uint8_t *f, size_t len,
			   int ver)
{
	uint16_t info = get_be16(f + OFF_INFO);
	uint16_t data_len = get_be16(f + OFF_DATA_LEN);
	uint16_t key_len = get_be16(f + OFF_KEY_LEN);
	uint8_t plain[MAX_EAPOL];
	const uint8_t *gtk = NULL;
	size_t gtk_len = 0;
	int gtk_idx = 0;

	if (!sm->ptk_installed)
		return;
	if (eapol_check_mic(sm->ptk, ver, f, len)) {
		xg_log(XG_LOG_WARN, "WPA: message de groupe avec un MIC invalide\n");
		return;
	}
	memcpy(sm->replay, f + OFF_REPLAY, 8);
	sm->replay_valid = 1;

	{
		int n = decrypt_key_data(sm->ptk + 16, ver, f, data_len, plain);

		if (n < 0) {
			xg_log(XG_LOG_WARN, "WPA: clé de groupe illisible\n");
			return;
		}
		if (sm->p.proto == WPA_PROTO_RSN) {
			if (!(info & KEY_INFO_ENCRYPTED) ||
			    find_gtk_kde(plain, (size_t)n, &gtk, &gtk_len,
					 &gtk_idx)) {
				xg_log(XG_LOG_WARN,
				       "WPA: clé de groupe illisible (renouvellement)\n");
				return;
			}
		} else {
			/* WPA: the key data is the group key itself */
			gtk_idx = (info & KEY_INFO_INDEX_MASK) >> 4;
			gtk_len = (size_t)n;
			if (key_len && key_len < gtk_len)
				gtk_len = key_len;
			gtk = plain;
		}
	}
	install_gtk(sm, gtk_idx, gtk, gtk_len, f + OFF_RSC);

	send_key_frame(sm, sm->ptk, ver, f[OFF_DESC_TYPE],
		       (uint16_t)(ver | KEY_INFO_MIC | KEY_INFO_SECURE |
				  (info & KEY_INFO_INDEX_MASK)),
		       sm->p.proto == WPA_PROTO_RSN ? 0 : key_len,
		       f + OFF_REPLAY, NULL, NULL, 0);
	xg_log(XG_LOG_DBG, "WPA: clé de groupe renouvelée, réponse envoyée\n");

	if (!sm->completed) {
		sm->completed = 1;
		sm->cb->completed(sm->ctx);
	}
	memset(plain, 0, sizeof(plain));
}

void wpa_sm_rx_eapol(struct wpa_sm *sm, const uint8_t *buf, size_t len)
{
	uint16_t info, data_len;
	size_t body_len;
	int ver;

	if (!sm->active || len < 4)
		return;
	if (buf[1] != EAPOL_TYPE_KEY)
		return; /* EAP itself (802.1X enterprise) is not supported */
	body_len = get_be16(buf + 2);
	if (4 + body_len > len || 4 + body_len < OFF_DATA ||
	    4 + body_len > MAX_EAPOL)
		return;
	len = 4 + body_len;

	if (buf[OFF_DESC_TYPE] !=
	    (sm->p.proto == WPA_PROTO_RSN ? DESC_TYPE_RSN : DESC_TYPE_WPA)) {
		xg_log(XG_LOG_DBG, "WPA: descripteur de clé inattendu (%u)\n",
		       buf[OFF_DESC_TYPE]);
		return;
	}
	info = get_be16(buf + OFF_INFO);
	data_len = get_be16(buf + OFF_DATA_LEN);
	if (OFF_DATA + (size_t)data_len > len)
		return;
	ver = info & KEY_INFO_VER_MASK;
	if (ver != 1 && ver != 2) {
		sm->cb->failed(sm->ctx,
			       "le point d'accès exige un mode de gestion de clés non pris en charge (WPA3 / PMF)");
		return;
	}
	if (!(info & KEY_INFO_ACK) || (info & KEY_INFO_REQUEST))
		return;
	if (sm->replay_valid && memcmp(buf + OFF_REPLAY, sm->replay, 8) <= 0) {
		xg_log(XG_LOG_DBG, "WPA: trame EAPOL rejouée, ignorée\n");
		return;
	}

	if (info & KEY_INFO_PAIRWISE) {
		if (info & KEY_INFO_MIC)
			process_msg3(sm, buf, len, ver);
		else
			process_msg1(sm, buf, ver);
	} else if (info & KEY_INFO_MIC) {
		process_group1(sm, buf, len, ver);
	}
}
