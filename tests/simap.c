/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * End-to-end test without any radio: the real station code (wlan.c, wpa.c,
 * crypto.c, ministack.c) runs against a simulated stick whose "air" leads
 * to a simulated WPA2 access point with a DHCP server and a router.
 *
 * This file replaces src/device.c at link time: it implements the same
 * xg_dev_* interface.
 *
 * usage: simap [ccmp|tkip-group|wpa2-tkip|wpa1|open|wrongpass|scan|panne|
 *               deauth|fuzz] [log level]
 *
 * "scan" searches for networks while connected, "panne" switches the access
 * point off for a while, "deauth" has it throw the station out: each time
 * the link must come back by itself and carry traffic again.
 *
 * "fuzz" connects, then floods the station with hundreds of thousands of
 * damaged copies of real frames: it must neither crash nor misbehave (build
 * with -fsanitize=address,undefined to make any slip visible).
 */
#include <CommonCrypto/CommonCrypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "crypto.h"
#include "device.h"
#include "ieee80211.h"
#include "ministack.h"
#include "wlan.h"

/* --- the rate table normally provided by device.c ----------------------- */

const struct xg_rate xg_rates[XG_N_RATES] = {
	{ 2, 0x00, 0 },  { 4, 0x01, 0 },  { 11, 0x02, 0 }, { 22, 0x03, 0 },
	{ 12, 0x1b, 1 }, { 18, 0x1f, 1 }, { 24, 0x1a, 1 }, { 36, 0x1e, 1 },
	{ 48, 0x19, 1 }, { 72, 0x1d, 1 }, { 96, 0x18, 1 }, { 108, 0x1c, 1 },
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
	(void)zd;
	return -1;
}

/* --- scenario ----------------------------------------------------------- */

#define AP_CHANNEL 6
#define AP_SSID "Reseau-Simule"
#define AP_PASS "phrase secrète du point d'accès"
#define ROUTER_IP 0xc0a84d01u /* 192.168.77.1 */
#define LEASE_IP 0xc0a84d2au  /* 192.168.77.42 */

static const uint8_t sta_addr[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t bssid[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0xaa };
static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int secured = 1;
static int wpa1;	/* advertise the older WPA element instead of RSN */
static enum xg_cipher pair_cipher = XG_CIPHER_CCMP;
static enum xg_cipher group_cipher = XG_CIPHER_CCMP;
/* EAPOL-Key descriptor version: 2 with AES-CCMP, 1 with TKIP */
#define KEY_VER (pair_cipher == XG_CIPHER_CCMP ? 2 : 1)
/* the access point is switched off: it neither sends nor hears anything */
static volatile int ap_off;

struct xg_dev {
	const struct xg_dev_ops *ops;
	void *ctx;
	int channel;
	int started;
	pthread_t beacon_thread;
	int stop;
	struct xg_dev_stats stats;
};

static struct {
	pthread_mutex_t lock;
	struct xg_dev *dev;
	uint16_t seq;
	uint8_t pmk[32];
	uint8_t anonce[32], snonce[32];
	uint8_t ptk[64];
	uint8_t gtk[32];
	int gtk_idx;
	uint64_t replay;
	int state; /* 0 idle, 1 sent msg1, 2 sent msg3, 3 keys installed */
	struct xg_key ptk_key, gtk_key;
	int sta_ip_known;
	int msg1_tries, msg1_age;
	/* what the test checks at the end */
	unsigned int n_probe, n_auth, n_assoc, n_msg2, n_msg4, n_group2;
	unsigned int n_dhcp, n_arp_req, n_arp_reply, n_ping, n_clear_after_keys;
	unsigned int n_decrypt_fail, n_bad_mic;
} ap;

/* --- helpers ------------------------------------------------------------ */

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint16_t csum(const uint8_t *p, size_t len)
{
	uint32_t sum = 0;

	for (; len > 1; p += 2, len -= 2)
		sum += (uint32_t)((p[0] << 8) | p[1]);
	if (len)
		sum += (uint32_t)(p[0] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* RFC 3394 key wrap, n 8-byte blocks of plaintext */
static void aes_wrap(const uint8_t kek[16], int n, const uint8_t *plain,
		     uint8_t *cipher)
{
	uint8_t a[8], b[16];
	size_t moved;

	memset(a, 0xa6, 8);
	memcpy(cipher + 8, plain, 8 * (size_t)n);
	for (int j = 0; j <= 5; j++) {
		for (int i = 1; i <= n; i++) {
			uint64_t t = (uint64_t)n * (uint64_t)j + (uint64_t)i;

			memcpy(b, a, 8);
			memcpy(b + 8, cipher + 8 * i, 8);
			CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, kek,
				16, NULL, b, 16, b, 16, &moved);
			memcpy(a, b, 8);
			for (int k = 0; k < 8; k++)
				a[7 - k] ^= (uint8_t)(t >> (8 * k));
			memcpy(cipher + 8 * i, b + 8, 8);
		}
	}
	memcpy(cipher, a, 8);
}

/* the last frames sent to the station: raw material for the fuzzer */
#define TAP_SLOTS 64
static struct {
	size_t len;
	uint8_t data[2500];
} tap[TAP_SLOTS];
static unsigned int tap_count;

static void deliver(const uint8_t *frame, size_t len)
{
	struct xg_rx_info info = { .signal = 70, .rate = XG_RATE_54M };
	struct xg_dev *dev = ap.dev;

	if (ap_off)
		return;
	if (len <= sizeof(tap[0].data)) {
		unsigned int slot = tap_count++ % TAP_SLOTS;

		/* keep a good mix: do not let pings evict everything else */
		if (tap_count > TAP_SLOTS && len > 1000)
			slot = TAP_SLOTS - 1;
		tap[slot].len = len;
		memcpy(tap[slot].data, frame, len);
	}

	if (dev && dev->started && dev->channel == AP_CHANNEL)
		dev->ops->rx(dev->ctx, frame, len, &info);
}

static void hdr(uint8_t *f, uint16_t fc, const uint8_t *a1, const uint8_t *a3)
{
	put_le16(f, fc);
	f[2] = f[3] = 0;
	memcpy(f + 4, a1, 6);
	memcpy(f + 10, bssid, 6);
	memcpy(f + 16, a3, 6);
	put_le16(f + 22, (uint16_t)((ap.seq++ & 0xfff) << 4));
}

static size_t rsn_ie(uint8_t *p)
{
	static const uint8_t rsn[] = { 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac,
				       0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
				       0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00,
				       0x00 };
	static const uint8_t wpa[] = { 0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01,
				       0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00,
				       0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00,
				       0x50, 0xf2, 0x02 };
	uint8_t g = group_cipher == XG_CIPHER_CCMP ? 4 : 2;
	uint8_t pw = pair_cipher == XG_CIPHER_CCMP ? 4 : 2;

	if (wpa1) {
		memcpy(p, wpa, sizeof(wpa));
		p[11] = g;
		p[17] = pw;
		return sizeof(wpa);
	}
	memcpy(p, rsn, sizeof(rsn));
	p[7] = g;
	p[13] = pw;
	return sizeof(rsn);
}

static void send_beacon(const uint8_t *dest, int probe_resp)
{
	static const uint8_t rates[] = { 1, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c,
					 0x12, 0x18, 0x24 };
	static const uint8_t ext[] = { 50, 4, 0x30, 0x48, 0x60, 0x6c };
	uint8_t f[256];
	uint8_t *p = f + 24;

	hdr(f, probe_resp ? FC_PROBE_RESP : FC_BEACON, dest, bssid);
	memset(p, 0, 8);
	put_le16(p + 8, 100);
	put_le16(p + 10, (uint16_t)(CAP_ESS | CAP_SHORT_PREAMBLE |
				    CAP_SHORT_SLOT |
				    (secured ? CAP_PRIVACY : 0)));
	p += 12;
	*p++ = IE_SSID;
	*p++ = (uint8_t)strlen(AP_SSID);
	memcpy(p, AP_SSID, strlen(AP_SSID));
	p += strlen(AP_SSID);
	memcpy(p, rates, sizeof(rates));
	p += sizeof(rates);
	*p++ = IE_DS_PARAMS;
	*p++ = 1;
	*p++ = AP_CHANNEL;
	*p++ = IE_ERP;
	*p++ = 1;
	*p++ = 0;
	if (secured)
		p += rsn_ie(p);
	memcpy(p, ext, sizeof(ext));
	p += sizeof(ext);
	deliver(f, (size_t)(p - f));
}

/* sends an Ethernet payload to the station, protected when keys exist */
static void send_data(const uint8_t *da, const uint8_t *sa, uint16_t type,
		      const uint8_t *payload, size_t len, int force_clear)
{
	uint8_t body[2400], f[2500];
	static const uint8_t snap[6] = { 0xaa, 0xaa, 0x03, 0, 0, 0 };
	int group = da[0] & 1;
	int protect = secured && ap.state == 3 && !force_clear;
	size_t blen;

	memcpy(body, snap, 6);
	put_be16(body + 6, type);
	memcpy(body + 8, payload, len);
	blen = 8 + len;
	hdr(f, (uint16_t)(FC_DATA | FC_FROMDS | (protect ? FC_PROTECTED : 0)),
	    da, sa);
	if (protect) {
		int n = xg_encrypt(group ? &ap.gtk_key : &ap.ptk_key, f, 24, body,
				   blen, f + 24);

		if (n < 0)
			return;
		blen = (size_t)n;
	} else {
		memcpy(f + 24, body, blen);
	}
	deliver(f, 24 + blen);
}

/* --- authenticator ------------------------------------------------------ */

static void eapol_mic(const uint8_t *kck, uint8_t *f, size_t len)
{
	uint8_t mac[20];

	memset(f + 81, 0, 16);
	if (KEY_VER == 1)
		hmac_md5(kck, 16, f, len, mac);
	else
		hmac_sha1(kck, 16, f, len, mac);
	memcpy(f + 81, mac, 16);
}

static int eapol_mic_ok(const uint8_t *kck, const uint8_t *f, size_t len)
{
	uint8_t tmp[512], mac[20];

	if (len > sizeof(tmp))
		return 0;
	memcpy(tmp, f, len);
	memset(tmp + 81, 0, 16);
	if (KEY_VER == 1)
		hmac_md5(kck, 16, tmp, len, mac);
	else
		hmac_sha1(kck, 16, tmp, len, mac);
	return memcmp(mac, f + 81, 16) == 0;
}

static void put_replay(uint8_t *f)
{
	uint64_t r = ++ap.replay;

	for (int i = 0; i < 8; i++)
		f[9 + i] = (uint8_t)(r >> (56 - 8 * i));
}

static void send_msg1(int first)
{
	uint8_t f[99];

	if (first) {
		/* retransmissions keep the same ANonce */
		xg_random(ap.anonce, 32);
		ap.msg1_tries = 0;
	}
	ap.msg1_tries++;
	ap.msg1_age = 0;

	memset(f, 0, sizeof(f));
	f[0] = 2;
	f[1] = 3;
	put_be16(f + 2, 95);
	f[4] = wpa1 ? 254 : 2;
	put_be16(f + 5, (uint16_t)(0x0088 | KEY_VER));
	put_be16(f + 7, pair_cipher == XG_CIPHER_CCMP ? 16 : 32);
	put_replay(f);
	memcpy(f + 17, ap.anonce, 32);
	ap.state = 1;
	send_data(sta_addr, bssid, ETHERTYPE_EAPOL, f, sizeof(f), 1);
}

static size_t gtk_kde(uint8_t *p, int idx)
{
	size_t klen = group_cipher == XG_CIPHER_CCMP ? 16 : 32;

	p[0] = 0xdd;
	p[1] = (uint8_t)(6 + klen);
	p[2] = 0x00;
	p[3] = 0x0f;
	p[4] = 0xac;
	p[5] = 1;
	p[6] = (uint8_t)idx;
	p[7] = 0;
	memcpy(p + 8, ap.gtk, klen);
	return 8 + klen;
}

static void install_gtk(int idx)
{
	uint8_t swapped[32];
	size_t klen = group_cipher == XG_CIPHER_CCMP ? 16 : 32;

	/* our key object is written from the supplicant's point of view:
	 * give it the Michael keys the other way round */
	memcpy(swapped, ap.gtk, 32);
	memcpy(swapped + 16, ap.gtk + 24, 8);
	memcpy(swapped + 24, ap.gtk + 16, 8);
	xg_key_set(&ap.gtk_key, group_cipher, idx, swapped, klen, NULL);
	ap.gtk_idx = idx;
}

/* message 3 (pairwise) or group message 1 */
static void send_key_data(int group_msg, int idx)
{
	uint8_t f[99 + 128], plain[128], *p = plain;
	size_t klen = group_cipher == XG_CIPHER_CCMP ? 16 : 32;
	size_t plen, dlen;
	uint16_t info;
	int encrypt = 1;

	memset(f, 0, sizeof(f));
	memset(plain, 0, sizeof(plain));
	if (!wpa1) {
		/* WPA2: the element again, and the group key in a KDE */
		if (!group_msg)
			p += rsn_ie(p);
		p += gtk_kde(p, idx);
	} else if (!group_msg) {
		/* WPA: message 3 only repeats the element, in clear; the
		 * group key follows in its own handshake */
		p += rsn_ie(p);
		encrypt = 0;
	} else {
		memcpy(p, ap.gtk, klen);
		p += klen;
	}
	plen = (size_t)(p - plain);

	if (!encrypt) {
		memcpy(f + 99, plain, plen);
		dlen = plen;
	} else if (KEY_VER == 2) {
		if (plen % 8) {
			plain[plen++] = 0xdd;
			while (plen % 8)
				plen++;
		}
		aes_wrap(ap.ptk + 16, (int)(plen / 8), plain, f + 99);
		dlen = plen + 8;
	} else {
		uint8_t rc4key[32];

		xg_random(f + 49, 16); /* key IV */
		memcpy(rc4key, f + 49, 16);
		memcpy(rc4key + 16, ap.ptk + 16, 16);
		memcpy(f + 99, plain, plen);
		rc4_skip(rc4key, 32, 256, f + 99, plen);
		dlen = plen;
	}

	if (!group_msg)
		info = (uint16_t)(0x01c8 | (wpa1 ? 0 : 0x1200));
	else
		info = (uint16_t)(0x0380 | (wpa1 ? idx << 4 : 0x1000));
	f[0] = 2;
	f[1] = 3;
	put_be16(f + 2, (uint16_t)(95 + dlen));
	f[4] = wpa1 ? 254 : 2;
	put_be16(f + 5, (uint16_t)(info | KEY_VER));
	put_be16(f + 7, (uint16_t)(group_msg ? klen :
				   pair_cipher == XG_CIPHER_CCMP ? 16 : 32));
	put_replay(f);
	if (!group_msg)
		memcpy(f + 17, ap.anonce, 32);
	/* key RSC: the group key has not been used yet */
	put_be16(f + 97, (uint16_t)dlen);
	eapol_mic(ap.ptk, f, 99 + dlen);
	if (!group_msg)
		ap.state = 2;
	/* the first handshake travels in clear; anything after the pairwise
	 * key is installed is protected */
	send_data(sta_addr, bssid, ETHERTYPE_EAPOL, f, 99 + dlen, !group_msg);
}

static void rx_eapol(const uint8_t *e, size_t len)
{
	uint16_t info;

	if (len < 99 || e[1] != 3)
		return;
	info = get_be16(e + 5);
	if ((info & 0x0008) && (info & 0x0100) && get_be16(e + 97) > 0 &&
	    ap.state == 1) {
		/* message 2 */
		uint8_t data[76];
		const uint8_t *aa = bssid, *spa = sta_addr;

		memcpy(ap.snonce, e + 17, 32);
		memcpy(data, memcmp(aa, spa, 6) < 0 ? aa : spa, 6);
		memcpy(data + 6, memcmp(aa, spa, 6) < 0 ? spa : aa, 6);
		if (memcmp(ap.anonce, ap.snonce, 32) < 0) {
			memcpy(data + 12, ap.anonce, 32);
			memcpy(data + 44, ap.snonce, 32);
		} else {
			memcpy(data + 12, ap.snonce, 32);
			memcpy(data + 44, ap.anonce, 32);
		}
		wpa_prf(ap.pmk, 32, "Pairwise key expansion", data, 76, ap.ptk,
			64);
		if (!eapol_mic_ok(ap.ptk, e, len)) {
			/* wrong passphrase: a real access point stays mute
			 * and repeats message 1 */
			ap.n_bad_mic++;
			return;
		}
		ap.n_msg2++;
		xg_random(ap.gtk, 32);
		send_key_data(0, 1);
	} else if ((info & 0x0008) && (info & 0x0100) && ap.state == 2) {
		/* message 4 */
		if (!eapol_mic_ok(ap.ptk, e, len)) {
			ap.n_bad_mic++;
			return;
		}
		ap.n_msg4++;
		{
			uint8_t swapped[32];

			/* as for the group key: Michael keys the other way
			 * round on this side of the link */
			memcpy(swapped, ap.ptk + 32, 32);
			memcpy(swapped + 16, ap.ptk + 56, 8);
			memcpy(swapped + 24, ap.ptk + 48, 8);
			xg_key_set(&ap.ptk_key, pair_cipher, 0, swapped,
				   pair_cipher == XG_CIPHER_CCMP ? 16 : 32, NULL);
		}
		ap.state = 3;
		if (wpa1) {
			/* WPA: the group key comes now, in a second handshake */
			xg_random(ap.gtk, 32);
			send_key_data(1, 1);
		}
		install_gtk(1);
	} else if (!(info & 0x0008) && (info & 0x0100) && ap.state == 3) {
		/* group message 2 */
		if (eapol_mic_ok(ap.ptk, e, len))
			ap.n_group2++;
		else
			ap.n_bad_mic++;
	}
}

/* --- router and DHCP server behind the access point --------------------- */

static void router_rx(const uint8_t *da, const uint8_t *sa, uint16_t type,
		      const uint8_t *p, size_t len)
{
	uint8_t out[1600];

	(void)da;
	if (type == 0x0806 && len >= 28) {
		if (get_be16(p + 6) == 1 && be32(p + 24) == ROUTER_IP) {
			ap.n_arp_req++;
			memcpy(out, p, 28);
			put_be16(out + 6, 2);
			memcpy(out + 8, bssid, 6);
			wr32(out + 14, ROUTER_IP);
			memcpy(out + 18, p + 8, 10);
			send_data(sa, bssid, 0x0806, out, 28, 0);
		} else if (get_be16(p + 6) == 2 && be32(p + 14) == LEASE_IP) {
			ap.n_arp_reply++;
		}
		return;
	}
	if (type != 0x0800 || len < 28 || (p[0] >> 4) != 4)
		return;

	if (p[9] == 17 && get_be16(p + 22) == 67 && len >= 20 + 8 + 240) {
		/* DHCP: offer or acknowledge the one lease we have */
		const uint8_t *b = p + 28, *o = b + 240;
		uint8_t *ip = out, *udp = out + 20, *r = out + 28, *ro;
		int type53 = 0;
		int want_bcast = get_be16(b + 10) & 0x8000;
		const uint8_t *dest = want_bcast ? bcast : sa;

		while (o < p + len && *o != 255) {
			if (*o == 53)
				type53 = o[2];
			o += 2 + o[1];
		}
		if (type53 != 1 && type53 != 3)
			return;
		ap.n_dhcp++;
		memset(out, 0, 28 + 300);
		r[0] = 2;
		r[1] = 1;
		r[2] = 6;
		memcpy(r + 4, b + 4, 4);
		put_be16(r + 10, (uint16_t)want_bcast);
		wr32(r + 16, LEASE_IP);
		wr32(r + 20, ROUTER_IP);
		memcpy(r + 28, b + 28, 16);
		wr32(r + 236, 0x63825363);
		ro = r + 240;
		*ro++ = 53; *ro++ = 1; *ro++ = type53 == 1 ? 2 : 5;
		*ro++ = 54; *ro++ = 4; wr32(ro, ROUTER_IP); ro += 4;
		*ro++ = 51; *ro++ = 4; wr32(ro, 3600); ro += 4;
		*ro++ = 1; *ro++ = 4; wr32(ro, 0xffffff00); ro += 4;
		*ro++ = 3; *ro++ = 4; wr32(ro, ROUTER_IP); ro += 4;
		*ro++ = 6; *ro++ = 4; wr32(ro, ROUTER_IP); ro += 4;
		*ro++ = 255;
		put_be16(udp, 67);
		put_be16(udp + 2, 68);
		put_be16(udp + 4, 8 + 300);
		ip[0] = 0x45;
		put_be16(ip + 2, 20 + 8 + 300);
		ip[8] = 64;
		ip[9] = 17;
		wr32(ip + 12, ROUTER_IP);
		wr32(ip + 16, want_bcast ? 0xffffffff : LEASE_IP);
		put_be16(ip + 10, csum(ip, 20));
		send_data(dest, bssid, 0x0800, out, 28 + 300, 0);

		if (type53 == 3 && !ap.sta_ip_known) {
			/* like a real router, ask who has the new address:
			 * a broadcast the station must answer */
			uint8_t arp[28] = { 0, 1, 8, 0, 6, 4, 0, 1 };

			ap.sta_ip_known = 1;
			memcpy(arp + 8, bssid, 6);
			wr32(arp + 14, ROUTER_IP);
			wr32(arp + 24, LEASE_IP);
			send_data(bcast, bssid, 0x0806, arp, 28, 0);
		}
		return;
	}
	if (p[9] == 1 && len >= 28 && p[20] == 8) {
		/* answers every ping, whatever the destination: it plays
		 * both the router and the Internet */
		size_t total = get_be16(p + 2);

		if (total > len || total > sizeof(out))
			return;
		ap.n_ping++;
		memcpy(out, p, total);
		memcpy(out + 12, p + 16, 4);
		memcpy(out + 16, p + 12, 4);
		put_be16(out + 10, 0);
		put_be16(out + 10, csum(out, 20));
		out[20] = 0;
		put_be16(out + 22, 0);
		put_be16(out + 22, csum(out + 20, total - 20));
		send_data(sa, bssid, 0x0800, out, total, 0);
	}
}

/* --- what the access point does with the station's frames --------------- */

static void ap_rx(const uint8_t *f, size_t len)
{
	uint16_t fc = get_le16(f);
	uint8_t out[128], plain[2400];
	uint8_t *p;

	if (len < 24)
		return;
	switch (fc & (FC_TYPE_MASK | FC_SUBTYPE_MASK)) {
	case FC_PROBE_REQ:
		ap.n_probe++;
		send_beacon(f + 10, 1);
		return;
	case FC_AUTH:
		if (!addr_equal(f + 4, bssid))
			return;
		ap.n_auth++;
		hdr(out, FC_AUTH, f + 10, bssid);
		put_le16(out + 24, 0);
		put_le16(out + 26, 2);
		put_le16(out + 28, 0);
		deliver(out, 30);
		return;
	case FC_ASSOC_REQ:
		if (!addr_equal(f + 4, bssid))
			return;
		ap.n_assoc++;
		hdr(out, FC_ASSOC_RESP, f + 10, bssid);
		p = out + 24;
		put_le16(p, 0x0431);
		put_le16(p + 2, 0);
		put_le16(p + 4, 0xc001);
		p += 6;
		*p++ = 1; *p++ = 8;
		*p++ = 0x82; *p++ = 0x84; *p++ = 0x8b; *p++ = 0x96;
		*p++ = 0x0c; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;
		*p++ = 50; *p++ = 4;
		*p++ = 0x30; *p++ = 0x48; *p++ = 0x60; *p++ = 0x6c;
		deliver(out, (size_t)(p - out));
		ap.state = 0;
		ap.sta_ip_known = 0;
		xg_key_clear(&ap.ptk_key);
		xg_key_clear(&ap.gtk_key);
		if (secured)
			send_msg1(1);
		else
			ap.state = 3;
		return;
	case FC_DEAUTH:
		ap.state = 0;
		return;
	default:
		break;
	}

	if ((fc & FC_TYPE_MASK) != FC_TYPE_DATA || (fc & FC_STYPE_DATA_NODATA) ||
	    (fc & (FC_TODS | FC_FROMDS)) != FC_TODS || !addr_equal(f + 4, bssid))
		return;
	{
		const uint8_t *body = f + 24;
		size_t blen = len - 24;

		if (fc & FC_PROTECTED) {
			int n = ap.state == 3 ?
				xg_decrypt(&ap.ptk_key, f, 24, body, blen, plain) :
				-1;

			if (n < 0) {
				ap.n_decrypt_fail++;
				return;
			}
			body = plain;
			blen = (size_t)n;
		} else if (secured && ap.state == 3) {
			ap.n_clear_after_keys++;
			return;
		}
		if (blen < 8 || body[0] != 0xaa)
			return;
		if (get_be16(body + 6) == ETHERTYPE_EAPOL)
			rx_eapol(body + 8, blen - 8);
		else if (ap.state == 3)
			router_rx(f + 16, f + 10, get_be16(body + 6), body + 8,
				  blen - 8);
	}
}

static void *beacon_main(void *arg)
{
	struct xg_dev *dev = arg;
	int ticks = 0;

	while (!dev->stop) {
		usleep(100 * 1000);
		pthread_mutex_lock(&ap.lock);
		send_beacon(bcast, 0);
		/* no valid answer to message 1: repeat it every second, then
		 * throw the station out, as real access points do */
		if (ap.state == 1 && ++ap.msg1_age >= 10) {
			if (ap.msg1_tries < 4) {
				send_msg1(0);
			} else {
				uint8_t d[26];

				hdr(d, FC_DEAUTH, sta_addr, bssid);
				put_le16(d + 24, REASON_4WAY_HANDSHAKE_TIMEOUT);
				ap.state = 0;
				deliver(d, sizeof(d));
			}
		}
		/* a little later, renew the group key like real access
		 * points do every hour or so */
		if (secured && ap.state == 3 && ++ticks == 25 && ap.gtk_idx == 1) {
			xg_random(ap.gtk, 32);
			send_key_data(1, 2);
			install_gtk(2);
		}
		pthread_mutex_unlock(&ap.lock);
	}
	return NULL;
}

/* --- the simulated stick ------------------------------------------------ */

int xg_dev_open(struct xg_dev **out, const struct xg_dev_ops *ops, void *ctx)
{
	struct xg_dev *dev = calloc(1, sizeof(*dev));

	dev->ops = ops;
	dev->ctx = ctx;
	dev->channel = 1;
	*out = dev;
	return 0;
}

int xg_dev_start(struct xg_dev *dev)
{
	pthread_mutex_lock(&ap.lock);
	ap.dev = dev;
	dev->started = 1;
	pthread_mutex_unlock(&ap.lock);
	pthread_create(&dev->beacon_thread, NULL, beacon_main, dev);
	return 0;
}

void xg_dev_stop(struct xg_dev *dev)
{
	if (!dev->started)
		return;
	dev->stop = 1;
	pthread_join(dev->beacon_thread, NULL);
	pthread_mutex_lock(&ap.lock);
	dev->started = 0;
	ap.dev = NULL;
	pthread_mutex_unlock(&ap.lock);
}

void xg_dev_close(struct xg_dev *dev)
{
	xg_dev_stop(dev);
	free(dev);
}

const uint8_t *xg_dev_addr(const struct xg_dev *dev) { return sta_addr; }
const char *xg_dev_description(const struct xg_dev *dev) { return "clé simulée"; }
int xg_dev_max_channel(const struct xg_dev *dev) { return 13; }
const char *xg_dev_regdomain_name(const struct xg_dev *dev) { return "simulation"; }
int xg_dev_channel(const struct xg_dev *dev) { return dev->channel; }
int xg_dev_set_short_preamble(struct xg_dev *dev, int enabled) { return 0; }
void xg_dev_set_led(struct xg_dev *dev, enum xg_led state) { }
int xg_dev_tx_queue_len(struct xg_dev *dev) { return 0; }

int xg_dev_set_channel(struct xg_dev *dev, int channel)
{
	dev->channel = channel;
	return 0;
}

void xg_dev_get_stats(struct xg_dev *dev, struct xg_dev_stats *st)
{
	*st = dev->stats;
}

int xg_dev_tx(struct xg_dev *dev, const uint8_t *frame, size_t len, int rate,
	      unsigned int flags)
{
	dev->stats.tx_frames++;
	if (dev->channel != AP_CHANNEL || ap_off)
		return 0;
	pthread_mutex_lock(&ap.lock);
	ap_rx(frame, len);
	pthread_mutex_unlock(&ap.lock);
	return 0;
}

/* --- the test ----------------------------------------------------------- */

static struct ministack *stack;
static int link_events;

static void on_device(void *ctx, int present, const uint8_t *addr) { }

static void on_link(void *ctx, int up)
{
	link_events += up ? 1 : 100;
}

static void on_packet(void *ctx, const uint8_t *eth, size_t len)
{
	ministack_rx(stack, eth, len);
}

static const struct wlan_callbacks cbs = { on_device, on_link, on_packet };

/* Floods the station with damaged variants of frames it really received. */
static void fuzz(struct wlan *w, unsigned long count)
{
	struct xg_rx_info info = { .signal = 50, .rate = XG_RATE_1M };
	static uint8_t buf[4800];
	unsigned int slots = tap_count < TAP_SLOTS ? tap_count : TAP_SLOTS;
	struct wlan_status st;

	srandom(760);
	for (unsigned long i = 0; i < count; i++) {
		unsigned int k = (unsigned int)random() % slots;
		size_t len = tap[k].len;
		int op = (int)(random() % 8);

		memcpy(buf, tap[k].data, len);
		switch (op) {
		case 0: /* cut short */
			len = (size_t)random() % (len + 1);
			break;
		case 1: /* random tail, possibly far too long */
			len += (size_t)random() % 2600;
			if (len > sizeof(buf))
				len = sizeof(buf);
			for (size_t j = tap[k].len; j < len; j++)
				buf[j] = (uint8_t)random();
			break;
		case 2: /* pure noise */
			len = (size_t)random() % 300;
			for (size_t j = 0; j < len; j++)
				buf[j] = (uint8_t)random();
			break;
		default: /* a few flipped bytes, lengths and counts included */
			for (int n = 1 + (int)(random() % 6); n > 0 && len; n--)
				buf[(size_t)random() % len] = (uint8_t)random();
			if (op == 7 && len > 40)
				buf[24 + (size_t)random() % 16] = 0xff;
			break;
		}
		pthread_mutex_lock(&ap.lock);
		if (ap.dev)
			ap.dev->ops->rx(ap.dev->ctx, buf, len, &info);
		pthread_mutex_unlock(&ap.lock);
		/* let the station digest: its queue is bounded */
		if (i % 200 == 199)
			usleep(1500);
	}
	usleep(500 * 1000);
	wlan_get_status(w, &st);
	printf("      après %lu trames abimees: état « %s », %llu paquets acceptes, %llu rejets de déchiffrement\n",
	       count, wlan_state_name(st.state), st.rx_packets,
	       st.rx_crypt_errors);
}

#define CHECK(cond, text) \
	do { \
		if (cond) { \
			printf("ok    %s\n", text); \
		} else { \
			printf("ÉCHEC %s\n", text); \
			failures++; \
		} \
	} while (0)

int main(int argc, char **argv)
{
	const char *scenario = argc > 1 ? argv[1] : "ccmp";
	const char *pass = AP_PASS;
	struct wlan_network net;
	struct wlan_status st;
	struct wlan *w;
	int failures = 0, r, connected = 0;

	xg_log_level = argc > 2 ? atoi(argv[2]) : XG_LOG_WARN;
	pthread_mutex_init(&ap.lock, NULL);
	if (!strcmp(scenario, "tkip-group")) {
		group_cipher = XG_CIPHER_TKIP;
	} else if (!strcmp(scenario, "wpa2-tkip")) {
		pair_cipher = group_cipher = XG_CIPHER_TKIP;
	} else if (!strcmp(scenario, "wpa1")) {
		wpa1 = 1;
		pair_cipher = group_cipher = XG_CIPHER_TKIP;
	} else if (!strcmp(scenario, "open")) {
		secured = 0;
	} else if (!strcmp(scenario, "wrongpass")) {
		pass = "ce n'est pas la bonne phrase";
	} else if (strcmp(scenario, "ccmp") && strcmp(scenario, "fuzz") &&
		   strcmp(scenario, "scan") && strcmp(scenario, "panne") &&
		   strcmp(scenario, "deauth")) {
		fprintf(stderr, "scenario inconnu\n");
		return 2;
	}
	printf("=== scenario %s\n", scenario);
	wpa_passphrase_to_pmk(AP_PASS, (const uint8_t *)AP_SSID, strlen(AP_SSID),
			      ap.pmk);

	memset(&net, 0, sizeof(net));
	net.ssid_len = (uint8_t)strlen(AP_SSID);
	memcpy(net.ssid, AP_SSID, net.ssid_len);
	if (secured) {
		net.has_psk = 1;
		wpa_passphrase_to_pmk(pass, net.ssid, net.ssid_len, net.pmk);
	}

	stack = ministack_new(sta_addr);
	w = wlan_create(&cbs, NULL);
	ministack_attach(stack, w);
	wlan_wait_device(w, 5000);
	wlan_set_networks(w, &net, 1);

	for (int i = 0; i < 60 && !connected; i++) {
		usleep(250 * 1000);
		wlan_get_status(w, &st);
		connected = st.state == WLAN_CONNECTED;
		if (!strcmp(scenario, "wrongpass") &&
		    strstr(st.last_error, "refusé par"))
			break;
	}

	if (!strcmp(scenario, "wrongpass")) {
		wlan_get_status(w, &st);
		printf("      message: %s\n", st.last_error);
		CHECK(!connected, "pas de connexion avec une mauvaise phrase");
		CHECK(strstr(st.last_error, "mot de passe") != NULL,
		      "diagnostic « mot de passe » affiche");
		CHECK(ap.n_assoc <= 2,
		      "le pilote n'insiste pas au-delà de deux refus");
		CHECK(link_events == 0, "aucune liaison annoncée au système");
		goto done;
	}

	CHECK(connected, "connexion établie");
	if (!connected) {
		printf("      dernier message: %s\n", st.last_error);
		goto done;
	}
	CHECK(ap.n_probe > 0 && ap.n_auth == 1 && ap.n_assoc == 1,
	      "sonde, authentification et association reçues par le point d'accès");
	if (secured)
		CHECK(ap.n_msg2 == 1 && ap.n_msg4 == 1 && ap.n_bad_mic == 0,
		      "négociation des clés en 4 messages acceptée par le point d'accès");
	CHECK(link_events == 1, "liaison annoncée une fois au système");

	r = ministack_run(stack);
	CHECK(r == 0, "DHCP, ARP et ping à travers la liaison");
	if (!strcmp(scenario, "scan")) {
		static struct wlan_bss list[WLAN_MAX_BSS];
		int n = wlan_scan(w, list, WLAN_MAX_BSS);

		CHECK(n == 1 && list[0].ssid_len == strlen(AP_SSID),
		      "recherche pendant la connexion : le réseau est trouvé");
		wlan_get_status(w, &st);
		CHECK(st.state == WLAN_CONNECTED && link_events == 1,
		      "la connexion a survécu à la recherche");
		r = ministack_run(stack);
		CHECK(r == 0, "le trafic passe encore après la recherche");
		goto done;
	}
	if (!strcmp(scenario, "panne") || !strcmp(scenario, "deauth")) {
		int down = 0;

		if (!strcmp(scenario, "panne")) {
			ap_off = 1;
		} else {
			uint8_t d[26];

			pthread_mutex_lock(&ap.lock);
			hdr(d, FC_DEAUTH, sta_addr, bssid);
			put_le16(d + 24, REASON_DEAUTH_LEAVING);
			ap.state = 0;
			deliver(d, sizeof(d));
			pthread_mutex_unlock(&ap.lock);
		}
		for (int i = 0; i < 80 && !down; i++) {
			usleep(250 * 1000);
			down = link_events >= 100;
		}
		CHECK(down, "coupure détectée et annoncée au système");
		wlan_get_status(w, &st);
		printf("      message: %s\n", st.last_error);
		if (ap_off) {
			/* stays off for a while: the station must keep trying
			 * without giving up */
			sleep(6);
			wlan_get_status(w, &st);
			CHECK(st.state != WLAN_CONNECTED,
			      "pas de fausse connexion pendant la panne");
			ap_off = 0;
		}
		connected = 0;
		for (int i = 0; i < 160 && !connected; i++) {
			usleep(250 * 1000);
			wlan_get_status(w, &st);
			connected = st.state == WLAN_CONNECTED;
		}
		CHECK(connected, "reconnexion spontanée");
		CHECK(link_events == 102, "liaison de nouveau annoncée au système");
		r = ministack_run(stack);
		CHECK(r == 0, "le trafic passe de nouveau");
		goto done;
	}
	if (!strcmp(scenario, "fuzz")) {
		fuzz(w, 400000);
		/* whatever happened (the flood contains forged farewells),
		 * the station must come back to a working link by itself */
		connected = 0;
		for (int i = 0; i < 120 && !connected; i++) {
			usleep(250 * 1000);
			wlan_get_status(w, &st);
			connected = st.state == WLAN_CONNECTED;
		}
		CHECK(connected, "station toujours (ou de nouveau) connectee après le deluge");
		r = ministack_run(stack);
		CHECK(r == 0, "le trafic passe encore après le deluge");
		goto done;
	}
	CHECK(ap.n_dhcp >= 2, "découverte et demande DHCP reçues par le routeur");
	CHECK(ap.n_arp_reply >= 1,
	      "réponse de la station à une requête ARP diffusée (clé de groupe)");
	CHECK(ap.n_ping > 100, "trafic de charge reçu par le routeur");
	CHECK(ap.n_decrypt_fail == 0 && ap.n_clear_after_keys == 0,
	      "aucune trame en clair ni indéchiffrable après l'installation des clés");
	if (secured) {
		/* the group key was renewed during the load test: broadcasts
		 * must still get through */
		usleep(400 * 1000);
		CHECK(ap.n_group2 == (wpa1 ? 2u : 1u),
		      "renouvellement de la clé de groupe acquitté par la station");
		pthread_mutex_lock(&ap.lock);
		ap.n_arp_reply = 0;
		{
			uint8_t arp[28] = { 0, 1, 8, 0, 6, 4, 0, 1 };

			memcpy(arp + 8, bssid, 6);
			wr32(arp + 14, ROUTER_IP);
			wr32(arp + 24, LEASE_IP);
			send_data(bcast, bssid, 0x0806, arp, 28, 0);
		}
		pthread_mutex_unlock(&ap.lock);
		/* the stack only answers while somebody reads it */
		ministack_run(stack);
		CHECK(ap.n_arp_reply >= 1,
		      "diffusion chiffrée avec la nouvelle clé de groupe comprise");
	}
	wlan_get_status(w, &st);
	CHECK(st.rx_crypt_errors == 0, "aucune erreur de déchiffrement côté station");
	printf("      état final: %s, %llu paquets reçus, %llu émis\n",
	       wlan_state_name(st.state), st.rx_packets, st.tx_packets);

done:
	wlan_destroy(w);
	ministack_free(stack);
	printf("%s\n\n", failures ? "=== ÉCHEC" : "=== réussi");
	return failures ? 1 : 0;
}
