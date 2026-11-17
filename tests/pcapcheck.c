/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Checks the WPA code of the driver against a real-world capture.
 *
 * Reads a pcap/pcapng file of 802.11 traffic, replays every 4-way handshake
 * it contains through our own supplicant (src/wpa.c) and then decrypts the
 * data frames with the keys the supplicant installed (src/crypto.c). The
 * frames were produced by independent implementations, so success here
 * means interoperability, not just self-consistency.
 *
 * usage: pcapcheck <capture> <passphrase | 64 hex digits PSK> [ssid]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "crypto.h"
#include "ieee80211.h"
#include "wpa.h"

#define MAX_SESS 64
#define MAX_BSS 64

struct bss {
	uint8_t bssid[6];
	uint8_t ssid[32];
	uint8_t ssid_len;
};

struct session {
	uint8_t bssid[6], sta[6];
	uint8_t msg1[512];
	size_t msg1_len;
	uint8_t snonce[32];
	uint8_t ie[64];
	size_t ie_len;
	uint8_t msg2[512];
	size_t msg2_len;
	int have_msg1, have_msg2, keyed;
	struct wpa_sm sm;
	struct xg_key ptk_down, ptk_up, gtk[4];
	uint8_t sent[512];
	size_t sent_len;
	unsigned long ok_down, ok_up, ok_group, bad, replay, nokey;
	unsigned long llc_ok, llc_bad;
};

static struct bss bsses[MAX_BSS];
static int n_bss;
static struct session sessions[MAX_SESS];
static int n_sess;
static struct session *cur;
static const char *secret;
static const char *forced_ssid;
static unsigned long n_frames, n_handshakes, n_mic_ok, n_mic_bad;
static unsigned long n_identical_msg2, n_group_rekeys;

static int hex_psk(const char *s, uint8_t pmk[32])
{
	if (strlen(s) != 64)
		return -1;
	for (int i = 0; i < 32; i++) {
		unsigned int v;

		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			return -1;
		pmk[i] = (uint8_t)v;
	}
	return 0;
}

static struct bss *find_bss(const uint8_t *bssid)
{
	for (int i = 0; i < n_bss; i++)
		if (addr_equal(bsses[i].bssid, bssid))
			return &bsses[i];
	return NULL;
}

static struct session *find_session(const uint8_t *bssid, const uint8_t *sta,
				    int create)
{
	for (int i = 0; i < n_sess; i++)
		if (addr_equal(sessions[i].bssid, bssid) &&
		    addr_equal(sessions[i].sta, sta))
			return &sessions[i];
	if (!create || n_sess >= MAX_SESS)
		return NULL;
	memcpy(sessions[n_sess].bssid, bssid, 6);
	memcpy(sessions[n_sess].sta, sta, 6);
	return &sessions[n_sess++];
}

/* supplicant callbacks: capture what our code would send / install */
static int cb_send(void *ctx, const uint8_t *eapol, size_t len)
{
	struct session *s = ctx;

	if (len <= sizeof(s->sent)) {
		memcpy(s->sent, eapol, len);
		s->sent_len = len;
	}
	return 0;
}

static int cb_set_key(void *ctx, int pairwise, int idx, enum xg_cipher cipher,
		      const uint8_t *key, size_t len, const uint8_t *rsc)
{
	struct session *s = ctx;

	if (pairwise) {
		uint8_t swapped[32];

		xg_key_set(&s->ptk_down, cipher, 0, key, len, NULL);
		/* the uplink direction uses the two Michael keys swapped */
		memcpy(swapped, key, len);
		if (cipher == XG_CIPHER_TKIP) {
			memcpy(swapped + 16, key + 24, 8);
			memcpy(swapped + 24, key + 16, 8);
		}
		xg_key_set(&s->ptk_up, cipher, 0, swapped, len, NULL);
		printf("    clé de session installée (%s)\n",
		       cipher == XG_CIPHER_CCMP ? "CCMP" : "TKIP");
	} else {
		/* rsc ignored: a capture may start after later frames */
		xg_key_set(&s->gtk[idx & 3], cipher, idx & 3, key, len, NULL);
		printf("    clé de groupe %d installée (%s)\n", idx,
		       cipher == XG_CIPHER_CCMP ? "CCMP" : "TKIP");
	}
	(void)rsc;
	return 0;
}

static void cb_completed(void *ctx)
{
	struct session *s = ctx;

	s->keyed = 1;
	printf("    négociation terminée par notre supplicant\n");
}

static void cb_failed(void *ctx, const char *text)
{
	(void)ctx;
	printf("    ÉCHEC du supplicant: %s\n", text);
}

static const struct wpa_callbacks cbs = {
	.send_eapol = cb_send,
	.set_key = cb_set_key,
	.completed = cb_completed,
	.failed = cb_failed,
};

static int check_mic(const uint8_t *kck, const uint8_t *eapol, size_t len)
{
	uint8_t tmp[1024], mac[20];
	int ver = get_be16(eapol + 5) & 7;

	if (len > sizeof(tmp))
		return -1;
	memcpy(tmp, eapol, len);
	memset(tmp + 81, 0, 16);
	if (ver == 1)
		hmac_md5(kck, 16, tmp, len, mac);
	else
		hmac_sha1(kck, 16, tmp, len, mac);
	return memcmp(mac, eapol + 81, 16) == 0 ? 0 : -1;
}

/* parses the WPA/RSN element a station put in message 2 */
static int parse_sta_ie(const uint8_t *ie, size_t len, struct wpa_params *p)
{
	const uint8_t *d;

	if (len < 2 || (size_t)ie[1] + 2 > len)
		return -1;
	if (ie[0] == IE_RSN && ie[1] >= 12) {
		d = ie + 2;
		p->proto = WPA_PROTO_RSN;
	} else if (ie[0] == IE_VENDOR && ie[1] >= 16) {
		d = ie + 6;
		p->proto = WPA_PROTO_WPA;
	} else {
		return -1;
	}
	/* version(2) group(4) count(2) pairwise(4) */
	p->group = d[5] == 4 ? XG_CIPHER_CCMP : XG_CIPHER_TKIP;
	p->pairwise = d[11] == 4 ? XG_CIPHER_CCMP : XG_CIPHER_TKIP;
	return 0;
}

static void run_handshake(struct session *s, const uint8_t *msg3, size_t len)
{
	struct wpa_params p;
	struct bss *b = find_bss(s->bssid);
	uint8_t ssid[32];
	size_t ssid_len = 0;

	memset(&p, 0, sizeof(p));
	if (parse_sta_ie(s->ie, s->ie_len, &p)) {
		printf("    élément WPA/RSN du message 2 illisible\n");
		return;
	}
	if (forced_ssid) {
		ssid_len = strlen(forced_ssid);
		memcpy(ssid, forced_ssid, ssid_len);
	} else if (b) {
		ssid_len = b->ssid_len;
		memcpy(ssid, b->ssid, ssid_len);
	}
	if (hex_psk(secret, p.pmk) &&
	    wpa_passphrase_to_pmk(secret, ssid, ssid_len, p.pmk)) {
		printf("    phrase secrète invalide\n");
		return;
	}
	memcpy(p.own_addr, s->sta, 6);
	memcpy(p.bssid, s->bssid, 6);
	memcpy(p.own_ie, s->ie, s->ie_len);
	p.own_ie_len = s->ie_len;

	n_handshakes++;
	printf("  négociation %02x:%02x:%02x:%02x:%02x:%02x <-> station %02x:%02x:%02x:%02x:%02x:%02x (%s, \"%.*s\")\n",
	       s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4],
	       s->bssid[5], s->sta[0], s->sta[1], s->sta[2], s->sta[3],
	       s->sta[4], s->sta[5],
	       p.proto == WPA_PROTO_RSN ? "WPA2" : "WPA", (int)ssid_len, ssid);

	xg_key_clear(&s->ptk_down);
	xg_key_clear(&s->ptk_up);
	wpa_sm_init(&s->sm, &cbs, s);
	wpa_sm_start(&s->sm, &p);
	/* play the part of the captured station: same SNonce */
	memcpy(s->sm.snonce, s->snonce, 32);

	s->sent_len = 0;
	wpa_sm_rx_eapol(&s->sm, s->msg1, s->msg1_len);
	if (!s->sm.have_tptk) {
		printf("    message 1/4 non accepté\n");
		return;
	}
	if (check_mic(s->sm.tptk, s->msg2, s->msg2_len) == 0) {
		n_mic_ok++;
		printf("    MIC du message 2/4 capture: valide avec notre PTK\n");
	} else {
		n_mic_bad++;
		printf("    MIC du message 2/4 capture: INVALIDE (mauvaise phrase ?)\n");
		return;
	}
	if (s->sent_len == s->msg2_len &&
	    memcmp(s->sent, s->msg2, s->msg2_len) == 0) {
		n_identical_msg2++;
		printf("    notre message 2/4 est identique, octet pour octet, à celui de la capture\n");
	} else if (s->sent_len == s->msg2_len && s->msg2_len > 1 &&
		   memcmp(s->sent + 1, s->msg2 + 1, 80) == 0) {
		printf("    notre message 2/4 ne diffère que par le numéro de version 802.1X\n");
	}

	s->keyed = 0;
	wpa_sm_rx_eapol(&s->sm, msg3, len);
}

static void handle_eapol(const uint8_t *bssid, const uint8_t *sta, int from_ap,
			 const uint8_t *e, size_t len)
{
	struct session *s;
	uint16_t info;
	size_t body;

	if (len < 99 || e[1] != 3)
		return;
	body = get_be16(e + 2);
	if (4 + body > len)
		return;
	len = 4 + body;
	info = get_be16(e + 5);
	s = find_session(bssid, sta, 1);
	if (!s)
		return;
	cur = s;

	if (from_ap) {
		if (!(info & 0x0008)) {
			/* group key handshake */
			if (s->keyed) {
				n_group_rekeys++;
				wpa_sm_rx_eapol(&s->sm, e, len);
			}
			return;
		}
		if (!(info & 0x0100)) { /* message 1 */
			if (len <= sizeof(s->msg1)) {
				memcpy(s->msg1, e, len);
				s->msg1_len = len;
				s->have_msg1 = 1;
				s->have_msg2 = 0;
			}
		} else if (s->have_msg1 && s->have_msg2) { /* message 3 */
			run_handshake(s, e, len);
			s->have_msg1 = s->have_msg2 = 0;
		}
	} else {
		uint16_t dlen = get_be16(e + 97);

		if ((info & 0x0008) && (info & 0x0100) && dlen > 0 &&
		    dlen <= sizeof(s->ie) && s->have_msg1) { /* message 2 */
			memcpy(s->snonce, e + 17, 32);
			memcpy(s->ie, e + 99, dlen);
			s->ie_len = dlen;
			if (len <= sizeof(s->msg2)) {
				memcpy(s->msg2, e, len);
				s->msg2_len = len;
				s->have_msg2 = 1;
			}
		} else if ((info & 0x0008) && (info & 0x0100) && dlen == 0 &&
			   s->keyed) { /* message 4 */
			if (check_mic(s->sm.ptk, e, len) == 0) {
				n_mic_ok++;
				printf("    MIC du message 4/4 capture: valide\n");
			} else {
				n_mic_bad++;
				printf("    MIC du message 4/4 capture: INVALIDE\n");
			}
		}
	}
}

static void handle_frame(const uint8_t *f, size_t len)
{
	uint8_t plain[4096];
	uint16_t fc;
	size_t hdr_len = 24;
	const uint8_t *bssid, *sta, *body;
	size_t blen;
	int from_ap, group;
	struct session *s;

	if (len < 24)
		return;
	n_frames++;
	fc = get_le16(f);

	if ((fc & FC_TYPE_MASK) == FC_TYPE_MGMT) {
		uint16_t st = fc & (FC_TYPE_MASK | FC_SUBTYPE_MASK);

		if ((st == FC_BEACON || st == FC_PROBE_RESP) && len > 38 &&
		    !find_bss(f + 16) && n_bss < MAX_BSS && f[36] == IE_SSID &&
		    f[37] <= 32 && 38u + f[37] <= len && f[37] > 0 && f[38]) {
			struct bss *b = &bsses[n_bss++];

			memcpy(b->bssid, f + 16, 6);
			b->ssid_len = f[37];
			memcpy(b->ssid, f + 38, f[37]);
		}
		return;
	}
	if ((fc & FC_TYPE_MASK) != FC_TYPE_DATA || (fc & FC_STYPE_DATA_NODATA))
		return;
	switch (fc & (FC_TODS | FC_FROMDS)) {
	case FC_FROMDS:
		bssid = f + 10;
		sta = f + 4;
		from_ap = 1;
		break;
	case FC_TODS:
		bssid = f + 4;
		sta = f + 10;
		from_ap = 0;
		break;
	default:
		return;
	}
	if (fc & FC_STYPE_DATA_QOS)
		hdr_len += 2;
	if (len <= hdr_len)
		return;
	body = f + hdr_len;
	blen = len - hdr_len;
	group = from_ap && addr_is_group(sta);

	if (!(fc & FC_PROTECTED)) {
		if (blen > 8 && body[0] == 0xaa && body[1] == 0xaa &&
		    get_be16(body + 6) == ETHERTYPE_EAPOL && !group)
			handle_eapol(bssid, sta, from_ap, body + 8, blen - 8);
		return;
	}
	if (fc & (FC_MOREFRAG) || (f[22] & 0x0f))
		return;

	if (group) {
		/* try the group keys of every keyed session of this BSS */
		int idx = xg_frame_key_idx(body, blen), done = 0;

		for (int i = 0; i < n_sess && !done; i++) {
			int n;

			s = &sessions[i];
			if (!addr_equal(s->bssid, bssid) || idx < 0 ||
			    s->gtk[idx].cipher == XG_CIPHER_NONE)
				continue;
			n = xg_decrypt(&s->gtk[idx], f, hdr_len, body, blen,
				       plain);
			if (n >= 0) {
				s->ok_group++;
				if (n >= 3 && plain[0] == 0xaa && plain[1] == 0xaa)
					s->llc_ok++;
				else if (s->llc_bad++ == 0)
					printf("    trame authentique sans en-tête SNAP, début %02x %02x %02x %02x %02x %02x (%d octets)\n",
					       plain[0], plain[1], plain[2], plain[3],
					       plain[4], plain[5], n);
				done = 1;
			} else if (n == -3) {
				s->replay++;
				done = 1;
			} else {
				s->bad++;
			}
		}
		return;
	}

	s = find_session(bssid, sta, 0);
	if (!s || !s->keyed) {
		if (s)
			s->nokey++;
		return;
	}
	{
		struct xg_key *k = from_ap ? &s->ptk_down : &s->ptk_up;
		int n = xg_decrypt(k, f, hdr_len, body, blen, plain);

		if (n >= 0) {
			if (from_ap)
				s->ok_down++;
			else
				s->ok_up++;
			if (n >= 3 && plain[0] == 0xaa && plain[1] == 0xaa) {
				s->llc_ok++;
				/* encrypted EAPOL: rekeying */
				if (n > 8 && get_be16(plain + 6) == ETHERTYPE_EAPOL)
					handle_eapol(bssid, sta, from_ap,
						     plain + 8, (size_t)n - 8);
			} else {
				s->llc_bad++;
			}
		} else if (n == -3) {
			s->replay++;
		} else {
			s->bad++;
		}
	}
}

/* strips the radiotap header; returns 0 if the frame is usable */
static int strip_radiotap(const uint8_t **pp, size_t *plen)
{
	const uint8_t *p = *pp;
	size_t len = *plen, rt_len, off = 4;
	uint32_t present;
	uint8_t flags = 0;

	if (len < 8)
		return -1;
	rt_len = get_le16(p + 2);
	if (rt_len > len)
		return -1;
	present = (uint32_t)p[4] | ((uint32_t)p[5] << 8) |
		  ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
	while (off + 4 <= rt_len) {
		uint32_t w = (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
			     ((uint32_t)p[off + 2] << 16) |
			     ((uint32_t)p[off + 3] << 24);

		off += 4;
		if (!(w & 0x80000000u))
			break;
	}
	if (present & 1)
		off = ((off + 7) & ~(size_t)7) + 8; /* TSFT */
	if ((present & 2) && off < rt_len)
		flags = p[off];
	if (flags & 0x40)
		return -1; /* bad FCS */
	*pp = p + rt_len;
	*plen = len - rt_len;
	if ((flags & 0x10) && *plen >= 4)
		*plen -= 4; /* FCS at the end */
	return 0;
}

static void handle_packet(int linktype, const uint8_t *p, size_t len)
{
	if (linktype == 127) {
		if (strip_radiotap(&p, &len))
			return;
	} else if (linktype != 105) {
		return;
	}
	handle_frame(p, len);
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv)
{
	uint8_t *data;
	long size;
	size_t pos;
	FILE *fp;
	int rc = 0;

	if (argc < 3) {
		fprintf(stderr, "usage: pcapcheck <capture> <phrase | PSK hex> [ssid]\n");
		return 2;
	}
	secret = argv[2];
	forced_ssid = argc > 3 ? argv[3] : NULL;
	xg_log_level = XG_LOG_WARN;

	fp = fopen(argv[1], "rb");
	if (!fp) {
		perror(argv[1]);
		return 2;
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	data = malloc((size_t)size);
	if (!data || fread(data, 1, (size_t)size, fp) != (size_t)size) {
		fprintf(stderr, "lecture impossible\n");
		return 2;
	}
	fclose(fp);

	printf("%s\n", argv[1]);
	if (size >= 24 && rd32(data) == 0xa1b2c3d4) {
		int linktype = (int)rd32(data + 20);

		pos = 24;
		while (pos + 16 <= (size_t)size) {
			uint32_t incl = rd32(data + pos + 8);

			pos += 16;
			if (pos + incl > (size_t)size)
				break;
			handle_packet(linktype, data + pos, incl);
			pos += incl;
		}
	} else if (size >= 12 && rd32(data) == 0x0a0d0d0a) {
		int linktypes[16] = { 0 };
		int n_if = 0;

		pos = 0;
		while (pos + 12 <= (size_t)size) {
			uint32_t type = rd32(data + pos);
			uint32_t blen = rd32(data + pos + 4);

			if (blen < 12 || pos + blen > (size_t)size)
				break;
			if (type == 1 && n_if < 16) {
				linktypes[n_if++] = data[pos + 8] |
						    (data[pos + 9] << 8);
			} else if (type == 6 && blen >= 32) {
				uint32_t ifid = rd32(data + pos + 8);
				uint32_t cap = rd32(data + pos + 20);

				if (ifid < 16 && 28 + cap <= blen)
					handle_packet(linktypes[ifid],
						      data + pos + 28, cap);
			}
			pos += blen;
		}
	} else {
		fprintf(stderr, "format de capture inconnu\n");
		return 2;
	}

	printf("  %lu trames, %lu négociations rejouées, MIC valides %lu / invalides %lu, messages 2/4 identiques %lu, renouvellements de groupe %lu\n",
	       n_frames, n_handshakes, n_mic_ok, n_mic_bad, n_identical_msg2,
	       n_group_rekeys);
	for (int i = 0; i < n_sess; i++) {
		struct session *s = &sessions[i];

		if (!s->ok_down && !s->ok_up && !s->ok_group && !s->bad)
			continue;
		printf("  station %02x:%02x:%02x:%02x:%02x:%02x: déchiffrées montantes %lu, descendantes %lu, diffusion %lu | échecs %lu, doublons %lu | trames SNAP %lu, autres LLC (ex. spanning tree) %lu\n",
		       s->sta[0], s->sta[1], s->sta[2], s->sta[3], s->sta[4],
		       s->sta[5], s->ok_up, s->ok_down, s->ok_group, s->bad,
		       s->replay, s->llc_ok, s->llc_bad);
		if (s->bad > (s->ok_up + s->ok_down + s->ok_group) / 20)
			rc = 1;
	}
	if (n_mic_bad || !n_handshakes)
		rc = 1;
	printf("  => %s\n", rc ? "PROBLÈME" : "conforme");
	(void)cur;
	return rc;
}
