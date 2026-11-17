/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * 802.11 station (infrastructure client) in user space.
 *
 * In the Linux driver this job is done by the kernel's mac80211 stack and
 * by wpa_supplicant. Here it is a compact state machine run by one thread:
 *
 *   no device -> idle -> scanning -> authenticating -> associating
 *             -> WPA handshake -> connected
 *
 * Events (received frames, transmit reports, packets from the host) reach
 * that thread through a queue; timers are handled by polling the clock.
 */
#include "wlan.h"

#include <stdarg.h>
#include <time.h>

#include "compat.h"
#include "crypto.h"
#include "device.h"
#include "ieee80211.h"
#include "wpa.h"

#define SCAN_DWELL_MS 110
#define AUTH_TIMEOUT_MS 300
#define ASSOC_TIMEOUT_MS 400
#define JOIN_TRIES 4
#define HANDSHAKE_TIMEOUT_MS 8000
#define BEACON_PROBE_MS 3000
#define BEACON_LOST_MS 8000
#define KEEPALIVE_MS 30000
#define BSS_EXPIRE_MS 60000
#define DEVICE_RETRY_MS 2000
#define MAX_EVENTS 1024
#define MAX_HOST_EVENTS 256
#define WRONG_PSK_LIMIT 2

enum { EV_RX, EV_TX_REPORT, EV_HOST_PKT, EV_GONE };

struct event {
	struct event *next;
	int type;
	int gen;
	int a, b, c;
	size_t len;
	uint8_t data[];
};

struct rate_ctl {
	int ladder[XG_N_RATES];	/* usable rates, slowest first */
	int n;
	int pos;		/* current position in the ladder */
	int sent, bad, failed;
	int final_sum, final_n;	/* where retried frames ended up */
	uint64_t window_start;
	int good_windows, up_threshold, probing;
};

struct wlan {
	const struct wlan_callbacks *cb;
	void *ctx;

	pthread_t thread;
	int thread_started;
	int quit;
	pthread_mutex_t lock;		/* protects everything below... */
	pthread_cond_t state_cond;
	pthread_mutex_t q_lock;		/* ...except the event queue */
	pthread_cond_t q_cond;
	struct event *q_head, *q_tail;
	int q_len, q_host_len;

	struct xg_dev *dev;
	int dev_gen;
	int dev_missing_logged;
	int dev_errors;		/* consecutive failed commands to the stick */
	int suspended;		/* the Mac is going to sleep: stick released */
	uint64_t next_dev_try;

	enum wlan_state state;
	uint64_t state_deadline;
	int tries;
	uint64_t next_connect_try;
	int backoff;

	struct wlan_network nets[WLAN_MAX_NETWORKS];
	int n_nets;
	int nets_changed;
	struct wlan_network cur_net;
	/* consecutive "wrong password" verdicts per known network */
	int psk_failures[WLAN_MAX_NETWORKS];

	struct wlan_bss table[WLAN_MAX_BSS];
	int n_bss;
	int scan_request;
	unsigned int scan_gen;
	int scanning;
	int scan_chan;
	int scan_while_connected;
	uint64_t scan_started;
	uint64_t scan_deadline;
	unsigned int probe_resp_to_us;

	struct wlan_bss bss;
	uint16_t aid;
	uint16_t seq;
	int secured;
	enum wpa_proto proto;
	enum xg_cipher pairwise, group;
	uint8_t own_ie[64];
	size_t own_ie_len;
	struct wpa_sm wpa;
	int port_open;
	struct xg_key ptk;
	struct xg_key gtk[4];
	int short_preamble, use_protection;
	int mgmt_rate;
	struct rate_ctl rc;
	uint64_t last_beacon, last_tx, connected_since;
	int probing_ap;
	int signal_avg;
	int rx_rate;
	uint16_t last_seq[17];
	char last_error[160];

	/* read by the USB thread without the lock: only an optimisation */
	volatile int filter_active;
	uint8_t filter_bssid[6];
	volatile int listening;	/* 0: idle, received frames are of no use */
	long wait_ms;		/* how long the station thread may sleep */

	uint64_t rx_packets, tx_packets, rx_dropped, tx_dropped;
	uint64_t rx_crypt_errors;
};

static const uint8_t bcast_addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const int backoff_ms[] = { 500, 2000, 5000, 10000, 20000, 30000 };

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

const char *wlan_state_name(enum wlan_state s)
{
	switch (s) {
	case WLAN_NO_DEVICE:
		return "clé absente";
	case WLAN_IDLE:
		return "non connecté";
	case WLAN_SCANNING:
		return "recherche des réseaux";
	case WLAN_AUTHENTICATING:
		return "authentification";
	case WLAN_ASSOCIATING:
		return "association";
	case WLAN_HANDSHAKE:
		return "négociation des clés";
	case WLAN_CONNECTED:
		return "connecté";
	}
	return "?";
}

static void set_state(struct wlan *w, enum wlan_state s)
{
	if (w->state != s) {
		xg_log(XG_LOG_DBG, "état: %s -> %s\n", wlan_state_name(w->state),
		       wlan_state_name(s));
		w->state = s;
	}
	pthread_cond_broadcast(&w->state_cond);
}

static void set_error(struct wlan *w, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void set_error(struct wlan *w, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(w->last_error, sizeof(w->last_error), fmt, ap);
	va_end(ap);
	xg_log(XG_LOG_WARN, "%s\n", w->last_error);
}

static void ssid_text(const uint8_t *ssid, size_t len, char *out, size_t max)
{
	size_t n = 0;

	for (size_t i = 0; i < len && n + 1 < max; i++)
		out[n++] = (ssid[i] >= 0x20 && ssid[i] != 0x7f) ? (char)ssid[i] :
								  '?';
	out[n] = 0;
}

/* --- event queue -------------------------------------------------------- */

static int post_event(struct wlan *w, int type, const void *data, size_t len,
		      int a, int b, int c)
{
	struct event *e;

	pthread_mutex_lock(&w->q_lock);
	if (w->quit || w->q_len >= MAX_EVENTS ||
	    (type == EV_HOST_PKT && w->q_host_len >= MAX_HOST_EVENTS)) {
		pthread_mutex_unlock(&w->q_lock);
		return -ENOBUFS;
	}
	pthread_mutex_unlock(&w->q_lock);

	e = malloc(sizeof(*e) + len);
	if (!e)
		return -ENOMEM;
	e->next = NULL;
	e->type = type;
	e->gen = w->dev_gen;
	e->a = a;
	e->b = b;
	e->c = c;
	e->len = len;
	if (len)
		memcpy(e->data, data, len);

	pthread_mutex_lock(&w->q_lock);
	if (w->q_tail)
		w->q_tail->next = e;
	else
		w->q_head = e;
	w->q_tail = e;
	w->q_len++;
	if (type == EV_HOST_PKT)
		w->q_host_len++;
	pthread_cond_signal(&w->q_cond);
	pthread_mutex_unlock(&w->q_lock);
	return 0;
}

static void kick(struct wlan *w)
{
	pthread_mutex_lock(&w->q_lock);
	pthread_cond_signal(&w->q_cond);
	pthread_mutex_unlock(&w->q_lock);
}

/* --- callbacks from the device (USB event thread) ----------------------- */

static void dev_rx(void *ctx, const uint8_t *frame, size_t len,
		   const struct xg_rx_info *info)
{
	struct wlan *w = ctx;
	uint16_t fc;

	/* Nothing legitimate is longer than a header and a full frame body;
	 * the buffers further down rely on this bound. */
	if (len < IEEE80211_HDR_LEN ||
	    len > IEEE80211_HDR_LEN + 2 + IEEE80211_MAX_FRAME_LEN)
		return;
	if (!w->listening)
		return; /* not scanning, not joining, not connected */
	fc = get_le16(frame);
	if ((fc & FC_TYPE_MASK) == FC_TYPE_CTRL)
		return;
	if ((fc & FC_TYPE_MASK) == FC_TYPE_MGMT && w->filter_active) {
		uint16_t st = fc & (FC_TYPE_MASK | FC_SUBTYPE_MASK);

		/* connected and not scanning: the neighbours' beacons are
		 * of no interest */
		if ((st == FC_BEACON || st == FC_PROBE_RESP) &&
		    memcmp(frame + 16, w->filter_bssid, 6) != 0)
			return;
	}
	post_event(w, EV_RX, frame, len, info->signal, info->rate, 0);
}

static void dev_tx_report(void *ctx, const uint8_t *dest, int final_rate,
			  int retries, int failed)
{
	post_event(ctx, EV_TX_REPORT, dest, 6, final_rate, retries, failed);
}

static void dev_gone(void *ctx)
{
	post_event(ctx, EV_GONE, NULL, 0, 0, 0, 0);
}

static const struct xg_dev_ops dev_ops = {
	.rx = dev_rx,
	.tx_report = dev_tx_report,
	.gone = dev_gone,
};

/* --- frame transmission ------------------------------------------------- */

static void fill_hdr(struct wlan *w, uint8_t *f, uint16_t fc, const uint8_t *a1,
		     const uint8_t *a2, const uint8_t *a3)
{
	put_le16(f, fc);
	f[2] = f[3] = 0;
	memcpy(f + 4, a1, 6);
	memcpy(f + 10, a2, 6);
	memcpy(f + 16, a3, 6);
	put_le16(f + 22, (uint16_t)((w->seq++ & 0x0fff) << 4));
}

static int tx_frame(struct wlan *w, const uint8_t *f, size_t len, int rate,
		    unsigned int flags)
{
	int r;

	if (!w->dev)
		return -ENODEV;
	if (w->short_preamble)
		flags |= XG_TX_SHORT_PREAMBLE;
	if (w->use_protection)
		flags |= XG_TX_CTS_PROTECT;
	if (addr_is_group(f + 4))
		flags |= XG_TX_NO_ACK;
	r = xg_dev_tx(w->dev, f, len, rate, flags);
	if (r == 0)
		w->last_tx = now_ms();
	return r;
}

static size_t add_rates_ies(uint8_t *p)
{
	static const uint8_t rates[] = { IE_SUPP_RATES, 8, 0x02, 0x04, 0x0b,
					 0x16, 0x0c, 0x12, 0x18, 0x24,
					 IE_EXT_SUPP_RATES, 4, 0x30, 0x48,
					 0x60, 0x6c };

	memcpy(p, rates, sizeof(rates));
	return sizeof(rates);
}

static void send_probe_req(struct wlan *w, const uint8_t *dest,
			   const uint8_t *ssid, size_t ssid_len)
{
	uint8_t f[128];
	uint8_t *p = f + IEEE80211_HDR_LEN;

	fill_hdr(w, f, FC_PROBE_REQ, dest, xg_dev_addr(w->dev), dest);
	*p++ = IE_SSID;
	*p++ = (uint8_t)ssid_len;
	if (ssid_len)
		memcpy(p, ssid, ssid_len);
	p += ssid_len;
	p += add_rates_ies(p);
	*p++ = IE_DS_PARAMS;
	*p++ = 1;
	*p++ = (uint8_t)xg_dev_channel(w->dev);
	tx_frame(w, f, (size_t)(p - f), XG_RATE_1M, XG_TX_URGENT);
}

static void send_auth(struct wlan *w)
{
	uint8_t f[IEEE80211_HDR_LEN + 6];

	fill_hdr(w, f, FC_AUTH, w->bss.bssid, xg_dev_addr(w->dev), w->bss.bssid);
	put_le16(f + 24, 0); /* open system */
	put_le16(f + 26, 1); /* transaction 1 */
	put_le16(f + 28, 0);
	tx_frame(w, f, sizeof(f), w->mgmt_rate, XG_TX_URGENT);
}

static void send_assoc_req(struct wlan *w)
{
	uint8_t f[256];
	uint8_t *p = f + IEEE80211_HDR_LEN;
	uint16_t capab = CAP_ESS;

	fill_hdr(w, f, FC_ASSOC_REQ, w->bss.bssid, xg_dev_addr(w->dev),
		 w->bss.bssid);
	if (w->secured)
		capab |= CAP_PRIVACY;
	/* like mac80211: a 2.4 GHz station always announces both, so that
	 * the cell is not forced back to long slots and long preambles */
	capab |= CAP_SHORT_SLOT | CAP_SHORT_PREAMBLE;
	put_le16(p, capab);
	put_le16(p + 2, 5); /* listen interval; we never sleep anyway */
	p += 4;
	*p++ = IE_SSID;
	*p++ = w->bss.ssid_len;
	memcpy(p, w->bss.ssid, w->bss.ssid_len);
	p += w->bss.ssid_len;
	p += add_rates_ies(p);
	if (w->own_ie_len) {
		memcpy(p, w->own_ie, w->own_ie_len);
		p += w->own_ie_len;
	}
	tx_frame(w, f, (size_t)(p - f), w->mgmt_rate, XG_TX_URGENT);
}

static void send_deauth(struct wlan *w, uint16_t reason)
{
	uint8_t f[IEEE80211_HDR_LEN + 2];

	fill_hdr(w, f, FC_DEAUTH, w->bss.bssid, xg_dev_addr(w->dev),
		 w->bss.bssid);
	put_le16(f + 24, reason);
	tx_frame(w, f, sizeof(f), w->mgmt_rate, XG_TX_URGENT);
}

static void send_nullfunc(struct wlan *w, int power_save)
{
	uint8_t f[IEEE80211_HDR_LEN];

	fill_hdr(w, f,
		 (uint16_t)(FC_NULLFUNC | FC_TODS | (power_save ? FC_PWRMGT : 0)),
		 w->bss.bssid, xg_dev_addr(w->dev), w->bss.bssid);
	tx_frame(w, f, sizeof(f), w->mgmt_rate, XG_TX_URGENT);
}

/* Sends an Ethernet-style payload to the distribution system. */
static int send_data(struct wlan *w, const uint8_t *da, const uint8_t *sa,
		     uint16_t ethertype, const uint8_t *payload, size_t len,
		     int is_eapol)
{
	uint8_t body[IEEE80211_MAX_FRAME_LEN];
	uint8_t f[IEEE80211_HDR_LEN + IEEE80211_MAX_FRAME_LEN +
		  XG_CRYPT_OVERHEAD];
	size_t blen = 0;
	uint16_t fc = FC_DATA | FC_TODS;
	int protect = w->ptk.cipher != XG_CIPHER_NONE;
	int rate;
	int n;

	if (len > 2304 - 8)
		return -EMSGSIZE;
	if (ethertype >= 0x0600) {
		/* RFC 1042 encapsulation (bridge tunnel for AppleTalk ARP
		 * and IPX, as IEEE 802.1H requires) */
		static const uint8_t rfc1042[6] = { 0xaa, 0xaa, 0x03,
						    0x00, 0x00, 0x00 };

		memcpy(body, rfc1042, 6);
		if (ethertype == 0x80f3 || ethertype == 0x8137)
			body[5] = 0xf8;
		put_be16(body + 6, ethertype);
		blen = 8;
	}
	memcpy(body + blen, payload, len);
	blen += len;

	if (protect)
		fc |= FC_PROTECTED;
	fill_hdr(w, f, fc, w->bss.bssid, sa, da);
	if (protect) {
		n = xg_encrypt(&w->ptk, f, IEEE80211_HDR_LEN, body, blen,
			       f + IEEE80211_HDR_LEN);
		if (n < 0)
			return -EIO;
		blen = (size_t)n;
	} else {
		memcpy(f + IEEE80211_HDR_LEN, body, blen);
	}

	rate = is_eapol ? w->mgmt_rate : w->rc.ladder[w->rc.pos];
	n = tx_frame(w, f, IEEE80211_HDR_LEN + blen, rate,
		     is_eapol ? XG_TX_URGENT : 0);
	if (n == 0 && !is_eapol)
		w->rc.sent++;
	return n;
}

/* --- rate control ------------------------------------------------------- */

/*
 * The chip retries by itself, stepping down through slower rates, and
 * reports every frame that needed it. Per window of frames we look at the
 * share of such reports: mostly clean -> try the next faster rate after a
 * while; many retries or losses -> one step slower. A failed attempt at a
 * faster rate doubles the wait before the next one.
 */
static void rc_init(struct wlan *w, uint16_t mask, int signal)
{
	static const int by_speed[XG_N_RATES] = { 0, 1, 2, 4, 5, 3,
						  6, 7, 8, 9, 10, 11 };
	struct rate_ctl *rc = &w->rc;
	int has_11 = mask & (1 << XG_RATE_11M);
	int want;

	memset(rc, 0, sizeof(*rc));
	if (!mask)
		mask = 0x000f;
	for (int i = 0; i < XG_N_RATES; i++) {
		int idx = by_speed[i];

		if (!(mask & (1 << idx)))
			continue;
		/* 6 and 9 Mbit/s bring nothing over 5.5 and 11 */
		if (has_11 && (idx == 4 || idx == 5))
			continue;
		rc->ladder[rc->n++] = idx;
	}
	/* a sensible start for the signal level; it adapts from there */
	want = signal >= 50 ? 72 : signal >= 35 ? 48 : signal >= 25 ? 22 : 4;
	for (int i = 0; i < rc->n; i++)
		if (xg_rates[rc->ladder[i]].ieee <= want)
			rc->pos = i;
	rc->up_threshold = 2;
	rc->window_start = now_ms();
}

static void rc_tick(struct wlan *w, uint64_t now)
{
	struct rate_ctl *rc = &w->rc;
	uint64_t age = now - rc->window_start;
	int old = rc->pos;

	if (rc->sent < 40 && !(age >= 500 && rc->sent >= 10)) {
		if (age >= 5000) {
			/* idle link: forget stale counts */
			rc->sent = rc->bad = rc->failed = 0;
			rc->final_sum = rc->final_n = 0;
			rc->window_start = now;
		}
		return;
	}

	if (rc->failed * 10 >= rc->sent || rc->bad * 100 >= rc->sent * 40) {
		if (rc->pos > 0)
			rc->pos--;
		/* the chip tells at which rate the retried frames finally got
		 * through: go straight there instead of one step at a time */
		if (rc->final_n > 0 && rc->final_sum / rc->final_n < rc->pos)
			rc->pos = rc->final_sum / rc->final_n;
		if (rc->probing && rc->up_threshold < 32)
			rc->up_threshold *= 2;
		rc->probing = 0;
		rc->good_windows = 0;
	} else if (rc->bad * 100 <= rc->sent * 10) {
		if (rc->probing) {
			rc->probing = 0;
			rc->up_threshold = 2;
		}
		if (++rc->good_windows >= rc->up_threshold &&
		    rc->pos < rc->n - 1) {
			rc->pos++;
			rc->probing = 1;
			rc->good_windows = 0;
		}
	} else {
		rc->probing = 0;
		rc->good_windows = 0;
	}
	if (rc->pos != old)
		xg_log(XG_LOG_DBG,
		       "débit d'émission: %g -> %g Mbit/s (%d trames, %d reprises, %d pertes)\n",
		       xg_rates[rc->ladder[old]].ieee / 2.0,
		       xg_rates[rc->ladder[rc->pos]].ieee / 2.0, rc->sent,
		       rc->bad, rc->failed);
	rc->sent = rc->bad = rc->failed = 0;
	rc->final_sum = rc->final_n = 0;
	rc->window_start = now;
}

/* One report from the chip about a frame sent to the access point. */
static void rc_report(struct wlan *w, int final_rate, int failed)
{
	struct rate_ctl *rc = &w->rc;

	rc->bad++;
	if (failed) {
		rc->failed++;
		return;
	}
	if (final_rate < 0)
		return;
	/* position of the fastest usable rate not above the final one */
	for (int i = rc->n - 1; i >= 0; i--) {
		if (xg_rates[rc->ladder[i]].ieee <= xg_rates[final_rate].ieee) {
			rc->final_sum += i;
			rc->final_n++;
			break;
		}
	}
}

/* --- network table ------------------------------------------------------ */

static void parse_suites(const uint8_t *p, size_t len, const uint8_t *oui,
			 uint8_t *group, unsigned int *pairwise,
			 unsigned int *akm, uint16_t *caps)
{
	size_t pos = 2; /* version */
	unsigned int n;

	if (len < 2)
		return;
	if (pos + 4 > len)
		return;
	if (memcmp(p + pos, oui, 3) == 0)
		*group = p[pos + 3];
	pos += 4;

	if (pos + 2 > len)
		return;
	n = get_le16(p + pos);
	pos += 2;
	*pairwise = 0;
	for (unsigned int i = 0; i < n && pos + 4 <= len; i++, pos += 4)
		if (memcmp(p + pos, oui, 3) == 0 && p[pos + 3] < 32)
			*pairwise |= 1u << p[pos + 3];

	if (pos + 2 > len)
		return;
	n = get_le16(p + pos);
	pos += 2;
	*akm = 0;
	for (unsigned int i = 0; i < n && pos + 4 <= len; i++, pos += 4)
		if (memcmp(p + pos, oui, 3) == 0 && p[pos + 3] < 32)
			*akm |= 1u << p[pos + 3];

	if (caps && pos + 2 <= len)
		*caps = get_le16(p + pos);
}

static void parse_ies(const uint8_t *ies, size_t len, struct wlan_bss *b)
{
	static const uint8_t rsn_oui[3] = { 0x00, 0x0f, 0xac };
	static const uint8_t wpa_oui[4] = { 0x00, 0x50, 0xf2, 0x01 };
	size_t pos = 0;

	while (pos + 2 <= len) {
		uint8_t id = ies[pos], l = ies[pos + 1];
		const uint8_t *d = ies + pos + 2;

		if (pos + 2 + l > len)
			break;
		switch (id) {
		case IE_SSID:
			if (l <= IEEE80211_MAX_SSID_LEN) {
				int hidden = 1;

				for (int i = 0; i < l; i++)
					if (d[i])
						hidden = 0;
				if (!hidden) {
					memcpy(b->ssid, d, l);
					b->ssid_len = l;
				}
			}
			break;
		case IE_SUPP_RATES:
		case IE_EXT_SUPP_RATES:
			for (int i = 0; i < l; i++) {
				int idx = xg_rate_index(d[i]);

				if (idx < 0)
					continue;
				b->rate_mask |= (uint16_t)(1 << idx);
				if (d[i] & 0x80)
					b->basic_mask |= (uint16_t)(1 << idx);
			}
			break;
		case IE_DS_PARAMS:
			if (l >= 1 && d[0] >= 1 && d[0] <= 14)
				b->channel = d[0];
			break;
		case IE_ERP:
			if (l >= 1) {
				b->erp = d[0];
				b->has_erp = 1;
			}
			break;
		case IE_HT_CAP:
			b->has_ht = 1;
			break;
		case IE_RSN:
			b->has_rsn = 1;
			/* defaults when fields are omitted */
			b->rsn_group = 4;
			b->rsn_pairwise = WLAN_CIPHER_CCMP;
			b->rsn_akm = WLAN_AKM_8021X;
			parse_suites(d, l, rsn_oui, &b->rsn_group,
				     &b->rsn_pairwise, &b->rsn_akm,
				     &b->rsn_caps);
			break;
		case IE_VENDOR:
			if (l >= 6 && memcmp(d, wpa_oui, 4) == 0) {
				b->has_wpa = 1;
				b->wpa_group = 2;
				b->wpa_pairwise = WLAN_CIPHER_TKIP;
				b->wpa_akm = WLAN_AKM_8021X;
				parse_suites(d + 4, (size_t)l - 4, wpa_oui,
					     &b->wpa_group, &b->wpa_pairwise,
					     &b->wpa_akm, NULL);
			}
			break;
		default:
			break;
		}
		pos += 2 + (size_t)l;
	}
}

/*
 * Picks the protection to use with a network. Returns 0 and fills the
 * outputs (proto 0 = open), or -1 with a reason for the user.
 */
static int choose_security(const struct wlan_bss *b, enum wpa_proto *proto,
			   enum xg_cipher *pairwise, enum xg_cipher *group,
			   const char **why)
{
	*proto = 0;
	*pairwise = *group = XG_CIPHER_NONE;
	*why = "";

	if (b->has_rsn && (b->rsn_akm & WLAN_AKM_PSK) &&
	    !(b->rsn_caps & 0x0040) /* management frame protection required */) {
		if (b->rsn_pairwise & WLAN_CIPHER_CCMP)
			*pairwise = XG_CIPHER_CCMP;
		else if (b->rsn_pairwise & WLAN_CIPHER_TKIP)
			*pairwise = XG_CIPHER_TKIP;
		*group = b->rsn_group == 4 ? XG_CIPHER_CCMP :
			 b->rsn_group == 2 ? XG_CIPHER_TKIP : XG_CIPHER_NONE;
		if (*pairwise && *group) {
			*proto = WPA_PROTO_RSN;
			return 0;
		}
	}
	if (b->has_wpa && (b->wpa_akm & WLAN_AKM_PSK)) {
		if (b->wpa_pairwise & WLAN_CIPHER_CCMP)
			*pairwise = XG_CIPHER_CCMP;
		else if (b->wpa_pairwise & WLAN_CIPHER_TKIP)
			*pairwise = XG_CIPHER_TKIP;
		*group = b->wpa_group == 4 ? XG_CIPHER_CCMP :
			 b->wpa_group == 2 ? XG_CIPHER_TKIP : XG_CIPHER_NONE;
		if (*pairwise && *group) {
			*proto = WPA_PROTO_WPA;
			return 0;
		}
	}
	if (b->has_rsn || b->has_wpa) {
		unsigned int akm = b->rsn_akm | b->wpa_akm;

		if (b->has_rsn && (b->rsn_akm & WLAN_AKM_PSK) &&
		    (b->rsn_caps & 0x0040))
			*why = "protection des trames de gestion (PMF) obligatoire";
		else if (akm & WLAN_AKM_SAE)
			*why = "WPA3 seul (SAE)";
		else if (akm & WLAN_AKM_8021X)
			*why = "WPA-Entreprise (802.1X)";
		else if (akm & WLAN_AKM_PSK_SHA256)
			*why = "WPA2 SHA-256 seul";
		else
			*why = "protection inconnue";
		return -1;
	}
	if (b->capab & CAP_PRIVACY) {
		*why = "WEP";
		return -1;
	}
	return 0; /* open */
}

const char *wlan_bss_security(const struct wlan_bss *b, int *usable)
{
	enum wpa_proto proto;
	enum xg_cipher pw, gr;
	const char *why;
	int r = choose_security(b, &proto, &pw, &gr, &why);

	if (usable)
		*usable = r == 0;
	if (r)
		return why;
	if (!proto)
		return "ouvert";
	if (proto == WPA_PROTO_RSN) {
		if (b->rsn_akm & WLAN_AKM_SAE)
			return "WPA2/WPA3";
		return pw == XG_CIPHER_CCMP ? "WPA2" : "WPA2 (TKIP)";
	}
	return pw == XG_CIPHER_CCMP ? "WPA (AES)" : "WPA (TKIP)";
}

static struct wlan_bss *bss_find(struct wlan *w, const uint8_t *bssid)
{
	for (int i = 0; i < w->n_bss; i++)
		if (addr_equal(w->table[i].bssid, bssid))
			return &w->table[i];
	return NULL;
}

static struct wlan_bss *bss_alloc(struct wlan *w)
{
	struct wlan_bss *oldest = &w->table[0];

	if (w->n_bss < WLAN_MAX_BSS)
		return &w->table[w->n_bss++];
	for (int i = 1; i < w->n_bss; i++)
		if (w->table[i].last_seen < oldest->last_seen)
			oldest = &w->table[i];
	return oldest;
}

static void bss_expire(struct wlan *w, uint64_t now)
{
	int n = 0;

	for (int i = 0; i < w->n_bss; i++)
		if (now - w->table[i].last_seen < BSS_EXPIRE_MS)
			w->table[n++] = w->table[i];
	w->n_bss = n;
}

/* --- link management ---------------------------------------------------- */

static void clear_keys(struct wlan *w)
{
	xg_key_clear(&w->ptk);
	for (int i = 0; i < 4; i++)
		xg_key_clear(&w->gtk[i]);
}

static void apply_erp(struct wlan *w, const struct wlan_bss *b)
{
	int prot = b->has_erp && (b->erp & ERP_USE_PROTECTION);
	int sp = (b->capab & CAP_SHORT_PREAMBLE) &&
		 !(b->has_erp && (b->erp & ERP_BARKER_PREAMBLE));

	if (prot != w->use_protection) {
		w->use_protection = prot;
		xg_log(XG_LOG_DBG, "protection ERP %s\n",
		       prot ? "activée" : "désactivée");
	}
	if (sp != w->short_preamble) {
		w->short_preamble = sp;
		xg_dev_set_short_preamble(w->dev, sp);
	}
}

/* Leaves the current network (or attempt) and goes back to idle. */
static void link_down(struct wlan *w, int tell_ap)
{
	if (w->state <= WLAN_SCANNING)
		return;
	if (tell_ap && w->dev && w->state >= WLAN_ASSOCIATING)
		send_deauth(w, REASON_DEAUTH_LEAVING);
	wpa_sm_stop(&w->wpa);
	clear_keys(w);
	w->filter_active = 0;
	w->scanning = 0;
	if (w->port_open) {
		w->port_open = 0;
		xg_log(XG_LOG_INFO, "liaison coupée\n");
		w->cb->link(w->ctx, 0);
	}
	if (w->dev)
		xg_dev_set_led(w->dev, XG_LED_SCANNING);
	set_state(w, WLAN_IDLE);
}

static void schedule_retry(struct wlan *w)
{
	int n = (int)ARRAY_SIZE(backoff_ms);

	w->next_connect_try = now_ms() +
		(uint64_t)backoff_ms[w->backoff < n ? w->backoff : n - 1];
	if (w->backoff < n)
		w->backoff++;
}

static void join_failed(struct wlan *w, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void join_failed(struct wlan *w, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(w->last_error, sizeof(w->last_error), fmt, ap);
	va_end(ap);
	xg_log(XG_LOG_WARN, "%s\n", w->last_error);
	link_down(w, 1);
	schedule_retry(w);
}

static int net_equal(const struct wlan_network *a, const struct wlan_network *b)
{
	return a->ssid_len == b->ssid_len &&
	       memcmp(a->ssid, b->ssid, a->ssid_len) == 0 &&
	       a->has_psk == b->has_psk &&
	       (!a->has_psk || memcmp(a->pmk, b->pmk, 32) == 0);
}

/* Remembers that the access point refused our key for the current network
 * (delta > 0) or accepted it (delta = 0). */
static void note_psk_result(struct wlan *w, int delta)
{
	for (int i = 0; i < w->n_nets; i++)
		if (net_equal(&w->nets[i], &w->cur_net))
			w->psk_failures[i] = delta ? w->psk_failures[i] + delta : 0;
}

static void connected(struct wlan *w)
{
	char ssid[40];
	uint64_t now = now_ms();

	note_psk_result(w, 0);

	ssid_text(w->bss.ssid, w->bss.ssid_len, ssid, sizeof(ssid));
	w->port_open = 1;
	w->connected_since = now;
	w->last_beacon = now;
	w->probing_ap = 0;
	w->backoff = 0;
	w->last_error[0] = 0;
	xg_dev_set_led(w->dev, XG_LED_ASSOCIATED);
	set_state(w, WLAN_CONNECTED);
	xg_log(XG_LOG_INFO, "connecté à \"%s\" (canal %d, signal %d %%)\n", ssid,
	       w->bss.channel, w->signal_avg);
	w->cb->link(w->ctx, 1);
}

static void start_join(struct wlan *w, const struct wlan_bss *b,
		       const struct wlan_network *net)
{
	const char *why;
	char ssid[40];
	uint16_t mask;

	w->bss = *b;
	w->cur_net = *net;
	ssid_text(b->ssid, b->ssid_len, ssid, sizeof(ssid));

	if (choose_security(b, &w->proto, &w->pairwise, &w->group, &why)) {
		set_error(w, "\"%s\": protection non prise en charge (%s)", ssid,
			  why);
		schedule_retry(w);
		return;
	}
	w->secured = w->proto != 0;
	if (w->secured != (net->has_psk != 0)) {
		set_error(w, w->secured ?
			  "\"%s\" est protégé: un mot de passe est nécessaire" :
			  "\"%s\" est un réseau ouvert, mais un mot de passe est configuré",
			  ssid);
		schedule_retry(w);
		return;
	}
	w->own_ie_len = w->secured ?
		wpa_build_ie(w->proto, w->pairwise, w->group, w->own_ie,
			     sizeof(w->own_ie)) : 0;

	xg_log(XG_LOG_INFO,
	       "connexion à \"%s\" (%02x:%02x:%02x:%02x:%02x:%02x, canal %d, signal %d %%, %s)\n",
	       ssid, b->bssid[0], b->bssid[1], b->bssid[2], b->bssid[3],
	       b->bssid[4], b->bssid[5], b->channel, b->signal,
	       wlan_bss_security(b, NULL));

	if (xg_dev_set_channel(w->dev, b->channel)) {
		set_error(w, "changement de canal impossible");
		w->dev_errors++;
		schedule_retry(w);
		return;
	}
	mask = b->rate_mask ? b->rate_mask : 0x000f;
	/* management and key frames go out at the most robust rate */
	w->mgmt_rate = (mask & 1) ? XG_RATE_1M : XG_RATE_6M;
	w->use_protection = 0;
	w->short_preamble = 0;
	apply_erp(w, b);
	rc_init(w, mask, b->signal);
	w->signal_avg = b->signal;
	w->aid = 0;
	w->port_open = 0;
	clear_keys(w);
	for (int i = 0; i < 17; i++)
		w->last_seq[i] = 0xffff;
	memcpy(w->filter_bssid, b->bssid, 6);
	w->filter_active = 1;

	set_state(w, WLAN_AUTHENTICATING);
	w->tries = 1;
	w->state_deadline = now_ms() + AUTH_TIMEOUT_MS;
	send_auth(w);
}

/* After a scan: joins the first known network that is in range. */
static void try_join(struct wlan *w)
{
	const char *why = NULL;
	char ssid[40];
	int blocked = -1;

	for (int n = 0; n < w->n_nets; n++) {
		const struct wlan_network *net = &w->nets[n];
		struct wlan_bss *best = NULL;

		/* Do not keep knocking with a key the access point refuses:
		 * some lock the station out. A new configuration resets it. */
		if (w->psk_failures[n] >= WRONG_PSK_LIMIT) {
			if (blocked < 0)
				blocked = n;
			continue;
		}

		for (int i = 0; i < w->n_bss; i++) {
			struct wlan_bss *b = &w->table[i];
			enum wpa_proto proto;
			enum xg_cipher pw, gr;
			const char *reason;

			if (b->last_seen < w->scan_started ||
			    b->ssid_len != net->ssid_len ||
			    memcmp(b->ssid, net->ssid, net->ssid_len) != 0)
				continue;
			if (choose_security(b, &proto, &pw, &gr, &reason)) {
				why = reason;
				continue;
			}
			if (!best || b->signal > best->signal)
				best = b;
		}
		if (best) {
			start_join(w, best, net);
			return;
		}
	}
	if (blocked >= 0) {
		ssid_text(w->nets[blocked].ssid, w->nets[blocked].ssid_len, ssid,
			  sizeof(ssid));
		snprintf(w->last_error, sizeof(w->last_error),
			 "mot de passe refusé par \"%s\": corrigez-le pour réessayer",
			 ssid);
		w->next_connect_try = now_ms() + 60000;
		return;
	}
	if (w->n_nets) {
		ssid_text(w->nets[0].ssid, w->nets[0].ssid_len, ssid,
			  sizeof(ssid));
		if (why)
			set_error(w,
				  "\"%s\": protection non prise en charge (%s)",
				  ssid, why);
		else
			set_error(w, "réseau \"%s\" introuvable", ssid);
	}
	schedule_retry(w);
}

/* --- scanning ----------------------------------------------------------- */

static void scan_done(struct wlan *w)
{
	uint64_t now = now_ms();

	w->scanning = 0;
	w->scan_gen++;
	if (w->scan_while_connected) {
		xg_dev_set_channel(w->dev, w->bss.channel);
		send_nullfunc(w, 0);
		w->filter_active = 1;
		/* the time spent away must not count as missed beacons */
		w->last_beacon = now;
		pthread_cond_broadcast(&w->state_cond);
		return;
	}
	bss_expire(w, now);
	set_state(w, WLAN_IDLE);
	xg_log(XG_LOG_DBG, "recherche terminée: %d réseaux\n", w->n_bss);
	if (w->n_nets)
		try_join(w);
}

static void scan_next_channel(struct wlan *w)
{
	w->scan_chan++;
	if (w->scan_chan > xg_dev_max_channel(w->dev)) {
		scan_done(w);
		return;
	}
	if (xg_dev_set_channel(w->dev, w->scan_chan)) {
		xg_log(XG_LOG_WARN, "canal %d inaccessible\n", w->scan_chan);
		w->dev_errors++;
		scan_done(w);
		return;
	}
	w->dev_errors = 0;
	send_probe_req(w, bcast_addr, NULL, 0);
	/* hidden networks only answer when asked for by name */
	for (int n = 0; n < w->n_nets && n < 2; n++)
		send_probe_req(w, bcast_addr, w->nets[n].ssid,
			       w->nets[n].ssid_len);
	w->scan_deadline = now_ms() + SCAN_DWELL_MS;
}

static void start_scan(struct wlan *w)
{
	w->scan_request = 0;
	w->scanning = 1;
	w->listening = 1;
	w->scan_chan = 0;
	w->scan_started = now_ms();
	w->scan_while_connected = w->state == WLAN_CONNECTED;
	if (w->scan_while_connected) {
		/* ask the access point to hold our traffic meanwhile */
		send_nullfunc(w, 1);
		w->filter_active = 0;
		usleep(20 * 1000);
	} else {
		xg_dev_set_led(w->dev, XG_LED_SCANNING);
		set_state(w, WLAN_SCANNING);
	}
	scan_next_channel(w);
}

/* --- received frames ---------------------------------------------------- */

static void rx_beacon(struct wlan *w, const uint8_t *f, size_t len, int signal,
		      int is_probe_resp)
{
	const uint8_t *bssid = f + 16;
	struct wlan_bss tmp, *e;
	uint64_t now = now_ms();
	int cur_chan;

	if (len < IEEE80211_HDR_LEN + 12)
		return;
	memset(&tmp, 0, sizeof(tmp));
	memcpy(tmp.bssid, bssid, 6);
	tmp.beacon_int = get_le16(f + 32);
	tmp.capab = get_le16(f + 34);
	if (!(tmp.capab & CAP_ESS))
		return; /* ad hoc cells are of no use to us */
	cur_chan = xg_dev_channel(w->dev);
	tmp.channel = (uint8_t)cur_chan;
	parse_ies(f + 36, len - 36, &tmp);

	if (is_probe_resp && addr_equal(f + 4, xg_dev_addr(w->dev))) {
		/* an answer addressed to us: proof that we are heard */
		if (w->probe_resp_to_us++ == 0)
			xg_log(XG_LOG_DBG,
			       "première réponse à nos sondes: l'émission radio fonctionne\n");
	}

	e = bss_find(w, bssid);
	if (!e) {
		e = bss_alloc(w);
		*e = tmp;
		e->signal = signal;
	} else {
		uint8_t ssid[32];
		uint8_t ssid_len = e->ssid_len;
		int old_signal = e->signal;
		uint64_t old_seen = e->last_seen;

		memcpy(ssid, e->ssid, sizeof(ssid));
		*e = tmp;
		if (!e->ssid_len && ssid_len) {
			/* a hidden network keeps the name a probe gave us */
			memcpy(e->ssid, ssid, sizeof(ssid));
			e->ssid_len = ssid_len;
		}
		/* A beacon also leaks onto neighbouring channels, weaker:
		 * keep the best reading of the current scan. */
		if (old_seen >= w->scan_started && w->scanning &&
		    old_signal > signal)
			e->signal = old_signal;
		else if (tmp.channel == cur_chan || old_seen < w->scan_started)
			e->signal = signal;
		else
			e->signal = old_signal;
	}
	e->last_seen = now;

	if (w->state >= WLAN_AUTHENTICATING && addr_equal(bssid, w->bss.bssid) &&
	    !w->scanning) {
		w->last_beacon = now;
		w->probing_ap = 0;
		w->signal_avg = (w->signal_avg * 7 + signal + 4) / 8;
		if (!is_probe_resp && w->state == WLAN_CONNECTED) {
			w->bss.erp = tmp.erp;
			w->bss.has_erp = tmp.has_erp;
			w->bss.capab = tmp.capab;
			apply_erp(w, &w->bss);
		}
	}
}

static const char *status_text(uint16_t status)
{
	switch (status) {
	case 1:
		return "refus sans précision";
	case 10:
		return "capacités non acceptées";
	case 12:
		return "association refusée";
	case 13:
		return "méthode d'authentification refusée";
	case 17:
		return "point d'accès saturé";
	case 18:
		return "débits de base non pris en charge";
	case 40:
	case 41:
	case 42:
	case 43:
	case 45:
	case 46:
		return "paramètres de sécurité refusés";
	default:
		return "refus";
	}
}

static void rx_auth(struct wlan *w, const uint8_t *f, size_t len)
{
	uint16_t alg, seq, status;

	if (w->state != WLAN_AUTHENTICATING || len < IEEE80211_HDR_LEN + 6 ||
	    !addr_equal(f + 4, xg_dev_addr(w->dev)) ||
	    !addr_equal(f + 16, w->bss.bssid))
		return;
	alg = get_le16(f + 24);
	seq = get_le16(f + 26);
	status = get_le16(f + 28);
	if (alg != 0 || seq != 2)
		return;
	if (status != 0) {
		join_failed(w, "authentification refusée par le point d'accès: %s (code %u)",
			    status_text(status), status);
		return;
	}
	xg_log(XG_LOG_DBG, "authentifié, demande d'association\n");
	set_state(w, WLAN_ASSOCIATING);
	w->tries = 1;
	w->state_deadline = now_ms() + ASSOC_TIMEOUT_MS;
	send_assoc_req(w);
}

static void start_handshake(struct wlan *w)
{
	struct wpa_params p;

	memset(&p, 0, sizeof(p));
	p.proto = w->proto;
	p.pairwise = w->pairwise;
	p.group = w->group;
	memcpy(p.pmk, w->cur_net.pmk, 32);
	memcpy(p.own_addr, xg_dev_addr(w->dev), 6);
	memcpy(p.bssid, w->bss.bssid, 6);
	memcpy(p.own_ie, w->own_ie, w->own_ie_len);
	p.own_ie_len = w->own_ie_len;
	wpa_sm_start(&w->wpa, &p);
	memset(&p, 0, sizeof(p));
	set_state(w, WLAN_HANDSHAKE);
	w->state_deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
}

static void rx_assoc_resp(struct wlan *w, const uint8_t *f, size_t len)
{
	struct wlan_bss tmp;
	uint16_t status;

	if (w->state != WLAN_ASSOCIATING || len < IEEE80211_HDR_LEN + 6 ||
	    !addr_equal(f + 4, xg_dev_addr(w->dev)) ||
	    !addr_equal(f + 16, w->bss.bssid))
		return;
	status = get_le16(f + 26);
	if (status != 0) {
		join_failed(w, "association refusée par le point d'accès: %s (code %u)",
			    status_text(status), status);
		return;
	}
	w->aid = get_le16(f + 28) & 0x3fff;

	/* the rates the access point really grants us */
	memset(&tmp, 0, sizeof(tmp));
	parse_ies(f + 30, len - 30, &tmp);
	if (tmp.rate_mask) {
		w->bss.rate_mask = tmp.rate_mask;
		rc_init(w, tmp.rate_mask, w->signal_avg);
	}
	xg_log(XG_LOG_DBG, "associé (identifiant %u)\n", w->aid);
	w->last_beacon = now_ms();

	if (w->secured)
		start_handshake(w);
	else
		connected(w);
}

static const char *reason_text(uint16_t reason)
{
	switch (reason) {
	case 2:
		return "authentification périmée";
	case 3:
		return "le point d'accès s'arrête ou nous déconnecte";
	case 4:
		return "inactivité";
	case 5:
		return "point d'accès saturé";
	case 6:
	case 7:
		return "trame reçue hors association";
	case 14:
		return "erreur d'intégrité (MIC)";
	case 15:
		return "négociation des clés expirée";
	case 16:
		return "renouvellement de la clé de groupe expiré";
	case 23:
		return "authentification 802.1X échouée";
	default:
		return "sans précision";
	}
}

static void rx_deauth(struct wlan *w, const uint8_t *f, size_t len, int disassoc)
{
	uint16_t reason;

	if (w->state < WLAN_AUTHENTICATING || len < IEEE80211_HDR_LEN + 2 ||
	    !addr_equal(f + 10, w->bss.bssid) ||
	    !(addr_equal(f + 4, xg_dev_addr(w->dev)) || addr_is_group(f + 4)))
		return;
	reason = get_le16(f + 24);

	if (w->state == WLAN_HANDSHAKE && w->wpa.msg1_count >= 2) {
		/* we answered message 1 several times and the access point
		 * never went on: it could not verify our answer */
		note_psk_result(w, 1);
		join_failed(w, "mot de passe Wi-Fi incorrect (le point d'accès a rejeté la négociation, code %u)",
			    reason);
		return;
	}
	set_error(w, "%s par le point d'accès: %s (code %u)",
		  disassoc ? "dissociation" : "désauthentification",
		  reason_text(reason), reason);
	link_down(w, 0);
	schedule_retry(w);
}

static void rx_data(struct wlan *w, const uint8_t *f, size_t len, int rate)
{
	uint8_t plain[IEEE80211_MAX_FRAME_LEN + 64];
	uint8_t eth[IEEE80211_MAX_FRAME_LEN + 64];
	uint16_t fc = get_le16(f);
	const uint8_t *da = f + 4, *sa = f + 16, *body;
	size_t hdr_len = IEEE80211_HDR_LEN, blen, elen;
	int qos = (fc & FC_STYPE_DATA_QOS) != 0;
	int group = addr_is_group(da);
	int tid_idx = 16;
	uint16_t seq_ctrl;

	if (w->state < WLAN_HANDSHAKE || w->scanning)
		return;
	if (fc & FC_STYPE_DATA_NODATA)
		return;
	if ((fc & (FC_TODS | FC_FROMDS)) != FC_FROMDS)
		return;
	if (!addr_equal(f + 10, w->bss.bssid))
		return;
	if (group) {
		if (addr_equal(sa, xg_dev_addr(w->dev)))
			return; /* our own broadcast, relayed back */
	} else if (!addr_equal(da, xg_dev_addr(w->dev))) {
		return;
	}
	if (qos) {
		hdr_len += 2;
		if (len < hdr_len)
			return;
		tid_idx = f[24] & 0x0f;
	}
	seq_ctrl = get_le16(f + 22);
	if ((fc & FC_MOREFRAG) || (seq_ctrl & 0x000f)) {
		w->rx_dropped++; /* fragmented frames are not reassembled */
		return;
	}
	if (!group) {
		if ((fc & FC_RETRY) && w->last_seq[tid_idx] == seq_ctrl)
			return; /* duplicate */
		w->last_seq[tid_idx] = seq_ctrl;
	}
	if (len <= hdr_len)
		return;
	body = f + hdr_len;
	blen = len - hdr_len;

	if (fc & FC_PROTECTED) {
		struct xg_key *key;
		int n;

		if (group) {
			int idx = xg_frame_key_idx(body, blen);

			if (idx < 0)
				return;
			key = &w->gtk[idx];
		} else {
			key = &w->ptk;
		}
		if (key->cipher == XG_CIPHER_NONE) {
			w->rx_dropped++;
			return;
		}
		n = xg_decrypt(key, f, hdr_len, body, blen, plain);
		if (n < 0) {
			if (n != -3) /* a replay is usually a mere duplicate */
				w->rx_crypt_errors++;
			return;
		}
		body = plain;
		blen = (size_t)n;
	} else if (w->secured && w->ptk.cipher != XG_CIPHER_NONE) {
		/* once keys are installed nothing is accepted in clear */
		w->rx_dropped++;
		return;
	}

	memcpy(eth, da, 6);
	memcpy(eth + 6, sa, 6);
	if (blen >= 8 && body[0] == 0xaa && body[1] == 0xaa && body[2] == 0x03 &&
	    body[3] == 0x00 && body[4] == 0x00 &&
	    (body[5] == 0xf8 ||
	     (body[5] == 0x00 && get_be16(body + 6) != 0x80f3 &&
	      get_be16(body + 6) != 0x8137))) {
		uint16_t type = get_be16(body + 6);

		if (type == ETHERTYPE_EAPOL) {
			if (w->secured)
				wpa_sm_rx_eapol(&w->wpa, body + 8, blen - 8);
			return;
		}
		memcpy(eth + 12, body + 6, blen - 6);
		elen = 12 + blen - 6;
	} else {
		put_be16(eth + 12, (uint16_t)blen);
		memcpy(eth + 14, body, blen);
		elen = 14 + blen;
	}
	if (!w->port_open) {
		w->rx_dropped++;
		return;
	}
	if (w->secured && !(fc & FC_PROTECTED)) {
		w->rx_dropped++;
		return;
	}
	w->rx_packets++;
	if (rate >= 0)
		w->rx_rate = rate;
	w->cb->rx_packet(w->ctx, eth, elen);
}

static void handle_rx(struct wlan *w, const uint8_t *f, size_t len, int signal,
		      int rate)
{
	uint16_t fc = get_le16(f);

	if ((fc & FC_TYPE_MASK) == FC_TYPE_DATA) {
		rx_data(w, f, len, rate);
		return;
	}
	if ((fc & FC_TYPE_MASK) != FC_TYPE_MGMT)
		return;
	switch (fc & (FC_TYPE_MASK | FC_SUBTYPE_MASK)) {
	case FC_BEACON:
		rx_beacon(w, f, len, signal, 0);
		break;
	case FC_PROBE_RESP:
		rx_beacon(w, f, len, signal, 1);
		break;
	case FC_AUTH:
		rx_auth(w, f, len);
		break;
	case FC_ASSOC_RESP:
	case FC_REASSOC_RESP:
		rx_assoc_resp(w, f, len);
		break;
	case FC_DEAUTH:
		rx_deauth(w, f, len, 0);
		break;
	case FC_DISASSOC:
		rx_deauth(w, f, len, 1);
		break;
	default:
		break;
	}
}

static void handle_host_packet(struct wlan *w, const uint8_t *eth, size_t len)
{
	uint16_t type;

	if (w->state != WLAN_CONNECTED || !w->port_open || w->scanning ||
	    len < 14) {
		w->tx_dropped++;
		return;
	}
	type = get_be16(eth + 12);
	/* the source address must be ours: the access point only relays
	 * frames from stations it knows */
	if (send_data(w, eth, xg_dev_addr(w->dev), type, eth + 14, len - 14,
		      0) == 0)
		w->tx_packets++;
	else
		w->tx_dropped++;
}

/* --- WPA callbacks ------------------------------------------------------ */

static int wpa_cb_send_eapol(void *ctx, const uint8_t *eapol, size_t len)
{
	struct wlan *w = ctx;

	return send_data(w, w->bss.bssid, xg_dev_addr(w->dev), ETHERTYPE_EAPOL,
			 eapol, len, 1);
}

static int wpa_cb_set_key(void *ctx, int pairwise, int key_idx,
			  enum xg_cipher cipher, const uint8_t *key, size_t len,
			  const uint8_t *rsc)
{
	struct wlan *w = ctx;

	if (pairwise)
		return xg_key_set(&w->ptk, cipher, 0, key, len, NULL);
	return xg_key_set(&w->gtk[key_idx & 3], cipher, key_idx & 3, key, len,
			  rsc);
}

static void wpa_cb_completed(void *ctx)
{
	struct wlan *w = ctx;

	if (w->state == WLAN_HANDSHAKE)
		connected(w);
}

static void wpa_cb_failed(void *ctx, const char *text)
{
	struct wlan *w = ctx;

	join_failed(w, "négociation des clés impossible: %s", text);
}

static const struct wpa_callbacks wpa_cb = {
	.send_eapol = wpa_cb_send_eapol,
	.set_key = wpa_cb_set_key,
	.completed = wpa_cb_completed,
	.failed = wpa_cb_failed,
};

/* --- device presence ---------------------------------------------------- */

/*
 * Lets go of the stick: it was unplugged, it stopped answering, or the Mac
 * is about to sleep (then the access point is told we leave).
 */
static void device_release(struct wlan *w, const char *why, int graceful)
{
	struct xg_dev *dev = w->dev;

	if (!dev)
		return;
	xg_log(graceful ? XG_LOG_INFO : XG_LOG_WARN, "%s\n", why);
	link_down(w, graceful);
	if (graceful) {
		/* let the farewell frame leave */
		for (int i = 0; i < 20 && xg_dev_tx_queue_len(dev) > 0; i++)
			usleep(10 * 1000);
		usleep(30 * 1000);
	}
	w->dev = NULL;
	w->dev_errors = 0;
	w->dev_gen++;
	w->scanning = 0;
	w->n_bss = 0;
	set_state(w, WLAN_NO_DEVICE);
	w->cb->device(w->ctx, 0, NULL);
	w->next_dev_try = now_ms() + 1000;
	pthread_mutex_unlock(&w->lock);
	xg_dev_close(dev);
	pthread_mutex_lock(&w->lock);
}

/* called with the lock held; drops it while the stick is initialised */
static void try_open_device(struct wlan *w)
{
	struct xg_dev *dev = NULL;
	int r;

	w->dev_gen++;
	pthread_mutex_unlock(&w->lock);
	r = xg_dev_open(&dev, &dev_ops, w);
	if (r == 0) {
		r = xg_dev_start(dev);
		if (r) {
			xg_dev_close(dev);
			dev = NULL;
		}
	}
	pthread_mutex_lock(&w->lock);

	if (!dev) {
		if (r == -ENODEV) {
			if (!w->dev_missing_logged)
				xg_log(XG_LOG_INFO,
				       "clé Wi-Fi non branchée, en attente\n");
			w->dev_missing_logged = 1;
		} else {
			xg_log(XG_LOG_ERR,
			       "démarrage de la clé impossible (%d), nouvel essai dans quelques secondes\n",
			       r);
		}
		w->next_dev_try = now_ms() + DEVICE_RETRY_MS;
		pthread_cond_broadcast(&w->state_cond);
		return;
	}
	w->dev = dev;
	w->dev_missing_logged = 0;
	w->seq = 0;
	w->backoff = 0;
	w->next_connect_try = 0;
	xg_dev_set_led(dev, XG_LED_SCANNING);
	xg_log(XG_LOG_INFO, "clé prête: %s, domaine %s\n",
	       xg_dev_description(dev), xg_dev_regdomain_name(dev));
	set_state(w, WLAN_IDLE);
	w->cb->device(w->ctx, 1, xg_dev_addr(dev));
}

/* --- timers ------------------------------------------------------------- */

static void step(struct wlan *w)
{
	uint64_t now = now_ms();

	if (w->suspended) {
		device_release(w, "mise en veille: clé libérée", 1);
		pthread_cond_broadcast(&w->state_cond);
		return;
	}
	if (!w->dev) {
		if (now >= w->next_dev_try)
			try_open_device(w);
		return;
	}
	if (w->dev_errors >= 3) {
		/* e.g. the port lost power during sleep: start it afresh */
		device_release(w, "la clé ne répond plus aux commandes: réinitialisation", 0);
		return;
	}

	if (w->nets_changed) {
		w->nets_changed = 0;
		w->backoff = 0;
		w->next_connect_try = 0;
		if (w->state > WLAN_SCANNING &&
		    !(w->n_nets > 0 && net_equal(&w->cur_net, &w->nets[0]))) {
			xg_log(XG_LOG_INFO, "changement de réseau demandé\n");
			link_down(w, 1);
		}
		if (!w->n_nets)
			w->last_error[0] = 0;
	}

	if (w->scanning) {
		if (now >= w->scan_deadline)
			scan_next_channel(w);
		return;
	}

	switch (w->state) {
	case WLAN_IDLE:
		if (w->scan_request ||
		    (w->n_nets > 0 && now >= w->next_connect_try))
			start_scan(w);
		break;
	case WLAN_AUTHENTICATING:
		if (now < w->state_deadline)
			break;
		if (w->tries++ >= JOIN_TRIES) {
			join_failed(w, "le point d'accès ne répond pas à l'authentification");
			break;
		}
		w->state_deadline = now + AUTH_TIMEOUT_MS;
		send_auth(w);
		break;
	case WLAN_ASSOCIATING:
		if (now < w->state_deadline)
			break;
		if (w->tries++ >= JOIN_TRIES) {
			join_failed(w, "le point d'accès ne répond pas à la demande d'association");
			break;
		}
		w->state_deadline = now + ASSOC_TIMEOUT_MS;
		send_assoc_req(w);
		break;
	case WLAN_HANDSHAKE:
		if (now < w->state_deadline)
			break;
		if (w->wpa.msg1_count >= 2) {
			note_psk_result(w, 1);
			join_failed(w, "mot de passe Wi-Fi incorrect (le point d'accès n'a pas accepté notre réponse)");
		}
		else if (w->wpa.msg1_count == 0)
			join_failed(w, "le point d'accès n'a pas lancé la négociation des clés");
		else
			join_failed(w, "négociation des clés WPA interrompue");
		break;
	case WLAN_CONNECTED:
		if (w->scan_request) {
			start_scan(w);
			break;
		}
		rc_tick(w, now);
		if (now - w->last_beacon > BEACON_LOST_MS) {
			set_error(w, "point d'accès hors de portée (plus de balises)");
			link_down(w, 0);
			schedule_retry(w);
			break;
		}
		if (now - w->last_beacon > BEACON_PROBE_MS && !w->probing_ap) {
			w->probing_ap = 1;
			xg_log(XG_LOG_DBG, "balises manquantes, sondage du point d'accès\n");
			send_probe_req(w, w->bss.bssid, w->bss.ssid,
				       w->bss.ssid_len);
		}
		if (now - w->last_tx > KEEPALIVE_MS)
			send_nullfunc(w, 0);
		break;
	default:
		break;
	}
}

/*
 * Decides how long the station thread may sleep when no event arrives:
 * until the next real deadline while something is in progress, lazily
 * otherwise. Events and requests wake it at once in any case. Also tells
 * the USB thread whether received frames are of any interest.
 */
static void plan_wait(struct wlan *w)
{
	uint64_t now = now_ms(), deadline = 0;
	long ms = 100;

	w->listening = w->dev && (w->scanning || w->state > WLAN_IDLE);
	if (!w->dev) {
		ms = 250;
	} else if (w->scanning) {
		deadline = w->scan_deadline;
	} else {
		switch (w->state) {
		case WLAN_AUTHENTICATING:
		case WLAN_ASSOCIATING:
		case WLAN_HANDSHAKE:
			deadline = w->state_deadline;
			break;
		case WLAN_IDLE:
			if (w->scan_request)
				ms = 1;
			else if (w->n_nets > 0)
				deadline = w->next_connect_try;
			else
				ms = 500;
			break;
		default:
			break;
		}
	}
	if (deadline)
		ms = deadline > now ? (long)(deadline - now) : 1;
	if (ms > 500)
		ms = 500;
	w->wait_ms = ms < 1 ? 1 : ms;
}

/* --- station thread ----------------------------------------------------- */

static void *wlan_main(void *arg)
{
	struct wlan *w = arg;

	pthread_setname_np("xg760a-station");
	for (;;) {
		struct event *e;
		struct timespec wait;
		int quit;

		pthread_mutex_lock(&w->q_lock);
		if (!w->q_head && !w->quit) {
			long ms = w->wait_ms > 0 ? w->wait_ms : 10;

			wait.tv_sec = 0;
			wait.tv_nsec = ms * 1000000L;
			pthread_cond_timedwait_relative_np(&w->q_cond, &w->q_lock,
							   &wait);
		}
		e = w->q_head;
		if (e) {
			w->q_head = e->next;
			if (!w->q_head)
				w->q_tail = NULL;
			w->q_len--;
			if (e->type == EV_HOST_PKT)
				w->q_host_len--;
		}
		quit = w->quit;
		pthread_mutex_unlock(&w->q_lock);
		if (quit) {
			free(e);
			break;
		}

		pthread_mutex_lock(&w->lock);
		if (e && w->dev && e->gen == w->dev_gen) {
			switch (e->type) {
			case EV_RX:
				handle_rx(w, e->data, e->len, e->a, e->b);
				break;
			case EV_TX_REPORT:
				if (w->state >= WLAN_AUTHENTICATING &&
				    addr_equal(e->data, w->bss.bssid))
					rc_report(w, e->a, e->c);
				break;
			case EV_HOST_PKT:
				handle_host_packet(w, e->data, e->len);
				break;
			case EV_GONE:
				device_release(w, "clé Wi-Fi débranchée", 0);
				break;
			}
		}
		free(e);
		step(w);
		plan_wait(w);
		pthread_mutex_unlock(&w->lock);
	}

	pthread_mutex_lock(&w->lock);
	if (w->dev) {
		struct xg_dev *dev = w->dev;

		link_down(w, 1);
		/* let the farewell frame leave */
		for (int i = 0; i < 20 && xg_dev_tx_queue_len(dev) > 0; i++)
			usleep(10 * 1000);
		usleep(30 * 1000);
		w->dev = NULL;
		pthread_mutex_unlock(&w->lock);
		xg_dev_close(dev);
		pthread_mutex_lock(&w->lock);
	}
	pthread_mutex_unlock(&w->lock);
	return NULL;
}

/* --- public interface --------------------------------------------------- */

struct wlan *wlan_create(const struct wlan_callbacks *cb, void *ctx)
{
	struct wlan *w = calloc(1, sizeof(*w));

	if (!w)
		return NULL;
	w->cb = cb;
	w->ctx = ctx;
	pthread_mutex_init(&w->lock, NULL);
	pthread_cond_init(&w->state_cond, NULL);
	pthread_mutex_init(&w->q_lock, NULL);
	pthread_cond_init(&w->q_cond, NULL);
	wpa_sm_init(&w->wpa, &wpa_cb, w);
	if (pthread_create(&w->thread, NULL, wlan_main, w) != 0) {
		free(w);
		return NULL;
	}
	w->thread_started = 1;
	return w;
}

void wlan_destroy(struct wlan *w)
{
	struct event *e;

	if (!w)
		return;
	pthread_mutex_lock(&w->q_lock);
	w->quit = 1;
	pthread_cond_broadcast(&w->q_cond);
	pthread_mutex_unlock(&w->q_lock);
	if (w->thread_started)
		pthread_join(w->thread, NULL);
	while ((e = w->q_head)) {
		w->q_head = e->next;
		free(e);
	}
	clear_keys(w);
	memset(w->nets, 0, sizeof(w->nets));
	pthread_mutex_destroy(&w->lock);
	pthread_cond_destroy(&w->state_cond);
	pthread_mutex_destroy(&w->q_lock);
	pthread_cond_destroy(&w->q_cond);
	free(w);
}

void wlan_set_networks(struct wlan *w, const struct wlan_network *nets, int n)
{
	if (n > WLAN_MAX_NETWORKS)
		n = WLAN_MAX_NETWORKS;
	pthread_mutex_lock(&w->lock);
	memset(w->nets, 0, sizeof(w->nets));
	if (n > 0)
		memcpy(w->nets, nets, (size_t)n * sizeof(*nets));
	w->n_nets = n;
	memset(w->psk_failures, 0, sizeof(w->psk_failures));
	w->nets_changed = 1;
	pthread_mutex_unlock(&w->lock);
	kick(w);
}

static int wait_cond(struct wlan *w, uint64_t deadline)
{
	uint64_t now = now_ms();
	struct timespec wait;

	if (now >= deadline)
		return -ETIMEDOUT;
	wait.tv_sec = (time_t)((deadline - now) / 1000);
	wait.tv_nsec = (long)((deadline - now) % 1000) * 1000000L;
	pthread_cond_timedwait_relative_np(&w->state_cond, &w->lock, &wait);
	return 0;
}

static int cmp_signal(const void *a, const void *b)
{
	return ((const struct wlan_bss *)b)->signal -
	       ((const struct wlan_bss *)a)->signal;
}

int wlan_scan(struct wlan *w, struct wlan_bss *out, int max)
{
	uint64_t deadline = now_ms() + 15000;
	unsigned int gen;
	int n = 0;

	pthread_mutex_lock(&w->lock);
	if (!w->dev) {
		pthread_mutex_unlock(&w->lock);
		return -ENODEV;
	}
	gen = w->scan_gen;
	w->scan_request = 1;
	kick(w);
	while (w->scan_gen == gen && w->dev) {
		if (wait_cond(w, deadline))
			break;
	}
	if (w->scan_gen == gen) {
		int r = w->dev ? -ETIMEDOUT : -ENODEV;

		w->scan_request = 0;
		pthread_mutex_unlock(&w->lock);
		return r;
	}
	for (int i = 0; i < w->n_bss && n < max; i++)
		if (w->table[i].last_seen >= w->scan_started)
			out[n++] = w->table[i];
	pthread_mutex_unlock(&w->lock);
	qsort(out, (size_t)n, sizeof(*out), cmp_signal);
	return n;
}

void wlan_get_status(struct wlan *w, struct wlan_status *st)
{
	struct xg_dev_stats ds;

	memset(st, 0, sizeof(*st));
	pthread_mutex_lock(&w->lock);
	st->state = w->state;
	st->device_present = w->dev != NULL;
	snprintf(st->last_error, sizeof(st->last_error), "%s", w->last_error);
	st->rx_packets = w->rx_packets;
	st->tx_packets = w->tx_packets;
	st->rx_dropped = w->rx_dropped;
	st->tx_dropped = w->tx_dropped;
	st->rx_crypt_errors = w->rx_crypt_errors;
	if (w->dev) {
		snprintf(st->device, sizeof(st->device), "%s",
			 xg_dev_description(w->dev));
		snprintf(st->regdomain, sizeof(st->regdomain), "%s",
			 xg_dev_regdomain_name(w->dev));
		memcpy(st->addr, xg_dev_addr(w->dev), 6);
		xg_dev_get_stats(w->dev, &ds);
		st->tx_retried = ds.tx_retried;
		st->tx_failed = ds.tx_failed;
		st->tx_dropped += ds.tx_dropped;
	}
	if (w->state >= WLAN_AUTHENTICATING) {
		memcpy(st->ssid, w->bss.ssid, w->bss.ssid_len);
		st->ssid_len = w->bss.ssid_len;
		memcpy(st->bssid, w->bss.bssid, 6);
		st->channel = w->bss.channel;
		st->signal = w->signal_avg;
		snprintf(st->security, sizeof(st->security), "%s",
			 wlan_bss_security(&w->bss, NULL));
	}
	if (w->state == WLAN_CONNECTED) {
		st->tx_rate = xg_rates[w->rc.ladder[w->rc.pos]].ieee;
		st->rx_rate = xg_rates[w->rx_rate].ieee;
		st->connected_ms = now_ms() - w->connected_since;
	}
	pthread_mutex_unlock(&w->lock);
}

int wlan_wait_state(struct wlan *w, enum wlan_state state, int timeout_ms)
{
	uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
	int r = 0;

	pthread_mutex_lock(&w->lock);
	while (w->state != state) {
		if (wait_cond(w, deadline)) {
			r = -ETIMEDOUT;
			break;
		}
	}
	pthread_mutex_unlock(&w->lock);
	return r;
}

int wlan_wait_device(struct wlan *w, int timeout_ms)
{
	uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
	int r = 0;

	pthread_mutex_lock(&w->lock);
	while (!w->dev) {
		if (wait_cond(w, deadline)) {
			r = -ETIMEDOUT;
			break;
		}
	}
	pthread_mutex_unlock(&w->lock);
	return r;
}

void wlan_suspend(struct wlan *w)
{
	uint64_t deadline = now_ms() + 3000;

	pthread_mutex_lock(&w->lock);
	w->suspended = 1;
	kick(w);
	while (w->dev) {
		if (wait_cond(w, deadline))
			break;
	}
	pthread_mutex_unlock(&w->lock);
}

void wlan_resume(struct wlan *w)
{
	pthread_mutex_lock(&w->lock);
	w->suspended = 0;
	w->next_dev_try = 0;
	pthread_mutex_unlock(&w->lock);
	kick(w);
}

int wlan_tx_backlog(struct wlan *w)
{
	int n;

	pthread_mutex_lock(&w->q_lock);
	n = w->q_host_len;
	pthread_mutex_unlock(&w->q_lock);
	pthread_mutex_lock(&w->lock);
	if (w->dev)
		n += xg_dev_tx_queue_len(w->dev);
	pthread_mutex_unlock(&w->lock);
	return n;
}

int wlan_send(struct wlan *w, const uint8_t *eth, size_t len)
{
	if (len < 14 || len > 2304)
		return -EINVAL;
	return post_event(w, EV_HOST_PKT, eth, len, 0, 0, 0);
}
