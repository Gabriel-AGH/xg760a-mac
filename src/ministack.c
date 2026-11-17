/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Minimal IPv4 client used by the unprivileged self-test: DHCP, ARP, ICMP.
 */
#include "ministack.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "ieee80211.h"
#include "wlan.h"

#define QUEUE_LEN 128
#define MAX_PKT 1600

struct pkt {
	size_t len;
	uint8_t data[MAX_PKT];
};

struct ministack {
	struct wlan *w;
	uint8_t mac[6];
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct pkt *q;
	int head, count;

	uint32_t ip, mask, gw, dns, server;
	uint32_t lease;
	uint8_t gw_mac[6];
	uint16_t ip_id;
};

static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint64_t now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static uint32_t get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static const char *ip_str(uint32_t ip, char *buf)
{
	snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 0xff,
		 (ip >> 8) & 0xff, ip & 0xff);
	return buf;
}

static uint16_t checksum(const uint8_t *p, size_t len)
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

struct ministack *ministack_new(const uint8_t mac[6])
{
	struct ministack *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->q = calloc(QUEUE_LEN, sizeof(struct pkt));
	if (!m->q) {
		free(m);
		return NULL;
	}
	memcpy(m->mac, mac, 6);
	pthread_mutex_init(&m->lock, NULL);
	pthread_cond_init(&m->cond, NULL);
	xg_random(&m->ip_id, sizeof(m->ip_id));
	return m;
}

void ministack_free(struct ministack *m)
{
	if (!m)
		return;
	pthread_mutex_destroy(&m->lock);
	pthread_cond_destroy(&m->cond);
	free(m->q);
	free(m);
}

void ministack_attach(struct ministack *m, struct wlan *w)
{
	m->w = w;
}

void ministack_rx(struct ministack *m, const uint8_t *eth, size_t len)
{
	struct pkt *p;

	if (len < 14 || len > MAX_PKT)
		return;
	pthread_mutex_lock(&m->lock);
	if (m->count < QUEUE_LEN) {
		p = &m->q[(m->head + m->count) % QUEUE_LEN];
		p->len = len;
		memcpy(p->data, eth, len);
		m->count++;
		pthread_cond_signal(&m->cond);
	}
	pthread_mutex_unlock(&m->lock);
}

/* --- sending ------------------------------------------------------------ */

static void send_arp(struct ministack *m, int op, const uint8_t *dst_mac,
		     const uint8_t *target_mac, uint32_t target_ip)
{
	uint8_t f[42];

	memcpy(f, dst_mac, 6);
	memcpy(f + 6, m->mac, 6);
	put_be16(f + 12, 0x0806);
	put_be16(f + 14, 1);
	put_be16(f + 16, 0x0800);
	f[18] = 6;
	f[19] = 4;
	put_be16(f + 20, (uint16_t)op);
	memcpy(f + 22, m->mac, 6);
	put_be32(f + 28, m->ip);
	memcpy(f + 32, target_mac, 6);
	put_be32(f + 38, target_ip);
	wlan_send(m->w, f, sizeof(f));
}

/* f: room for 14 + 20 + payload; payload already at f + 34 */
static void send_ip(struct ministack *m, uint8_t *f, const uint8_t *dst_mac,
		    uint32_t src, uint32_t dst, uint8_t proto, size_t payload)
{
	uint8_t *ip = f + 14;

	memcpy(f, dst_mac, 6);
	memcpy(f + 6, m->mac, 6);
	put_be16(f + 12, 0x0800);
	ip[0] = 0x45;
	ip[1] = 0;
	put_be16(ip + 2, (uint16_t)(20 + payload));
	put_be16(ip + 4, m->ip_id++);
	put_be16(ip + 6, 0x4000); /* don't fragment */
	ip[8] = 64;
	ip[9] = proto;
	put_be16(ip + 10, 0);
	put_be32(ip + 12, src);
	put_be32(ip + 16, dst);
	put_be16(ip + 10, checksum(ip, 20));
	wlan_send(m->w, f, 34 + payload);
}

static void send_dhcp(struct ministack *m, uint32_t xid, int type,
		      int broadcast_flag)
{
	uint8_t f[14 + 20 + 8 + 300];
	uint8_t *udp = f + 34, *b = udp + 8, *o;

	memset(f, 0, sizeof(f));
	put_be16(udp, 68);
	put_be16(udp + 2, 67);
	put_be16(udp + 4, 8 + 300);
	b[0] = 1; /* request */
	b[1] = 1; /* Ethernet */
	b[2] = 6;
	put_be32(b + 4, xid);
	put_be16(b + 10, broadcast_flag ? 0x8000 : 0);
	memcpy(b + 28, m->mac, 6);
	put_be32(b + 236, 0x63825363);
	o = b + 240;
	*o++ = 53;
	*o++ = 1;
	*o++ = (uint8_t)type;
	*o++ = 61; /* client identifier */
	*o++ = 7;
	*o++ = 1;
	memcpy(o, m->mac, 6);
	o += 6;
	if (type == 3) {
		*o++ = 50; /* requested address */
		*o++ = 4;
		put_be32(o, m->ip);
		o += 4;
		*o++ = 54; /* server identifier */
		*o++ = 4;
		put_be32(o, m->server);
		o += 4;
	}
	*o++ = 55; /* parameter request list */
	*o++ = 3;
	*o++ = 1;
	*o++ = 3;
	*o++ = 6;
	*o++ = 255;
	send_ip(m, f, bcast, 0, 0xffffffff, 17, 8 + 300);
}

static void send_ping(struct ministack *m, const uint8_t *dst_mac, uint32_t dst,
		      uint16_t id, uint16_t seq, size_t data_len)
{
	uint8_t f[14 + 20 + 8 + 1472];
	uint8_t *icmp = f + 34;
	uint64_t t = now_us();

	if (data_len < 8)
		data_len = 8;
	if (data_len > 1472)
		data_len = 1472;
	icmp[0] = 8;
	icmp[1] = 0;
	put_be16(icmp + 2, 0);
	put_be16(icmp + 4, id);
	put_be16(icmp + 6, seq);
	for (size_t i = 0; i < data_len; i++)
		icmp[8 + i] = (uint8_t)(i * 7 + seq);
	for (int i = 0; i < 8; i++)
		icmp[8 + i] = (uint8_t)(t >> (56 - 8 * i));
	put_be16(icmp + 2, checksum(icmp, 8 + data_len));
	send_ip(m, f, dst_mac, m->ip, dst, 1, 8 + data_len);
}

/* --- receiving ---------------------------------------------------------- */

/* Pops the next received frame; answers ARP requests for our address on
 * the way. Returns 0, or -1 when the deadline has passed. */
static int next_packet(struct ministack *m, struct pkt *out, uint64_t deadline)
{
	for (;;) {
		uint64_t now = now_ms();

		pthread_mutex_lock(&m->lock);
		while (m->count == 0) {
			struct timespec wait;

			now = now_ms();
			if (now >= deadline) {
				pthread_mutex_unlock(&m->lock);
				return -1;
			}
			wait.tv_sec = (time_t)((deadline - now) / 1000);
			wait.tv_nsec = (long)((deadline - now) % 1000) * 1000000L;
			pthread_cond_timedwait_relative_np(&m->cond, &m->lock,
							   &wait);
		}
		*out = m->q[m->head];
		m->head = (m->head + 1) % QUEUE_LEN;
		m->count--;
		pthread_mutex_unlock(&m->lock);

		if (m->ip && out->len >= 42 && get_be16(out->data + 12) == 0x0806 &&
		    get_be16(out->data + 20) == 1 &&
		    get_be32(out->data + 38) == m->ip) {
			/* somebody asks who has our address */
			send_arp(m, 2, out->data + 22, out->data + 22,
				 get_be32(out->data + 28));
			continue;
		}
		return 0;
	}
}

/* returns the DHCP message type of a reply to xid, 0 otherwise */
static int parse_dhcp(struct ministack *m, const struct pkt *p, uint32_t xid,
		      int *was_broadcast)
{
	const uint8_t *ip = p->data + 14, *udp, *b, *o, *end;
	size_t ihl;
	int type = 0;

	if (p->len < 14 + 20 + 8 + 240 || get_be16(p->data + 12) != 0x0800 ||
	    (ip[0] >> 4) != 4 || ip[9] != 17)
		return 0;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (p->len < 14 + ihl + 8 + 240)
		return 0;
	udp = ip + ihl;
	if (get_be16(udp) != 67 || get_be16(udp + 2) != 68)
		return 0;
	b = udp + 8;
	if (b[0] != 2 || get_be32(b + 4) != xid ||
	    memcmp(b + 28, m->mac, 6) != 0 || get_be32(b + 236) != 0x63825363)
		return 0;
	*was_broadcast = addr_is_group(p->data);

	end = p->data + p->len;
	o = b + 240;
	while (o < end && *o != 255) {
		uint8_t code = *o, l;

		if (code == 0) {
			o++;
			continue;
		}
		if (o + 2 > end)
			break;
		l = o[1];
		if (o + 2 + l > end)
			break;
		if (code == 53 && l >= 1)
			type = o[2];
		else if (code == 1 && l >= 4)
			m->mask = get_be32(o + 2);
		else if (code == 3 && l >= 4)
			m->gw = get_be32(o + 2);
		else if (code == 6 && l >= 4)
			m->dns = get_be32(o + 2);
		else if (code == 51 && l >= 4)
			m->lease = get_be32(o + 2);
		else if (code == 54 && l >= 4)
			m->server = get_be32(o + 2);
		o += 2 + l;
	}
	if (type == 2 || type == 5)
		m->ip = get_be32(b + 16);
	return type;
}

/* returns 1 and the round trip in microseconds for an echo reply */
static int parse_pong(const struct pkt *p, uint32_t from, uint16_t id,
		      uint16_t *seq, uint64_t *rtt_us, size_t *data_len)
{
	const uint8_t *ip = p->data + 14, *icmp;
	size_t ihl, total;
	uint64_t t = 0;

	if (p->len < 14 + 20 + 16 || get_be16(p->data + 12) != 0x0800 ||
	    (ip[0] >> 4) != 4 || ip[9] != 1 || get_be32(ip + 12) != from)
		return 0;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	total = get_be16(ip + 2);
	if (total < ihl + 16 || 14 + total > p->len)
		return 0;
	icmp = ip + ihl;
	if (icmp[0] != 0 || get_be16(icmp + 4) != id)
		return 0;
	*seq = get_be16(icmp + 6);
	for (int i = 0; i < 8; i++)
		t = (t << 8) | icmp[8 + i];
	*rtt_us = now_us() - t;
	*data_len = total - ihl - 8;
	return 1;
}

/* --- the test itself ---------------------------------------------------- */

static int do_dhcp(struct ministack *m)
{
	struct pkt *p = malloc(sizeof(*p));
	uint32_t xid;
	char a[16], b[16], c[16], d[16];
	int ok = 0, bc = 0;

	xg_random(&xid, sizeof(xid));
	printf("DHCP: demande d'adresse...\n");
	for (int attempt = 0; attempt < 4 && !ok; attempt++) {
		uint64_t deadline = now_ms() + 2500;

		/* broadcast flag set: the offer comes back as a broadcast,
		 * which exercises the group key */
		send_dhcp(m, xid, 1, 1);
		while (!ok && next_packet(m, p, deadline) == 0)
			if (parse_dhcp(m, p, xid, &bc) == 2)
				ok = 1;
	}
	if (!ok) {
		printf("  ÉCHEC: aucune offre DHCP reçue\n");
		free(p);
		return -1;
	}
	printf("  offre reçue (%s): %s\n",
	       bc ? "en diffusion, clé de groupe" : "en direct", ip_str(m->ip, a));

	ok = 0;
	for (int attempt = 0; attempt < 4 && !ok; attempt++) {
		uint64_t deadline = now_ms() + 2500;

		/* no broadcast flag: the acknowledgement comes back to our
		 * address, which exercises the session key */
		send_dhcp(m, xid, 3, 0);
		while (!ok && next_packet(m, p, deadline) == 0) {
			int t = parse_dhcp(m, p, xid, &bc);

			if (t == 5)
				ok = 1;
			else if (t == 6) {
				printf("  ÉCHEC: le serveur DHCP a refusé la demande\n");
				free(p);
				return -1;
			}
		}
	}
	free(p);
	if (!ok) {
		printf("  ÉCHEC: pas d'accusé de réception DHCP\n");
		return -1;
	}
	printf("  bail accordé (%s): adresse %s, masque %s, routeur %s, DNS %s, durée %u s\n",
	       bc ? "en diffusion" : "en direct, clé de session",
	       ip_str(m->ip, a), ip_str(m->mask, b), ip_str(m->gw, c),
	       ip_str(m->dns, d), m->lease);
	return 0;
}

static int do_arp(struct ministack *m)
{
	static const uint8_t zero[6];
	struct pkt *p = malloc(sizeof(*p));
	char a[16];
	int ok = 0;

	printf("ARP: recherche du routeur %s...\n", ip_str(m->gw, a));
	for (int attempt = 0; attempt < 4 && !ok; attempt++) {
		uint64_t deadline = now_ms() + 1000;

		send_arp(m, 1, bcast, zero, m->gw);
		while (!ok && next_packet(m, p, deadline) == 0) {
			if (p->len >= 42 && get_be16(p->data + 12) == 0x0806 &&
			    get_be16(p->data + 20) == 2 &&
			    get_be32(p->data + 28) == m->gw) {
				memcpy(m->gw_mac, p->data + 22, 6);
				ok = 1;
			}
		}
	}
	free(p);
	if (!ok) {
		printf("  ÉCHEC: le routeur ne répond pas\n");
		return -1;
	}
	printf("  routeur à l'adresse %02x:%02x:%02x:%02x:%02x:%02x\n",
	       m->gw_mac[0], m->gw_mac[1], m->gw_mac[2], m->gw_mac[3],
	       m->gw_mac[4], m->gw_mac[5]);
	return 0;
}

static int do_ping(struct ministack *m, uint32_t target, const char *what,
		   int count)
{
	struct pkt *p = malloc(sizeof(*p));
	uint16_t id;
	char a[16];
	int received = 0;
	uint64_t best = 0, sum = 0;

	xg_random(&id, sizeof(id));
	printf("Ping %s (%s)...\n", what, ip_str(target, a));
	for (int i = 0; i < count; i++) {
		uint64_t deadline = now_ms() + 1500;
		uint16_t seq;
		uint64_t rtt;
		size_t dl;
		int got = 0;

		send_ping(m, m->gw_mac, target, id, (uint16_t)i, 56);
		while (!got && next_packet(m, p, deadline) == 0)
			if (parse_pong(p, target, id, &seq, &rtt, &dl) &&
			    seq == i)
				got = 1;
		if (got) {
			received++;
			sum += rtt;
			if (!best || rtt < best)
				best = rtt;
			printf("  réponse %d: %.1f ms\n", i + 1, rtt / 1000.0);
		} else {
			printf("  réponse %d: perdue\n", i + 1);
		}
		usleep(200 * 1000);
	}
	free(p);
	if (!received) {
		printf("  ÉCHEC: aucune réponse\n");
		return -1;
	}
	printf("  %d/%d réponses, %.1f ms en moyenne, %.1f ms au mieux\n",
	       received, count, sum / 1000.0 / received, best / 1000.0);
	return 0;
}

/*
 * Uplink capacity: UDP datagrams to the router's "discard" port, as fast as
 * the radio takes them. Nothing has to come back, so the figure does not
 * depend on how eagerly the router answers.
 */
static void do_uplink(struct ministack *m)
{
	enum { SIZE = 1400, DURATION_MS = 3000 };
	uint8_t f[14 + 20 + 8 + SIZE];
	uint8_t *udp = f + 34;
	struct wlan_status st0, st1;
	uint64_t start, elapsed;
	unsigned long sent = 0;
	unsigned long long lost;
	double mbps;

	printf("Débit montant : envoi continu vers le routeur pendant %d s...\n",
	       DURATION_MS / 1000);
	memset(f, 0, sizeof(f));
	put_be16(udp, 50760);
	put_be16(udp + 2, 9); /* discard */
	put_be16(udp + 4, 8 + SIZE);
	for (int i = 0; i < SIZE; i++)
		udp[8 + i] = (uint8_t)i;
	wlan_get_status(m->w, &st0);
	start = now_ms();
	while (now_ms() - start < DURATION_MS) {
		/* never more than a few dozen frames ahead of the radio */
		if (wlan_tx_backlog(m->w) > 40) {
			usleep(300);
			continue;
		}
		send_ip(m, f, m->gw_mac, m->ip, m->gw, 17, 8 + SIZE);
		sent++;
	}
	while (wlan_tx_backlog(m->w) > 0 && now_ms() - start < DURATION_MS + 2000)
		usleep(1000);
	elapsed = now_ms() - start;
	usleep(200 * 1000);
	wlan_get_status(m->w, &st1);
	lost = (st1.tx_failed - st0.tx_failed) + (st1.tx_dropped - st0.tx_dropped);
	if (lost > sent)
		lost = sent;
	mbps = (sent - lost) * (SIZE + 28) * 8.0 / (elapsed / 1000.0) / 1e6;
	printf("  %lu paquets de %d octets émis, %llu perdus : environ %.1f Mbit/s\n",
	       sent, SIZE, lost, mbps);
	printf("  débit radio retenu : %g Mbit/s ; trames reprises %llu\n",
	       st1.tx_rate / 2.0, st1.tx_retried - st0.tx_retried);
}

/* Keeps a window of large echo requests in flight for a few seconds. */
static void do_load(struct ministack *m)
{
	enum { WINDOW = 12, SIZE = 1400, DURATION_MS = 4000 };
	struct pkt *p = malloc(sizeof(*p));
	struct wlan_status st0, st1;
	uint64_t start = now_ms(), end = start + DURATION_MS;
	uint64_t sent_at[65536 / 64];
	uint16_t id, next = 0;
	unsigned int sent = 0, received = 0, outstanding = 0;
	double secs, mbps;

	(void)sent_at;
	xg_random(&id, sizeof(id));
	wlan_get_status(m->w, &st0);
	printf("Aller-retour : échos de %d octets avec le routeur pendant %d s...\n",
	       SIZE, DURATION_MS / 1000);
	while (now_ms() < end) {
		uint16_t seq;
		uint64_t rtt;
		size_t dl;

		while (outstanding < WINDOW) {
			send_ping(m, m->gw_mac, m->gw, id, next++, SIZE);
			sent++;
			outstanding++;
		}
		if (next_packet(m, p, now_ms() + 250) == 0) {
			if (parse_pong(p, m->gw, id, &seq, &rtt, &dl) &&
			    dl == SIZE) {
				received++;
				if (outstanding)
					outstanding--;
			}
		} else {
			/* nothing for 250 ms: the window was lost */
			outstanding = 0;
		}
	}
	/* collect the stragglers */
	while (next_packet(m, p, now_ms() + 300) == 0) {
		uint16_t seq;
		uint64_t rtt;
		size_t dl;

		if (parse_pong(p, m->gw, id, &seq, &rtt, &dl) && dl == SIZE)
			received++;
	}
	free(p);
	secs = (now_ms() - start) / 1000.0;
	mbps = received * (SIZE + 28) * 8.0 / secs / 1e6;
	wlan_get_status(m->w, &st1);
	printf("  %u échos envoyés, %u revenus (%.1f %% de perte)\n", sent,
	       received, sent ? 100.0 * (sent - received) / sent : 0.0);
	printf("  environ %.1f Mbit/s dans chaque sens à la fois\n", mbps);
	if (sent > received + sent / 5 &&
	    st1.tx_failed - st0.tx_failed < (sent - received) / 4)
		printf("  (les échos manquants n'ont pas été perdus par la radio : le routeur limite\n"
		       "   sans doute ses réponses aux pings ; se fier au débit montant ci-dessus)\n");
	printf("  débit radio retenu : %g Mbit/s ; trames reprises %llu, abandonnées %llu\n",
	       st1.tx_rate / 2.0, st1.tx_retried - st0.tx_retried,
	       st1.tx_failed - st0.tx_failed);
}

int ministack_run(struct ministack *m)
{
	int r;

	if (do_dhcp(m) || do_arp(m))
		return -1;
	r = do_ping(m, m->gw, "du routeur", 4);
	/* a well-known public resolver that answers pings */
	if (do_ping(m, 0x01010101, "d'Internet", 4))
		printf("  (pas de réponse d'Internet: la liaison Wi-Fi marche, mais la box ne route pas vers l'extérieur)\n");
	if (r == 0) {
		do_uplink(m);
		do_load(m);
	}
	return r;
}
