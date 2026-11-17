/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * System network interface built on a pair of macOS "feth" interfaces.
 *
 *   system  <->  feth760  ==peer==  feth5760  <->  this program  <->  radio
 *
 * Frames the system sends on feth760 appear on feth5760, where they are
 * read through BPF. Frames coming from the radio are written to feth5760
 * with a raw link-layer socket (AF_NDRV) and appear as received on
 * feth760. This is the technique ZeroTier uses for its macOS virtual
 * Ethernet port.
 */
#include "netif.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/ndrv.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>

#include "compat.h"
#include "wlan.h"

#define IF_NUMBER 760
#define IF_MTU "1500"
#define BPF_BUF_SIZE (128 * 1024)
#define LINK_DOWN_GRACE_MS 8000

extern char **environ;

enum { CMD_NONE, CMD_DEVICE_ON, CMD_DEVICE_OFF, CMD_LINK_UP, CMD_LINK_DOWN };

struct cmd {
	struct cmd *next;
	int type;
	uint8_t mac[6];
};

struct netif {
	struct wlan *wlan;
	char name[IFNAMSIZ];
	char peer[IFNAMSIZ];

	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_t worker, reader;
	int worker_started, reader_started;
	int quit;
	struct cmd *head, *tail;

	int exists;		/* the feth pair is there */
	int configured;		/* the system was told to configure it */
	int link;
	uint64_t down_since;	/* pending deconfiguration, 0 if none */
	uint64_t up_since;	/* waiting for an address, 0 if not */
	int bpf_fd, ndrv_fd;
	size_t bpf_buflen;	/* a BPF read must use exactly this size */
	int reader_stop;
	uint8_t mac[6];
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* runs a system tool and waits for it; returns its exit status */
static int run(const char *path, ...)
{
	const char *argv[12];
	char line[256] = "";
	va_list ap;
	pid_t pid;
	int n = 0, status = 0;

	argv[n++] = path;
	va_start(ap, path);
	while (n < 11 && (argv[n] = va_arg(ap, const char *)) != NULL)
		n++;
	va_end(ap);
	argv[n] = NULL;
	for (int i = 0; i < n; i++) {
		strlcat(line, argv[i], sizeof(line));
		strlcat(line, " ", sizeof(line));
	}
	if (posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, environ) !=
	    0) {
		xg_log(XG_LOG_ERR, "impossible de lancer: %s\n", line);
		return -1;
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	xg_log(XG_LOG_DBG, "%s-> %d\n", line, status);
	return status;
}

static int if_exists(const char *name)
{
	return if_nametoindex(name) != 0;
}

static void close_fds(struct netif *n)
{
	if (n->bpf_fd >= 0)
		close(n->bpf_fd);
	if (n->ndrv_fd >= 0)
		close(n->ndrv_fd);
	n->bpf_fd = n->ndrv_fd = -1;
}

/* --- frames from the system to the radio -------------------------------- */

static void *reader_main(void *arg)
{
	struct netif *n = arg;
	uint8_t *buf = malloc(n->bpf_buflen);

	pthread_setname_np("xg760a-netif-rx");
	while (buf && !n->reader_stop) {
		ssize_t got = read(n->bpf_fd, buf, n->bpf_buflen);
		uint8_t *p = buf;

		if (got < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			if (!n->reader_stop)
				xg_log(XG_LOG_DBG, "lecture BPF: %s\n",
				       strerror(errno));
			break;
		}
		while (p + sizeof(struct bpf_hdr) <= buf + got) {
			struct bpf_hdr *h = (struct bpf_hdr *)p;
			uint8_t *frame = p + h->bh_hdrlen;

			if (frame + h->bh_caplen > buf + got)
				break;
			/* only what the system itself sends: its frames
			 * carry the stick's address as source */
			if (h->bh_caplen >= 14 && h->bh_caplen == h->bh_datalen &&
			    memcmp(frame + 6, n->mac, 6) == 0 && n->wlan)
				wlan_send(n->wlan, frame, h->bh_caplen);
			p += BPF_WORDALIGN(h->bh_hdrlen + h->bh_caplen);
		}
	}
	free(buf);
	return NULL;
}

void netif_rx(struct netif *n, const uint8_t *eth, size_t len)
{
	int fd = n->ndrv_fd;

	if (fd < 0 || !n->link)
		return;
	if (write(fd, eth, len) < 0 && errno != ENOBUFS)
		xg_log(XG_LOG_TRACE, "injection vers le système: %s\n",
		       strerror(errno));
}

/* --- interface life cycle (worker thread) ------------------------------- */

static void destroy_interface(struct netif *n)
{
	if (n->reader_started) {
		n->reader_stop = 1;
		pthread_join(n->reader, NULL);
		n->reader_started = 0;
		n->reader_stop = 0;
	}
	close_fds(n);
	if (if_exists(n->name)) {
		if (n->configured) {
			run("/usr/sbin/ipconfig", "set", n->name, "NONE", NULL);
			run("/usr/sbin/ipconfig", "set", n->name, "NONE-V6", NULL);
		}
		run("/sbin/ifconfig", n->name, "destroy", NULL);
	}
	if (if_exists(n->peer))
		run("/sbin/ifconfig", n->peer, "destroy", NULL);
	n->configured = 0;
	n->exists = 0;
	n->link = 0;
	n->down_since = n->up_since = 0;
}

static int open_bpf(struct netif *n)
{
	struct ifreq ifr;
	struct timeval tv = { 0, 300 * 1000 };
	u_int v;
	int fd = -1;

	/* Start at /dev/bpf1: some simple tools hard-code /dev/bpf0. */
	for (int i = 1; i < 256 && fd < 0; i++) {
		char path[32];

		snprintf(path, sizeof(path), "/dev/bpf%d", i);
		fd = open(path, O_RDWR);
		if (fd < 0 && errno != EBUSY)
			break;
	}
	if (fd < 0) {
		xg_log(XG_LOG_ERR, "ouverture de /dev/bpf impossible: %s\n",
		       strerror(errno));
		return -1;
	}
	v = BPF_BUF_SIZE;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, n->peer, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSBLEN, &v) != 0 ||
	    /* the kernel may have settled on another size */
	    (n->bpf_buflen = v, v = 1, ioctl(fd, BIOCIMMEDIATE, &v)) != 0 ||
	    (v = 0, ioctl(fd, BIOCSSEESENT, &v)) != 0 ||
	    ioctl(fd, BIOCSETIF, &ifr) != 0 ||
	    (v = 1, ioctl(fd, BIOCSHDRCMPLT, &v)) != 0 ||
	    ioctl(fd, BIOCPROMISC, NULL) != 0 ||
	    ioctl(fd, BIOCSRTIMEOUT, &tv) != 0) {
		xg_log(XG_LOG_ERR, "configuration de BPF impossible: %s\n",
		       strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int open_ndrv(struct netif *n)
{
	struct sockaddr_ndrv nd;
	int fd = socket(AF_NDRV, SOCK_RAW, 0);

	if (fd < 0) {
		xg_log(XG_LOG_ERR, "socket AF_NDRV: %s\n", strerror(errno));
		return -1;
	}
	memset(&nd, 0, sizeof(nd));
	nd.snd_len = sizeof(nd);
	nd.snd_family = AF_NDRV;
	strlcpy((char *)nd.snd_name, n->peer, sizeof(nd.snd_name));
	if (bind(fd, (struct sockaddr *)&nd, sizeof(nd)) != 0 ||
	    connect(fd, (struct sockaddr *)&nd, sizeof(nd)) != 0) {
		xg_log(XG_LOG_ERR, "liaison AF_NDRV a %s: %s\n", n->peer,
		       strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static void create_interface(struct netif *n, const uint8_t *mac)
{
	char lladdr[20];

	destroy_interface(n); /* also clears what a crashed run left */
	memcpy(n->mac, mac, 6);
	snprintf(lladdr, sizeof(lladdr), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
		 mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (run("/sbin/ifconfig", n->peer, "create", NULL) != 0 ||
	    run("/sbin/ifconfig", n->name, "create", NULL) != 0) {
		xg_log(XG_LOG_ERR,
		       "création de l'interface %s impossible (droits administrateur requis)\n",
		       n->name);
		destroy_interface(n);
		return;
	}
	run("/sbin/ifconfig", n->name, "lladdr", lladdr, NULL);
	run("/sbin/ifconfig", n->peer, "peer", n->name, NULL);
	/* Both ends keep the same MTU, as ZeroTier does. The kernel refuses
	 * anything above net.link.fake.max_mtu (2048 by default). */
	run("/sbin/ifconfig", n->peer, "mtu", IF_MTU, NULL);
	run("/sbin/ifconfig", n->peer, "up", NULL);
	run("/sbin/ifconfig", n->name, "mtu", IF_MTU, NULL);
	/* stays down until the radio link is established */
	run("/sbin/ifconfig", n->name, "down", NULL);

	n->ndrv_fd = open_ndrv(n);
	n->bpf_fd = open_bpf(n);
	if (n->ndrv_fd < 0 || n->bpf_fd < 0) {
		destroy_interface(n);
		return;
	}
	if (pthread_create(&n->reader, NULL, reader_main, n) != 0) {
		destroy_interface(n);
		return;
	}
	n->reader_started = 1;
	n->exists = 1;
	xg_log(XG_LOG_INFO, "interface réseau %s créée (adresse %s)\n", n->name,
	       lladdr);
}

static void link_up(struct netif *n)
{
	if (!n->exists)
		return;
	n->down_since = 0;
	run("/sbin/ifconfig", n->name, "up", NULL);
	/* frames may flow before DHCP is started, so that its very first
	 * answer is not lost */
	n->link = 1;
	/* (re)starts DHCP: also right after a short loss of the radio link,
	 * where the previous lease is simply confirmed */
	run("/usr/sbin/ipconfig", "set", n->name, "DHCP", NULL);
	run("/usr/sbin/ipconfig", "set", n->name, "AUTOMATIC-V6", NULL);
	n->configured = 1;
	n->up_since = now_ms();
}

static void link_down_now(struct netif *n)
{
	n->down_since = 0;
	n->up_since = 0;
	if (!n->exists || !n->configured)
		return;
	run("/usr/sbin/ipconfig", "set", n->name, "NONE", NULL);
	run("/usr/sbin/ipconfig", "set", n->name, "NONE-V6", NULL);
	run("/sbin/ifconfig", n->name, "down", NULL);
	n->configured = 0;
	xg_log(XG_LOG_INFO, "interface %s désactivée\n", n->name);
}

static void ipv4_of(const char *name, char *out, size_t len)
{
	struct ifaddrs *list, *a;

	out[0] = 0;
	if (!name[0] || getifaddrs(&list) != 0)
		return;
	for (a = list; a; a = a->ifa_next) {
		if (a->ifa_addr && a->ifa_addr->sa_family == AF_INET &&
		    strcmp(a->ifa_name, name) == 0) {
			struct sockaddr_in *sin = (struct sockaddr_in *)a->ifa_addr;

			if ((ntohl(sin->sin_addr.s_addr) >> 16) == 0xa9fe)
				continue; /* 169.254: self-assigned */
			inet_ntop(AF_INET, &sin->sin_addr, out, (socklen_t)len);
			break;
		}
	}
	freeifaddrs(list);
}

static void *worker_main(void *arg)
{
	struct netif *n = arg;

	pthread_setname_np("xg760a-netif");
	pthread_mutex_lock(&n->lock);
	for (;;) {
		struct cmd *c = n->head;
		uint64_t now;

		if (!c) {
			struct timespec wait = { 0, 500 * 1000000L };

			if (n->quit)
				break;
			pthread_cond_timedwait_relative_np(&n->cond, &n->lock,
							   &wait);
			c = n->head;
		}
		if (c) {
			n->head = c->next;
			if (!n->head)
				n->tail = NULL;
		}
		pthread_mutex_unlock(&n->lock);

		if (c) {
			switch (c->type) {
			case CMD_DEVICE_ON:
				create_interface(n, c->mac);
				break;
			case CMD_DEVICE_OFF:
				destroy_interface(n);
				break;
			case CMD_LINK_UP:
				link_up(n);
				break;
			case CMD_LINK_DOWN:
				/* keep the addresses a little: connections
				 * survive a brief loss of the access point */
				n->link = 0;
				if (n->configured && !n->down_since)
					n->down_since = now_ms();
				break;
			}
			free(c);
		}

		now = now_ms();
		if (n->down_since && now - n->down_since > LINK_DOWN_GRACE_MS)
			link_down_now(n);
		if (n->up_since) {
			char ip[32];

			ipv4_of(n->name, ip, sizeof(ip));
			if (ip[0]) {
				xg_log(XG_LOG_INFO,
				       "interface %s configurée: adresse %s\n",
				       n->name, ip);
				n->up_since = 0;
			} else if (now - n->up_since > 30000) {
				xg_log(XG_LOG_WARN,
				       "interface %s: toujours pas d'adresse IP après 30 s (serveur DHCP muet ?)\n",
				       n->name);
				n->up_since = 0;
			}
		}
		pthread_mutex_lock(&n->lock);
	}
	pthread_mutex_unlock(&n->lock);
	destroy_interface(n);
	return NULL;
}

static void post(struct netif *n, int type, const uint8_t *mac)
{
	struct cmd *c = calloc(1, sizeof(*c));

	if (!c)
		return;
	c->type = type;
	if (mac)
		memcpy(c->mac, mac, 6);
	pthread_mutex_lock(&n->lock);
	if (n->tail)
		n->tail->next = c;
	else
		n->head = c;
	n->tail = c;
	pthread_cond_signal(&n->cond);
	pthread_mutex_unlock(&n->lock);
}

struct netif *netif_new(void)
{
	struct netif *n = calloc(1, sizeof(*n));

	if (!n)
		return NULL;
	snprintf(n->name, sizeof(n->name), "feth%d", IF_NUMBER);
	snprintf(n->peer, sizeof(n->peer), "feth%d", IF_NUMBER + 5000);
	n->bpf_fd = n->ndrv_fd = -1;
	pthread_mutex_init(&n->lock, NULL);
	pthread_cond_init(&n->cond, NULL);
	if (pthread_create(&n->worker, NULL, worker_main, n) != 0) {
		free(n);
		return NULL;
	}
	n->worker_started = 1;
	return n;
}

void netif_set_wlan(struct netif *n, struct wlan *w)
{
	n->wlan = w;
}

void netif_device(struct netif *n, int present, const uint8_t *mac)
{
	post(n, present ? CMD_DEVICE_ON : CMD_DEVICE_OFF, mac);
}

void netif_link(struct netif *n, int up)
{
	post(n, up ? CMD_LINK_UP : CMD_LINK_DOWN, NULL);
}

void netif_get_info(struct netif *n, char *name, size_t name_len, char *ipv4,
		    size_t ipv4_len)
{
	snprintf(name, name_len, "%s", n->exists ? n->name : "");
	ipv4[0] = 0;
	if (n->exists)
		ipv4_of(n->name, ipv4, ipv4_len);
}

void netif_free(struct netif *n)
{
	if (!n)
		return;
	pthread_mutex_lock(&n->lock);
	n->quit = 1;
	pthread_cond_broadcast(&n->cond);
	pthread_mutex_unlock(&n->lock);
	if (n->worker_started)
		pthread_join(n->worker, NULL);
	pthread_mutex_destroy(&n->lock);
	pthread_cond_destroy(&n->cond);
	free(n);
}
