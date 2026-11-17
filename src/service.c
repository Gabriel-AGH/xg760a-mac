/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Background service: stick + system interface + known networks + local
 * control socket.
 */
#include "service.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include "compat.h"
#include "netif.h"

static struct {
	struct wlan *w;
	struct netif *nif;
	pthread_mutex_t lock;
	struct wlan_network nets[WLAN_MAX_NETWORKS];
	int n_nets;
	int autoconnect;
	const char *config_path;
	int listen_fd;
} svc;

/* --- helpers ------------------------------------------------------------ */

int config_load(const char *path, struct wlan_network *nets, int max,
		int *autoconnect)
{
	char line[256], a[80], b[80];
	FILE *fp = fopen(path, "r");
	int n = 0;

	*autoconnect = 1;
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		int v;

		if (line[0] == '#')
			continue;
		if (sscanf(line, "auto %d", &v) == 1) {
			*autoconnect = v != 0;
		} else if (sscanf(line, "network %79s %79s", a, b) == 2 &&
			   n < max) {
			struct wlan_network *net = &nets[n];
			int len;

			memset(net, 0, sizeof(*net));
			len = hex_decode(a, net->ssid, sizeof(net->ssid));
			if (len <= 0)
				continue;
			net->ssid_len = (uint8_t)len;
			if (strcmp(b, "open") != 0) {
				if (hex_decode(b, net->pmk, 32) != 32)
					continue;
				net->has_psk = 1;
			}
			n++;
		}
	}
	fclose(fp);
	return n;
}

int config_save(const char *path, const struct wlan_network *nets, int n,
		int autoconnect)
{
	char tmp[512], dir[512], *slash;
	FILE *fp;
	int fd;

	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (slash) {
		*slash = 0;
		mkdir(dir, 0755);
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	/* holds Wi-Fi keys: readable by its owner (root) only */
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -errno;
	fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		return -EIO;
	}
	fprintf(fp, "# Réseaux connus du pilote xg760a (clé Sagem XG-760A), du préféré au moins préféré.\n"
		    "# Fichier géré par la commande xg760a. Le nom du réseau est en hexadécimal ;\n"
		    "# la clé est le condensé PBKDF2 de la phrase secrète, pas la phrase elle-même.\n");
	fprintf(fp, "auto %d\n", autoconnect ? 1 : 0);
	for (int i = 0; i < n; i++) {
		char ssid[65], psk[65];

		hex_encode(nets[i].ssid, nets[i].ssid_len, ssid);
		hex_encode(nets[i].pmk, 32, psk);
		fprintf(fp, "network %s %s\n", ssid,
			nets[i].has_psk ? psk : "open");
		memset(psk, 0, sizeof(psk));
	}
	if (fclose(fp) != 0 || rename(tmp, path) != 0) {
		unlink(tmp);
		return -EIO;
	}
	return 0;
}

/* --- wlan callbacks ----------------------------------------------------- */

static void on_device(void *ctx, int present, const uint8_t *addr)
{
	netif_device(svc.nif, present, addr);
}

static void on_link(void *ctx, int up)
{
	netif_link(svc.nif, up);
}

static void on_packet(void *ctx, const uint8_t *eth, size_t len)
{
	netif_rx(svc.nif, eth, len);
}

static const struct wlan_callbacks callbacks = {
	.device = on_device,
	.link = on_link,
	.rx_packet = on_packet,
};

/* --- sleep and wake ----------------------------------------------------- */

static io_connect_t power_port;

/*
 * A sleeping Mac cuts or suspends its USB ports, and the stick loses the
 * firmware we loaded into its memory. So: leave the network cleanly and
 * release the stick before sleeping, start it afresh on wake.
 */
static void power_event(void *refcon, io_service_t service, natural_t type,
			void *arg)
{
	switch (type) {
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(power_port, (long)arg);
		break;
	case kIOMessageSystemWillSleep:
		wlan_suspend(svc.w);
		IOAllowPowerChange(power_port, (long)arg);
		break;
	case kIOMessageSystemHasPoweredOn:
		xg_log(XG_LOG_INFO, "réveil du Mac\n");
		wlan_resume(svc.w);
		break;
	default:
		break;
	}
}

static void *power_main(void *arg)
{
	IONotificationPortRef port = NULL;
	io_object_t notifier = IO_OBJECT_NULL;

	pthread_setname_np("xg760a-power");
	power_port = IORegisterForSystemPower(NULL, &port, power_event, &notifier);
	if (!power_port || !port) {
		xg_log(XG_LOG_WARN,
		       "suivi de la mise en veille indisponible\n");
		return NULL;
	}
	CFRunLoopAddSource(CFRunLoopGetCurrent(),
			   IONotificationPortGetRunLoopSource(port),
			   kCFRunLoopDefaultMode);
	CFRunLoopRun();
	return NULL;
}

/* --- requests ----------------------------------------------------------- */

struct reply {
	char *buf;
	size_t len, cap;
};

static void reply_add(struct reply *r, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void reply_add(struct reply *r, const char *fmt, ...)
{
	char line[512];
	va_list ap;
	size_t n;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	n = strlen(line);
	if (r->len + n + 1 > r->cap) {
		size_t cap = (r->cap + n + 1) * 2;
		char *nb = realloc(r->buf, cap);

		if (!nb)
			return;
		r->buf = nb;
		r->cap = cap;
	}
	memcpy(r->buf + r->len, line, n + 1);
	r->len += n;
}

/* svc.lock held */
static void apply_networks(void)
{
	wlan_set_networks(svc.w, svc.nets, svc.autoconnect ? svc.n_nets : 0);
	if (svc.config_path) {
		int r = config_save(svc.config_path, svc.nets, svc.n_nets,
				    svc.autoconnect);

		if (r)
			xg_log(XG_LOG_WARN,
			       "enregistrement de la configuration impossible (%d)\n",
			       r);
	}
}

static void do_status(struct reply *r)
{
	struct wlan_status st;
	char ssid[65], name[32], ip[32];

	wlan_get_status(svc.w, &st);
	netif_get_info(svc.nif, name, sizeof(name), ip, sizeof(ip));
	hex_encode(st.ssid, st.ssid_len, ssid);
	reply_add(r, "version=%s\n", XG_VERSION);
	reply_add(r, "device=%s\n", st.device_present ? st.device : "");
	reply_add(r, "regdomain=%s\n", st.regdomain);
	reply_add(r, "mac=%02x:%02x:%02x:%02x:%02x:%02x\n", st.addr[0],
		  st.addr[1], st.addr[2], st.addr[3], st.addr[4], st.addr[5]);
	reply_add(r, "state=%d\n", (int)st.state);
	reply_add(r, "ssid=%s\n", ssid);
	reply_add(r, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n", st.bssid[0],
		  st.bssid[1], st.bssid[2], st.bssid[3], st.bssid[4],
		  st.bssid[5]);
	reply_add(r, "channel=%d\n", st.channel);
	reply_add(r, "signal=%d\n", st.signal);
	reply_add(r, "security=%s\n", st.security);
	reply_add(r, "tx_rate=%d\n", st.tx_rate);
	reply_add(r, "rx_rate=%d\n", st.rx_rate);
	reply_add(r, "connected_ms=%llu\n", st.connected_ms);
	reply_add(r, "iface=%s\n", name);
	reply_add(r, "ipv4=%s\n", ip);
	reply_add(r, "error=%s\n", st.last_error);
	reply_add(r, "rx_packets=%llu\n", st.rx_packets);
	reply_add(r, "tx_packets=%llu\n", st.tx_packets);
	reply_add(r, "rx_dropped=%llu\n", st.rx_dropped);
	reply_add(r, "tx_dropped=%llu\n", st.tx_dropped);
	reply_add(r, "tx_retried=%llu\n", st.tx_retried);
	reply_add(r, "tx_failed=%llu\n", st.tx_failed);
	reply_add(r, "rx_crypt_errors=%llu\n", st.rx_crypt_errors);
	pthread_mutex_lock(&svc.lock);
	reply_add(r, "autoconnect=%d\n", svc.autoconnect);
	reply_add(r, "known=%d\n", svc.n_nets);
	pthread_mutex_unlock(&svc.lock);
}

static void do_scan(struct reply *r)
{
	static struct wlan_bss list[WLAN_MAX_BSS];
	int n = wlan_scan(svc.w, list, WLAN_MAX_BSS);

	if (n < 0) {
		reply_add(r, "error\t%s\n",
			  n == -ENODEV ? "clé Wi-Fi non branchée" :
					 "recherche impossible pour l'instant");
		return;
	}
	for (int i = 0; i < n; i++) {
		char ssid[65];
		int usable;
		const char *sec = wlan_bss_security(&list[i], &usable);

		hex_encode(list[i].ssid, list[i].ssid_len, ssid);
		reply_add(r,
			  "bss\t%s\t%02x:%02x:%02x:%02x:%02x:%02x\t%d\t%d\t%d\t%d\t%s\n",
			  ssid[0] ? ssid : "-", list[i].bssid[0],
			  list[i].bssid[1], list[i].bssid[2], list[i].bssid[3],
			  list[i].bssid[4], list[i].bssid[5], list[i].channel,
			  list[i].signal, usable, list[i].has_ht, sec);
	}
	reply_add(r, "ok\n");
}

static int find_net(const uint8_t *ssid, int len)
{
	for (int i = 0; i < svc.n_nets; i++)
		if (svc.nets[i].ssid_len == len &&
		    memcmp(svc.nets[i].ssid, ssid, (size_t)len) == 0)
			return i;
	return -1;
}

static void do_connect(struct reply *r, const char *ssid_hex, const char *psk)
{
	struct wlan_network net;
	int len, idx;

	memset(&net, 0, sizeof(net));
	len = hex_decode(ssid_hex, net.ssid, sizeof(net.ssid));
	if (len <= 0) {
		reply_add(r, "error\tnom de réseau invalide\n");
		return;
	}
	net.ssid_len = (uint8_t)len;

	pthread_mutex_lock(&svc.lock);
	idx = find_net(net.ssid, len);
	if (strcmp(psk, "open") == 0) {
		net.has_psk = 0;
	} else if (strcmp(psk, "known") == 0) {
		/* reuse the stored key */
		if (idx < 0) {
			pthread_mutex_unlock(&svc.lock);
			reply_add(r, "error\tréseau inconnu: un mot de passe est nécessaire\n");
			return;
		}
		net = svc.nets[idx];
	} else if (hex_decode(psk, net.pmk, 32) == 32) {
		net.has_psk = 1;
	} else {
		pthread_mutex_unlock(&svc.lock);
		reply_add(r, "error\tclé invalide\n");
		return;
	}
	/* most recently chosen network first */
	if (idx >= 0) {
		memmove(&svc.nets[idx], &svc.nets[idx + 1],
			(size_t)(svc.n_nets - idx - 1) * sizeof(net));
		svc.n_nets--;
	}
	if (svc.n_nets >= WLAN_MAX_NETWORKS)
		svc.n_nets = WLAN_MAX_NETWORKS - 1;
	memmove(&svc.nets[1], &svc.nets[0], (size_t)svc.n_nets * sizeof(net));
	svc.nets[0] = net;
	svc.n_nets++;
	svc.autoconnect = 1;
	apply_networks();
	pthread_mutex_unlock(&svc.lock);
	memset(&net, 0, sizeof(net));
	reply_add(r, "ok\n");
}

static void do_forget(struct reply *r, const char *ssid_hex)
{
	uint8_t ssid[32];
	int len = hex_decode(ssid_hex, ssid, sizeof(ssid));
	int idx;

	pthread_mutex_lock(&svc.lock);
	idx = len > 0 ? find_net(ssid, len) : -1;
	if (idx < 0) {
		pthread_mutex_unlock(&svc.lock);
		reply_add(r, "error\tréseau inconnu\n");
		return;
	}
	memmove(&svc.nets[idx], &svc.nets[idx + 1],
		(size_t)(svc.n_nets - idx - 1) * sizeof(svc.nets[0]));
	svc.n_nets--;
	memset(&svc.nets[svc.n_nets], 0, sizeof(svc.nets[0]));
	apply_networks();
	pthread_mutex_unlock(&svc.lock);
	reply_add(r, "ok\n");
}

static void handle_request(char *line, struct reply *r)
{
	char cmd[32] = "", a[128] = "", b[128] = "";

	sscanf(line, "%31s %127s %127s", cmd, a, b);
	if (!strcmp(cmd, "STATUS")) {
		do_status(r);
	} else if (!strcmp(cmd, "SCAN")) {
		do_scan(r);
	} else if (!strcmp(cmd, "LIST")) {
		pthread_mutex_lock(&svc.lock);
		for (int i = 0; i < svc.n_nets; i++) {
			char ssid[65];

			hex_encode(svc.nets[i].ssid, svc.nets[i].ssid_len, ssid);
			reply_add(r, "net\t%s\t%d\n", ssid, svc.nets[i].has_psk);
		}
		reply_add(r, "auto\t%d\n", svc.autoconnect);
		pthread_mutex_unlock(&svc.lock);
		reply_add(r, "ok\n");
	} else if (!strcmp(cmd, "CONNECT") && a[0] && b[0]) {
		do_connect(r, a, b);
	} else if (!strcmp(cmd, "DISCONNECT")) {
		pthread_mutex_lock(&svc.lock);
		svc.autoconnect = 0;
		apply_networks();
		pthread_mutex_unlock(&svc.lock);
		reply_add(r, "ok\n");
	} else if (!strcmp(cmd, "FORGET") && a[0]) {
		do_forget(r, a);
	} else if (!strcmp(cmd, "SUSPEND")) {
		/* what happens when the Mac goes to sleep, for testing */
		wlan_suspend(svc.w);
		reply_add(r, "ok\n");
	} else if (!strcmp(cmd, "RESUME")) {
		wlan_resume(svc.w);
		reply_add(r, "ok\n");
	} else {
		reply_add(r, "error\tcommande inconnue\n");
	}
	memset(line, 0, strlen(line));
	memset(b, 0, sizeof(b));
}

static void *server_main(void *arg)
{
	pthread_setname_np("xg760a-ctl");
	for (;;) {
		struct timeval tv = { 5, 0 };
		struct reply r = { 0 };
		char line[512];
		size_t got = 0;
		int fd = accept(svc.listen_fd, NULL, NULL);

		if (fd < 0) {
			if (errno == EINTR)
				continue;
			break; /* socket closed: we are shutting down */
		}
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		while (got < sizeof(line) - 1) {
			ssize_t n = read(fd, line + got, sizeof(line) - 1 - got);

			if (n <= 0)
				break;
			got += (size_t)n;
			if (memchr(line, '\n', got))
				break;
		}
		line[got] = 0;
		line[strcspn(line, "\r\n")] = 0;
		if (line[0]) {
			handle_request(line, &r);
			for (size_t off = 0; r.buf && off < r.len;) {
				ssize_t n = write(fd, r.buf + off, r.len - off);

				if (n <= 0)
					break;
				off += (size_t)n;
			}
		}
		free(r.buf);
		close(fd);
	}
	return NULL;
}

static int open_socket(const char *path)
{
	struct sockaddr_un sa;
	int fd;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		xg_log(XG_LOG_ERR, "chemin de socket trop long: %s\n", path);
		return -1;
	}
	/* refuse to start twice */
	{
		char *probe = service_request(path, "STATUS");

		if (probe) {
			free(probe);
			xg_log(XG_LOG_ERR, "le service xg760a tourne déjà\n");
			return -1;
		}
	}
	unlink(path);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(fd, 8) != 0) {
		xg_log(XG_LOG_ERR, "socket de commande %s: %s\n", path,
		       strerror(errno));
		close(fd);
		return -1;
	}
	/* administrators of this Mac may drive the service */
	chown(path, 0, 80 /* admin */);
	chmod(path, 0660);
	return fd;
}

int service_run(const struct service_options *opt)
{
	pthread_t server, power;
	sigset_t set;
	int sig = 0;

	memset(&svc, 0, sizeof(svc));
	pthread_mutex_init(&svc.lock, NULL);
	svc.config_path = opt->config_path;
	svc.autoconnect = 1;
	if (opt->config_path)
		svc.n_nets = config_load(opt->config_path, svc.nets,
					 WLAN_MAX_NETWORKS, &svc.autoconnect);
	if (!svc.n_nets && opt->initial && opt->n_initial > 0) {
		svc.n_nets = opt->n_initial > WLAN_MAX_NETWORKS ?
			WLAN_MAX_NETWORKS : opt->n_initial;
		memcpy(svc.nets, opt->initial,
		       (size_t)svc.n_nets * sizeof(svc.nets[0]));
	}

	/* every thread created from here on leaves these to the main one */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	signal(SIGPIPE, SIG_IGN);

	svc.listen_fd = open_socket(opt->socket_path);
	if (svc.listen_fd < 0)
		return 1;

	svc.nif = netif_new();
	svc.w = wlan_create(&callbacks, NULL);
	if (!svc.nif || !svc.w) {
		xg_log(XG_LOG_ERR, "démarrage impossible\n");
		return 1;
	}
	netif_set_wlan(svc.nif, svc.w);
	wlan_set_networks(svc.w, svc.nets, svc.autoconnect ? svc.n_nets : 0);
	if (pthread_create(&server, NULL, server_main, NULL) != 0)
		return 1;
	if (pthread_create(&power, NULL, power_main, NULL) == 0)
		pthread_detach(power);

	xg_log(XG_LOG_INFO, "service xg760a %s démarré (%d réseau(x) connu(s))\n",
	       XG_VERSION, svc.n_nets);
	sigwait(&set, &sig);
	xg_log(XG_LOG_INFO, "arrêt demandé (signal %d)\n", sig);

	close(svc.listen_fd);
	unlink(opt->socket_path);
	pthread_join(server, NULL);
	/* radio first (says goodbye to the access point), interface last */
	wlan_destroy(svc.w);
	netif_free(svc.nif);
	memset(svc.nets, 0, sizeof(svc.nets));
	xg_log(XG_LOG_INFO, "service arrêté\n");
	return 0;
}
