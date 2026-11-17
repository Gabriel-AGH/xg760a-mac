/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * xg760a - pilote en espace utilisateur de la cle Wi-Fi Sagem XG-760A
 * (ZyDAS ZD1211) pour macOS. Outil en ligne de commande et service.
 */
#include <readpassphrase.h>
#include <signal.h>

#include "compat.h"
#include "crypto.h"
#include "ministack.h"
#include "service.h"
#include "wlan.h"

static const char *sock_path = XG_SOCKET_PATH;
static const char *config_path = XG_CONFIG_FILE;
/* development aid: lets the service run unprivileged, where it cannot
 * create the network interface but everything else can be exercised */
static int allow_unprivileged;

static void usage(void)
{
	printf(
"xg760a %s - clé Wi-Fi Sagem XG-760A (ZyDAS ZD1211) sous macOS\n"
"\n"
"Commandes courantes (le service doit tourner) :\n"
"  xg760a scan                 réseaux Wi-Fi à portée\n"
"  xg760a connect <réseau>     se connecter (le mot de passe est demandé) et mémoriser\n"
"  xg760a status               état de la clé et de la connexion\n"
"  xg760a disconnect           se déconnecter jusqu'au prochain « connect »\n"
"  xg760a list                 réseaux mémorisés\n"
"  xg760a forget <réseau>      oublier un réseau\n"
"\n"
"Sans installation :\n"
"  xg760a test <réseau>        essai complet sans droits administrateur :\n"
"                              connexion, adresse DHCP, ping, mesure de débit\n"
"                              (aucune interface réseau n'est créée)\n"
"  sudo xg760a run <réseau>    connexion avec interface réseau, jusqu'à Ctrl-C\n"
"\n"
"Service :\n"
"  sudo xg760a daemon          service d'arrière-plan (lancé par launchd une fois installé)\n"
"\n"
"Options : -v messages détaillés, -vv très détaillés\n",
		XG_VERSION);
}

/* --- small text helpers ------------------------------------------------- */

static void print_ssid(const uint8_t *ssid, size_t len, int width)
{
	int cols = 0;

	for (size_t i = 0; i < len; i++) {
		uint8_t c = ssid[i];

		if (c < 0x20 || c == 0x7f)
			c = '?';
		putchar(c);
		if ((c & 0xc0) != 0x80) /* not a UTF-8 continuation byte */
			cols++;
	}
	for (; cols < width; cols++)
		putchar(' ');
}

static const char *signal_bars(int signal)
{
	if (signal >= 55)
		return "||||";
	if (signal >= 40)
		return "|||.";
	if (signal >= 25)
		return "||..";
	if (signal >= 12)
		return "|...";
	return "....";
}

static int ask_passphrase(const char *ssid, char *out, size_t max)
{
	char prompt[128];

	if (!isatty(STDIN_FILENO)) {
		/* piped in, for scripts */
		if (!fgets(out, (int)max, stdin))
			return -1;
		out[strcspn(out, "\r\n")] = 0;
		return 0;
	}
	snprintf(prompt, sizeof(prompt), "Mot de passe Wi-Fi de « %s » : ", ssid);
	if (!readpassphrase(prompt, out, max, RPP_ECHO_OFF))
		return -1;
	return 0;
}

/* value of "key=" in a STATUS answer ("" if absent); not reentrant */
static const char *field(const char *reply, const char *key)
{
	static char bufs[8][256];
	static int which;
	char *out = bufs[which++ & 7];
	size_t klen = strlen(key);
	const char *p = reply;

	out[0] = 0;
	while (p && *p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
			size_t n = strcspn(p + klen + 1, "\n");

			if (n > 255)
				n = 255;
			memcpy(out, p + klen + 1, n);
			out[n] = 0;
			break;
		}
		p = strchr(p, '\n');
		if (p)
			p++;
	}
	return out;
}

static char *request_or_explain(const char *line)
{
	char *reply = service_request(sock_path, line);

	if (!reply) {
		if (errno == EACCES)
			fprintf(stderr,
				"Accès refusé au service xg760a : cette commande est réservée aux administrateurs de ce Mac.\n");
		else
			fprintf(stderr,
				"Le service xg760a ne tourne pas.\n"
				"  - pour un essai immédiat :  sudo xg760a run <réseau>\n"
				"  - sans droits administrateur : xg760a test <réseau>\n"
				"  - pour l'installer à demeure : voir LISEZMOI.md\n");
	}
	return reply;
}

/* --- scan --------------------------------------------------------------- */

static void print_scan_header(void)
{
	/* padded by hand: printf counts bytes, not accented letters */
	printf("Réseau                            Signal   Canal  Protection\n");
}

static void print_scan_row(const uint8_t *ssid, size_t ssid_len, int signal,
			   int channel, const char *security, int usable, int ht)
{
	if (ssid_len)
		print_ssid(ssid, ssid_len, 32);
	else
		print_ssid((const uint8_t *)"(nom masqué)",
			   strlen("(nom masqué)"), 32);
	printf("  %s %2d%%  %5d  %s%s\n", signal_bars(signal), signal, channel,
	       security, usable ? "" : "  [non pris en charge]");
	(void)ht;
}

static void null_device(void *ctx, int present, const uint8_t *addr) { }
static void null_link(void *ctx, int up) { }
static void null_packet(void *ctx, const uint8_t *eth, size_t len) { }

static const struct wlan_callbacks null_callbacks = {
	.device = null_device,
	.link = null_link,
	.rx_packet = null_packet,
};

static int cmd_scan_direct(void)
{
	static struct wlan_bss list[WLAN_MAX_BSS];
	struct wlan *w = wlan_create(&null_callbacks, NULL);
	int n;

	if (!w)
		return 1;
	if (wlan_wait_device(w, 12000)) {
		fprintf(stderr, "Clé Wi-Fi introuvable : est-elle branchée ?\n");
		wlan_destroy(w);
		return 1;
	}
	n = wlan_scan(w, list, WLAN_MAX_BSS);
	if (n < 0) {
		fprintf(stderr, "Recherche impossible (%d).\n", n);
		wlan_destroy(w);
		return 1;
	}
	print_scan_header();
	for (int i = 0; i < n; i++) {
		int usable;
		const char *sec = wlan_bss_security(&list[i], &usable);

		print_scan_row(list[i].ssid, list[i].ssid_len, list[i].signal,
			       list[i].channel, sec, usable, list[i].has_ht);
	}
	printf("%d réseau(x).\n", n);
	wlan_destroy(w);
	return 0;
}

static int cmd_scan(void)
{
	char *reply = service_request(sock_path, "SCAN");
	char *line, *save = NULL;
	int n = 0, rc = 0;

	if (!reply) {
		if (errno == EACCES) {
			free(request_or_explain("SCAN"));
			return 1;
		}
		/* no service: talk to the stick directly, no rights needed */
		return cmd_scan_direct();
	}
	print_scan_header();
	for (line = strtok_r(reply, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char ssid_hex[80], bssid[24], sec[64];
		uint8_t ssid[32];
		int channel, signal, usable, ht, len;

		if (!strncmp(line, "error\t", 6)) {
			fprintf(stderr, "%s\n", line + 6);
			rc = 1;
			continue;
		}
		if (sscanf(line, "bss\t%79[^\t]\t%23[^\t]\t%d\t%d\t%d\t%d\t%63[^\n]",
			   ssid_hex, bssid, &channel, &signal, &usable, &ht,
			   sec) != 7)
			continue;
		len = strcmp(ssid_hex, "-") ? hex_decode(ssid_hex, ssid, 32) : 0;
		print_scan_row(ssid, len > 0 ? (size_t)len : 0, signal, channel,
			       sec, usable, ht);
		n++;
	}
	if (!rc)
		printf("%d réseau(x).\n", n);
	free(reply);
	return rc;
}

/* --- status ------------------------------------------------------------- */

static void print_status(const char *reply)
{
	int state = atoi(field(reply, "state"));
	uint8_t ssid[32];
	int ssid_len = hex_decode(field(reply, "ssid"), ssid, 32);
	const char *dev = field(reply, "device");

	if (!dev[0]) {
		printf("Clé Wi-Fi     : non branchée (le service l'attend)\n");
		return;
	}
	printf("Clé Wi-Fi     : %s\n", dev);
	printf("Adresse MAC   : %s, domaine %s\n", field(reply, "mac"),
	       field(reply, "regdomain"));
	printf("État          : %s\n", wlan_state_name((enum wlan_state)state));
	if (state >= WLAN_AUTHENTICATING && ssid_len > 0) {
		printf("Réseau        : ");
		print_ssid(ssid, (size_t)ssid_len, 0);
		printf(" (%s), canal %s, %s\n", field(reply, "bssid"),
		       field(reply, "channel"), field(reply, "security"));
		printf("Signal        : %s %s %%\n",
		       signal_bars(atoi(field(reply, "signal"))),
		       field(reply, "signal"));
	}
	if (state == WLAN_CONNECTED) {
		unsigned long long ms = strtoull(field(reply, "connected_ms"),
						 NULL, 10);
		const char *ip = field(reply, "ipv4");

		printf("Débit radio   : émission %g Mbit/s, réception %g Mbit/s\n",
		       atoi(field(reply, "tx_rate")) / 2.0,
		       atoi(field(reply, "rx_rate")) / 2.0);
		printf("Interface     : %s, %s%s\n", field(reply, "iface"),
		       ip[0] ? "adresse " : "pas encore d'adresse IP",
		       ip);
		printf("Connecté      : depuis %llu min %02llu s\n", ms / 60000,
		       (ms / 1000) % 60);
		printf("Trafic        : %s paquets reçus, %s émis ; trames reprises %s, abandonnées %s\n",
		       field(reply, "rx_packets"), field(reply, "tx_packets"),
		       field(reply, "tx_retried"), field(reply, "tx_failed"));
	}
	if (field(reply, "error")[0])
		printf("Dernier souci : %s\n", field(reply, "error"));
	if (!atoi(field(reply, "autoconnect")))
		printf("Connexion automatique suspendue (xg760a connect <réseau> pour reprendre).\n");
	else if (!atoi(field(reply, "known")))
		printf("Aucun réseau mémorisé : xg760a connect <réseau>.\n");
}

static int cmd_status(void)
{
	char *reply = request_or_explain("STATUS");

	if (!reply)
		return 1;
	print_status(reply);
	free(reply);
	return 0;
}

/* --- connect ------------------------------------------------------------ */

static int make_network(const char *ssid, const char *pass,
			struct wlan_network *net)
{
	size_t len = strlen(ssid);

	memset(net, 0, sizeof(*net));
	if (len == 0 || len > 32) {
		fprintf(stderr, "Nom de réseau invalide (1 à 32 caractères).\n");
		return -1;
	}
	net->ssid_len = (uint8_t)len;
	memcpy(net->ssid, ssid, len);
	if (pass && pass[0]) {
		if (wpa_passphrase_to_pmk(pass, net->ssid, len, net->pmk)) {
			fprintf(stderr,
				"Mot de passe invalide : une clé WPA compte 8 à 63 caractères.\n");
			return -1;
		}
		net->has_psk = 1;
	}
	return 0;
}

static int cmd_connect(const char *ssid, int new_password)
{
	char ssid_hex[65], psk_hex[65], req[256], pass[128] = "";
	struct wlan_network net;
	char *reply;
	const char *psk = NULL;
	int secured = 1, known = 0, seen = 0;
	int last_state = -1;

	if (strlen(ssid) == 0 || strlen(ssid) > 32) {
		fprintf(stderr, "Nom de réseau invalide (1 à 32 caractères).\n");
		return 1;
	}
	hex_encode((const uint8_t *)ssid, strlen(ssid), ssid_hex);

	reply = request_or_explain("LIST");
	if (!reply)
		return 1;
	snprintf(req, sizeof(req), "net\t%s\t", ssid_hex);
	known = strstr(reply, req) != NULL;
	free(reply);

	/* is it in range, and is it protected? */
	printf("Recherche de « %s »...\n", ssid);
	reply = service_request(sock_path, "SCAN");
	if (reply) {
		char *line, *save = NULL;

		for (line = strtok_r(reply, "\n", &save); line;
		     line = strtok_r(NULL, "\n", &save)) {
			char h[80], bssid[24], sec[64];
			int ch, sig, usable, ht;

			if (sscanf(line, "bss\t%79[^\t]\t%23[^\t]\t%d\t%d\t%d\t%d\t%63[^\n]",
				   h, bssid, &ch, &sig, &usable, &ht, sec) != 7 ||
			    strcmp(h, ssid_hex) != 0)
				continue;
			if (!seen || !usable)
				secured = strcmp(sec, "ouvert") != 0;
			seen = 1;
			if (!usable) {
				fprintf(stderr,
					"Ce réseau utilise une protection que la clé ne sait pas gérer (%s).\n",
					sec);
				free(reply);
				return 1;
			}
		}
		free(reply);
	}
	if (!seen)
		printf("Réseau non vu pour l'instant (hors de portée ou nom masqué) ; il sera rejoint dès qu'il répondra.\n");

	if (!secured) {
		psk = "open";
	} else if (known && !new_password) {
		psk = "known";
	} else {
		if (ask_passphrase(ssid, pass, sizeof(pass)))
			return 1;
		if (!pass[0] && !seen) {
			psk = "open";
		} else {
			if (make_network(ssid, pass, &net)) {
				memset(pass, 0, sizeof(pass));
				return 1;
			}
			hex_encode(net.pmk, 32, psk_hex);
			psk = psk_hex;
			memset(&net, 0, sizeof(net));
		}
		memset(pass, 0, sizeof(pass));
	}

	snprintf(req, sizeof(req), "CONNECT %s %s", ssid_hex, psk);
	reply = request_or_explain(req);
	memset(req, 0, sizeof(req));
	memset(psk_hex, 0, sizeof(psk_hex));
	if (!reply)
		return 1;
	if (strncmp(reply, "ok", 2) != 0) {
		fprintf(stderr, "%s", !strncmp(reply, "error\t", 6) ? reply + 6 :
								     reply);
		free(reply);
		return 1;
	}
	free(reply);

	/* follow the attempt */
	for (int i = 0; i < 90; i++) {
		int state;
		const char *err;

		usleep(500 * 1000);
		reply = service_request(sock_path, "STATUS");
		if (!reply)
			break;
		state = atoi(field(reply, "state"));
		err = field(reply, "error");
		if (state != last_state && state > WLAN_IDLE) {
			printf("  %s...\n", wlan_state_name((enum wlan_state)state));
			last_state = state;
		}
		if (state == WLAN_CONNECTED) {
			const char *ip = field(reply, "ipv4");

			if (ip[0] || i >= 60) {
				printf("Connecté à « %s » : interface %s, %s%s\n",
				       ssid, field(reply, "iface"),
				       ip[0] ? "adresse " :
					       "pas encore d'adresse IP (voir xg760a status)",
				       ip);
				free(reply);
				return 0;
			}
		} else if (err[0] && state <= WLAN_SCANNING && i >= 6 &&
			   (strstr(err, "mot de passe") ||
			    strstr(err, "non prise en charge"))) {
			fprintf(stderr, "Échec : %s\n", err);
			if (strstr(err, "mot de passe")) {
				/* do not keep a key the access point refuses:
				 * the next attempt must ask again */
				snprintf(req, sizeof(req), "FORGET %s", ssid_hex);
				free(service_request(sock_path, req));
				fprintf(stderr,
					"Le réseau n'a pas été mémorisé ; relancez la commande pour ressaisir le mot de passe.\n");
			}
			free(reply);
			return 1;
		} else if (i == 60 && err[0]) {
			printf("  toujours en cours (%s)\n", err);
		}
		free(reply);
	}
	printf("Pas encore connecté ; le service continue d'essayer (xg760a status pour suivre).\n");
	return 1;
}

static int cmd_simple(const char *req, const char *done)
{
	char *reply = request_or_explain(req);

	if (!reply)
		return 1;
	if (strncmp(reply, "ok", 2) != 0) {
		fprintf(stderr, "%s", !strncmp(reply, "error\t", 6) ? reply + 6 :
								     reply);
		free(reply);
		return 1;
	}
	printf("%s\n", done);
	free(reply);
	return 0;
}

static int cmd_list(void)
{
	char *reply = request_or_explain("LIST");
	char *line, *save = NULL;
	int n = 0;

	if (!reply)
		return 1;
	for (line = strtok_r(reply, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char h[80];
		uint8_t ssid[32];
		int secured, len;

		if (sscanf(line, "net\t%79[^\t]\t%d", h, &secured) != 2)
			continue;
		len = hex_decode(h, ssid, 32);
		if (len <= 0)
			continue;
		printf("%d. ", ++n);
		print_ssid(ssid, (size_t)len, 0);
		printf("%s\n", secured ? "" : " (ouvert)");
	}
	if (!n)
		printf("Aucun réseau mémorisé.\n");
	free(reply);
	return 0;
}

/* --- test (no administrator rights) ------------------------------------- */

static struct ministack *test_stack;

static void test_device(void *ctx, int present, const uint8_t *addr) { }

static void test_link(void *ctx, int up) { }

static void test_packet(void *ctx, const uint8_t *eth, size_t len)
{
	if (test_stack)
		ministack_rx(test_stack, eth, len);
}

static const struct wlan_callbacks test_callbacks = {
	.device = test_device,
	.link = test_link,
	.rx_packet = test_packet,
};

static int cmd_test(const char *ssid)
{
	struct wlan_network net;
	struct wlan_status st;
	struct wlan *w;
	char pass[128] = "";
	char *probe;
	int rc = 1, ok = 0;

	probe = service_request(sock_path, "STATUS");
	if (probe) {
		free(probe);
		fprintf(stderr,
			"Le service xg760a utilise déjà la clé : « xg760a status » donne l'état de la connexion.\n"
			"Pour refaire cet essai, arrêtez d'abord le service.\n");
		return 1;
	}
	if (ask_passphrase(ssid, pass, sizeof(pass)))
		return 1;
	if (make_network(ssid, pass, &net)) {
		memset(pass, 0, sizeof(pass));
		return 1;
	}
	memset(pass, 0, sizeof(pass));

	printf("Démarrage de la clé...\n");
	w = wlan_create(&test_callbacks, NULL);
	if (!w)
		return 1;
	if (wlan_wait_device(w, 12000)) {
		fprintf(stderr, "Clé Wi-Fi introuvable : est-elle branchée ?\n");
		goto out;
	}
	wlan_get_status(w, &st);
	printf("  %s\n  adresse %02x:%02x:%02x:%02x:%02x:%02x\n", st.device,
	       st.addr[0], st.addr[1], st.addr[2], st.addr[3], st.addr[4],
	       st.addr[5]);
	test_stack = ministack_new(st.addr);
	ministack_attach(test_stack, w);

	printf("Connexion à « %s »...\n", ssid);
	wlan_set_networks(w, &net, 1);
	memset(&net, 0, sizeof(net));
	for (int i = 0; i < 50 && !ok; i++) {
		usleep(500 * 1000);
		wlan_get_status(w, &st);
		if (st.state == WLAN_CONNECTED)
			ok = 1;
		else if (st.last_error[0] && st.state <= WLAN_SCANNING &&
			 (strstr(st.last_error, "mot de passe") ||
			  strstr(st.last_error, "non prise en charge") ||
			  strstr(st.last_error, "est protégé") ||
			  strstr(st.last_error, "réseau ouvert")))
			break;
	}
	if (!ok) {
		fprintf(stderr, "Connexion impossible : %s\n",
			st.last_error[0] ? st.last_error : "délai dépassé");
		goto out;
	}
	printf("  connecté : canal %d, signal %d %%, %s\n", st.channel, st.signal,
	       st.security);

	rc = ministack_run(test_stack) ? 1 : 0;
	wlan_get_status(w, &st);
	printf("\n%s\n", rc ?
	       "RÉSULTAT : la liaison radio est établie mais l'essai IP a échoué (voir ci-dessus)." :
	       "RÉSULTAT : la clé fonctionne de bout en bout (WPA, DHCP, trafic IP).");
	if (st.rx_crypt_errors)
		printf("(%llu trame(s) reçue(s) non déchiffrable(s))\n",
		       st.rx_crypt_errors);
out:
	wlan_destroy(w);
	ministack_free(test_stack);
	test_stack = NULL;
	return rc;
}

/* --- service entry points ----------------------------------------------- */

static int need_root(const char *cmd)
{
	if (geteuid() == 0 || allow_unprivileged)
		return 0;
	fprintf(stderr,
		"« xg760a %s » crée une interface réseau : il faut les droits administrateur.\n"
		"  sudo xg760a %s ...\n"
		"(« xg760a test <réseau> » vérifie la clé sans ces droits.)\n",
		cmd, cmd);
	return 1;
}

static int cmd_run(const char *ssid)
{
	struct service_options opt = { .socket_path = sock_path };
	struct wlan_network net;
	char pass[128] = "";
	int rc;

	if (need_root("run"))
		return 1;
	if (ask_passphrase(ssid, pass, sizeof(pass)))
		return 1;
	if (make_network(ssid, pass, &net)) {
		memset(pass, 0, sizeof(pass));
		return 1;
	}
	memset(pass, 0, sizeof(pass));
	opt.initial = &net;
	opt.n_initial = 1;
	printf("Connexion à « %s ». Ctrl-C pour arrêter. Dans un autre terminal : xg760a status\n",
	       ssid);
	rc = service_run(&opt);
	memset(&net, 0, sizeof(net));
	return rc;
}

static int cmd_daemon(void)
{
	struct service_options opt = {
		.socket_path = sock_path,
		.config_path = config_path,
	};

	if (need_root("daemon"))
		return 1;
	return service_run(&opt);
}

int main(int argc, char **argv)
{
	const char *cmd;
	int i = 1;

	int verbose = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	/* the commands print their own results: keep the journal quiet
	 * unless asked; the service logs its activity */
	xg_log_level = XG_LOG_ERR;
	for (; i < argc && argv[i][0] == '-'; i++) {
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "-vv")) {
			xg_log_level = argv[i][2] ? XG_LOG_TRACE : XG_LOG_DBG;
			verbose = 1;
		} else if (!strcmp(argv[i], "--socket") && i + 1 < argc) {
			sock_path = argv[++i];
		} else if (!strcmp(argv[i], "--config") && i + 1 < argc) {
			config_path = argv[++i];
		} else if (!strcmp(argv[i], "--sans-root")) {
			allow_unprivileged = 1;
		} else {
			break;
		}
	}
	if (i >= argc) {
		usage();
		return 2;
	}
	cmd = argv[i++];
	if (!verbose && (!strcmp(cmd, "daemon") || !strcmp(cmd, "run")))
		xg_log_level = XG_LOG_INFO;

	if (!strcmp(cmd, "scan") || !strcmp(cmd, "liste-reseaux"))
		return cmd_scan();
	if (!strcmp(cmd, "status") || !strcmp(cmd, "etat"))
		return cmd_status();
	if (!strcmp(cmd, "list"))
		return cmd_list();
	if (!strcmp(cmd, "disconnect"))
		return cmd_simple("DISCONNECT", "Déconnecté. « xg760a connect <réseau> » pour se reconnecter.");
	if (!strcmp(cmd, "daemon"))
		return cmd_daemon();
	if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
		usage();
		return 0;
	}
	if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
		printf("xg760a %s\n", XG_VERSION);
		return 0;
	}

	/* commands that take a network name */
	if (!strcmp(cmd, "connect") || !strcmp(cmd, "test") ||
	    !strcmp(cmd, "run") || !strcmp(cmd, "forget")) {
		int new_password = 0;

		if (i < argc && !strcmp(argv[i], "--nouveau-mot-de-passe")) {
			new_password = 1;
			i++;
		}
		if (i >= argc) {
			fprintf(stderr, "Il manque le nom du réseau : xg760a %s <réseau>\n",
				cmd);
			return 2;
		}
		if (!strcmp(cmd, "connect"))
			return cmd_connect(argv[i], new_password);
		if (!strcmp(cmd, "test"))
			return cmd_test(argv[i]);
		if (!strcmp(cmd, "run"))
			return cmd_run(argv[i]);
		{
			char hex[65], req[128];

			if (strlen(argv[i]) > 32)
				return 2;
			hex_encode((const uint8_t *)argv[i], strlen(argv[i]), hex);
			snprintf(req, sizeof(req), "FORGET %s", hex);
			return cmd_simple(req, "Réseau oublié.");
		}
	}

	fprintf(stderr, "Commande inconnue : %s\n\n", cmd);
	usage();
	return 2;
}
