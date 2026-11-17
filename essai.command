#!/bin/sh
# Essai guidé de la clé Wi-Fi Sagem XG-760A avec le pilote xg760a.
# Double-cliquez sur ce fichier (ou lancez-le dans le Terminal).
#
# Étape 1 : connexion, DHCP, ping et mesure de débit SANS droits
#           administrateur et sans rien installer.
# Étape 2 : (facultative) la même chose à travers une vraie interface réseau
#           de macOS, ce qui demande le mot de passe administrateur du Mac.
#
# Rien n'est installé ni conservé par ce script, sauf deux journaux texte
# (sans aucun mot de passe) rangés à côté de lui : journal-essai.txt et
# journal-service.txt.

HERE=$(cd "$(dirname "$0")" && pwd)
X="$HERE/build/xg760a"
LOG="$HERE/journal-essai.txt"

say() { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$LOG"; }

: > "$LOG"
say "=== Essai du pilote xg760a — $(date '+%d/%m/%Y %H:%M') ==="
say "macOS $(sw_vers -productVersion), $(uname -m)"

if [ ! -x "$X" ]; then
	say "Compilation du pilote..."
	(cd "$HERE" && make) >> "$LOG" 2>&1 || { say "La compilation a échoué : voir $LOG"; exit 1; }
fi
if [ -S /var/run/xg760a.sock ] && "$X" status >/dev/null 2>&1; then
	say "Le service xg760a tourne déjà (pilote installé) : voici son état."
	"$X" status | tee -a "$LOG"
	exit 0
fi

echo
echo "Réseaux à portée de la clé :"
if ! "$X" scan > "$HERE/build/essai-scan.txt" 2>&1; then
	tee -a "$LOG" < "$HERE/build/essai-scan.txt"
	say "La recherche a échoué : la clé est-elle branchée ?"
	exit 1
fi
tee -a "$LOG" < "$HERE/build/essai-scan.txt"
echo
SSID=
while [ -z "$SSID" ]; do
	printf "Nom du réseau à rejoindre : "
	read -r SSID || exit 1
done
printf "Mot de passe Wi-Fi de « %s » (rien ne s'affiche) : " "$SSID"
stty -echo 2>/dev/null
read -r PASS
stty echo 2>/dev/null
echo
printf 'Réseau choisi : %s\n' "$SSID" >> "$LOG"

echo
say "--- Étape 1 : essai sans droits administrateur ---"
printf '%s\n' "$PASS" | "$X" test "$SSID" 2>&1 | tee -a "$LOG"
if ! grep -q "fonctionne de bout en bout" "$LOG"; then
	echo
	if grep -q "mot de passe" "$LOG"; then
		say "La box a refusé le mot de passe : relancez ce script et ressaisissez-le."
	else
		# second passage avec le journal détaillé du pilote, pour le
		# diagnostic (il ne contient ni mot de passe ni clé)
		echo "L'étape 1 n'est pas allée au bout : nouvel essai avec journal détaillé..."
		printf '%s\n' "--- second essai, journal détaillé ---" >> "$LOG"
		printf '%s\n' "$PASS" | "$X" -v test "$SSID" >> "$LOG" 2>&1
		say "Le détail est dans : $LOG"
	fi
	PASS=
	exit 1
fi

echo
echo "Étape 1 réussie : la clé se connecte et transporte du trafic."
echo
echo "Étape 2 : créer une vraie interface réseau macOS (feth760) le temps"
echo "d'un essai. Il faut pour cela le mot de passe administrateur du Mac."
printf "Faire l'étape 2 maintenant ? [O/n] "
read -r ANSWER
case "$ANSWER" in
	n|N|non|Non) PASS=; say "Étape 2 non faite."; exit 0 ;;
esac

say "--- Étape 2 : interface réseau macOS ---"
if ! sudo -v; then
	PASS=
	say "Droits administrateur refusés : étape 2 abandonnée."
	exit 1
fi
RUNLOG="$HERE/journal-service.txt"
printf '%s\n' "$PASS" | sudo "$X" run "$SSID" > "$RUNLOG" 2>&1 &
SUDO_PID=$!
PASS=

echo "Connexion en cours..."
IP=
for i in $(seq 1 40); do
	sleep 1
	STATUS=$("$X" status 2>/dev/null)
	IP=$(printf '%s\n' "$STATUS" | sed -n 's/.*adresse \([0-9][0-9.]*\).*/\1/p' | head -1)
	[ -n "$IP" ] && break
done
"$X" status 2>&1 | tee -a "$LOG"
echo

if [ -n "$IP" ]; then
	say "Adresse obtenue par le DHCP de macOS : $IP"
	say "Ping de la box à travers la clé :"
	GW=$(/usr/sbin/ipconfig getoption feth760 router 2>/dev/null)
	[ -n "$GW" ] && ping -c 4 -b feth760 "$GW" 2>&1 | tail -3 | tee -a "$LOG"
	say "Ping d'Internet à travers la clé :"
	ping -c 4 -b feth760 1.1.1.1 2>&1 | tail -3 | tee -a "$LOG"
	say "Téléchargement d'essai à travers la clé (10 Mo) :"
	curl --interface feth760 -s -o /dev/null -m 60 \
		-w 'débit moyen : %{speed_download} octets/s en %{time_total} s\n' \
		https://proof.ovh.net/files/10Mb.dat 2>&1 | tee -a "$LOG"
	"$X" status 2>&1 | grep -E "Débit|Trafic" | tee -a "$LOG"
	echo
	say "RÉSULTAT : l'interface réseau fonctionne."
else
	say "Pas d'adresse IP sur feth760 après 40 s."
	/sbin/ifconfig feth760 2>&1 | tee -a "$LOG"
	say "RÉSULTAT : la partie interface réseau est à corriger ; les journaux"
	say "journal-essai.txt et journal-service.txt disent où cela bloque."
fi

echo
echo "Arrêt de l'essai (l'interface feth760 est retirée)..."
sudo kill -TERM "$SUDO_PID" 2>/dev/null
wait "$SUDO_PID" 2>/dev/null
cat "$RUNLOG" >> "$LOG" 2>/dev/null
echo
echo "Journal : $LOG"
if [ -n "$IP" ]; then
	echo
	echo "Pour installer le pilote à demeure (service au démarrage, icône dans la"
	echo "barre de menus) : make pkg, puis ouvrez build/XG760A-*.pkg"
fi
