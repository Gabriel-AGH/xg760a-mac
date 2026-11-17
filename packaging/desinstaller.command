#!/bin/sh
# Désinstalle complètement le pilote de la clé Wi-Fi Sagem XG-760A.
# Double-cliquez sur ce fichier, ou lancez-le dans le Terminal.

echo "Désinstallation du pilote Wi-Fi Sagem XG-760A (xg760a)."
echo "Le service sera arrêté et tous ses fichiers supprimés,"
echo "y compris les réseaux Wi-Fi mémorisés."
printf "Continuer ? [o/N] "
read answer
case "$answer" in
	o|O|oui|Oui|OUI) ;;
	*) echo "Annulé."; exit 0 ;;
esac

# l'icône de la barre de menus tourne dans la session de l'utilisateur
/bin/launchctl bootout "gui/$(id -u)/local.xg760a.menu" 2>/dev/null

echo "Le mot de passe de votre session peut être demandé (droits administrateur)."
sudo /bin/sh -c '
	/bin/launchctl bootout system/local.xg760a 2>/dev/null
	/bin/rm -f /Library/LaunchAgents/local.xg760a.menu.plist
	/bin/rm -f /Library/LaunchDaemons/local.xg760a.plist
	/bin/rm -f /etc/newsyslog.d/xg760a.conf
	/bin/rm -f /var/log/xg760a.log /var/log/xg760a.log.*
	/bin/rm -f /var/run/xg760a.sock
	if [ -L /usr/local/bin/xg760a ]; then /bin/rm -f /usr/local/bin/xg760a; fi
	if [ -d "/Applications/Wi-Fi XG-760A.app" ]; then /bin/rm -rf "/Applications/Wi-Fi XG-760A.app"; fi
	/sbin/ifconfig feth760 destroy 2>/dev/null
	/sbin/ifconfig feth5760 destroy 2>/dev/null
	/bin/rm -rf "/Library/Application Support/XG760A"
	/usr/sbin/pkgutil --forget local.xg760a.pkg >/dev/null 2>&1
	exit 0
'
if [ $? -eq 0 ]; then
	echo "Pilote désinstallé. Vous pouvez débrancher la clé."
else
	echo "La désinstallation n'a pas pu se faire (droits administrateur refusés ?)."
fi
