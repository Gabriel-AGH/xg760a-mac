# Pilote macOS pour la clé Wi-Fi Sagem XG-760A

Ce programme fait fonctionner la clé USB Wi-Fi **Sagem XG-760A** (puce ZyDAS
ZD1211, 802.11b/g, USB `079b:004a`) sur un **Mac Intel** récent, pour lequel
aucun pilote n'existe.

Il ne s'agit pas d'une extension du noyau : c'est un programme ordinaire qui
dialogue avec la clé en USB, tient lui-même la connexion Wi-Fi (WPA2 compris)
et présente le résultat à macOS sous la forme d'une interface réseau.
**Aucun réglage de sécurité de macOS n'est modifié** (ni SIP, ni AMFI),
rien n'est écrit dans la clé (son micrologiciel est chargé en mémoire à
chaque branchement) et tout se désinstalle d'un double-clic.

## Où en est-on

| Élément | État |
|---|---|
| Chargement du micrologiciel, initialisation de la puce et de la radio AL2230 | vérifié sur la clé |
| Réception et **émission** radio, à tous les débits de 1 à 54 Mbit/s | vérifié sur la clé (trames acquittées par la box) |
| Recherche des réseaux | vérifié sur la clé |
| Authentification et association avec une Freebox | vérifié sur la clé |
| Connexion WPA2 (AES-CCMP) complète à une Freebox, diagnostic « mot de passe incorrect » | vérifié sur la clé (16 novembre 2026) |
| DHCP, ARP, ping, trafic chiffré de bout en bout | vérifié sur la clé : 25 Mbit/s en émission, 6 639 paquets sans perte |
| Interface réseau macOS (`feth760`), DHCP du système | vérifié sur la clé : adresse obtenue par macOS, pings, téléchargement de 10 Mo à 15–17 Mbit/s |
| La clé comme seule connexion du Mac (Wi-Fi intégré coupé) | vérifié : route par défaut, DNS, IPv4 et IPv6 passent par la clé |
| WPA1 et WPA2 en TKIP (anciennes box) | vérifié sur vecteurs officiels, capture publique et point d'accès simulé ; **jamais sur un vrai réseau TKIP** |
| Installeur `.pkg`, service, commande `xg760a` | installés et utilisés plusieurs jours sur le Mac de mise au point |
| Désinstalleur | vérifié : il ne reste aucun fichier, service ni interface après son passage |
| Application de barre de menus « Wi-Fi XG-760A » | installée et lancée par l'installeur ; logique vérifiée en mode texte |
| Robustesse : 400 000 trames abîmées injectées dans la station | aucun plantage, aucune erreur mémoire |
| Veille / réveil du Mac | logique vérifiée par simulation, pas par une vraie mise en veille |

Le pilote a servi plusieurs jours comme connexion du Mac sans problème
signalé. N'ont pas fait l'objet d'un essai consigné : la mise en veille, le
débranchement à chaud et le redémarrage du Mac. Tout a été mis au point sur
un seul Mac (MacBook Pro Intel, macOS 15) et une seule clé.

## Premier essai (5 minutes)

Ces essais se font depuis les sources, sans rien installer. Il faut les
« Command Line Tools » d'Apple (`xcode-select --install`), puis `make`.

Le plus simple : double-cliquez sur **`essai.command`**. Il compile si
nécessaire, enchaîne les deux essais ci-dessous, ne demande le mot de passe
Wi-Fi qu'une fois et laisse un journal (`journal-essai.txt`, sans mot de
passe).

À la main, dans le Terminal ouvert sur ce dossier, clé branchée :

**1. Essai complet sans droits administrateur.** Rien n'est installé, aucune
interface réseau n'est créée ; le programme se connecte, obtient une adresse,
envoie des pings, mesure le débit (environ dix secondes de trafic soutenu
vers la box), puis s'arrête.

```sh
./build/xg760a test "Nom de votre réseau"
```

Le mot de passe Wi-Fi est demandé (il n'est ni affiché ni enregistré).
La dernière ligne doit être
`RÉSULTAT : la clé fonctionne de bout en bout (WPA, DHCP, trafic IP).`

**2. Essai avec une vraie interface réseau,** toujours sans rien installer :

```sh
sudo ./build/xg760a run "Nom de votre réseau"
```

Laissez tourner et, dans une autre fenêtre du Terminal :

```sh
./build/xg760a status              # doit afficher une adresse IP sur feth760
ping -c 3 -b feth760 1.1.1.1       # ping en passant par la clé
curl --interface feth760 -sI https://www.apple.com | head -1
```

`Ctrl-C` dans la première fenêtre arrête tout et retire l'interface.

Tant que le Wi-Fi intégré du Mac (ou un câble) est actif, macOS le préfère :
le trafic ordinaire ne passe par la clé que si vous les coupez, ou si un
programme la choisit explicitement comme ci-dessus.

## Installation à demeure

Téléchargez `XG760A-1.0.pkg` sur la page
[Releases](https://github.com/Gabriel-AGH/xg760a-mac/releases) du dépôt et
ouvrez-le (voir plus bas si macOS refuse de l'ouvrir). Ou fabriquez-le
vous-même à partir des sources :

```sh
make pkg
open build/XG760A-1.0.pkg
```

L'installeur dépose le pilote dans `/Library/Application Support/XG760A`,
crée un service lancé au démarrage du Mac, ajoute une icône d'antenne dans
la barre de menus (application « Wi-Fi XG-760A ») et rend la commande
`xg760a` disponible dans le Terminal.

Ensuite, au choix :

- **par la barre de menus** : cliquez sur l'icône d'antenne, choisissez le
  réseau, tapez son mot de passe ;
- **par le Terminal** :

  ```sh
  xg760a scan
  xg760a connect "Nom de votre réseau"
  ```

Le réseau est mémorisé : la clé s'y reconnecte seule à chaque branchement,
à chaque démarrage et au réveil du Mac. L'icône est grisée tant que la clé
n'est pas connectée.

### Si macOS refuse d'ouvrir le paquet

Le fichier `XG760A-1.0.pkg` est autonome : ni Xcode ni les sources ne sont
nécessaires sur le Mac où on l'installe. Il vise macOS 10.13 ou plus récent
sur Mac Intel, mais n'a été essayé que sous macOS 15.

Le paquet n'est pas signé par un développeur Apple identifié. S'il a transité
par Internet ou AirDrop, macOS refuse le double-clic ; deux façons de passer :

- Réglages Système → Confidentialité et sécurité → « Ouvrir quand même »
  (sur les versions plus anciennes : clic droit sur le fichier → Ouvrir) ;
- ou, dans le Terminal : `sudo installer -pkg XG760A-1.0.pkg -target /`

### Désinstaller

Double-cliquez sur
`/Library/Application Support/XG760A/desinstaller.command`.
Le service, l'application, la commande, le journal et les réseaux mémorisés
sont supprimés.

## Commandes

| Commande | Effet |
|---|---|
| `xg760a scan` | réseaux à portée (fonctionne même sans le service) |
| `xg760a connect <réseau>` | se connecter et mémoriser ; le mot de passe n'est demandé que la première fois |
| `xg760a connect --nouveau-mot-de-passe <réseau>` | ressaisir le mot de passe d'un réseau connu |
| `xg760a status` | état de la clé, du lien radio et de l'interface |
| `xg760a disconnect` | se déconnecter jusqu'au prochain `connect` |
| `xg760a list` / `xg760a forget <réseau>` | réseaux mémorisés / en oublier un |
| `xg760a test <réseau>` | essai complet sans droits administrateur |
| `sudo xg760a run <réseau>` | connexion immédiate avec interface, sans installation |

Ajoutez `-v` (ou `-vv`) juste après `xg760a` pour des messages détaillés.
Une fois installé, le service écrit son journal dans `/var/log/xg760a.log`.

## Ce que la clé sait faire, et ne sait pas faire

- Bande 2,4 GHz uniquement, 54 Mbit/s au mieux (c'est une clé 802.11g de
  2005). Mesuré à quelques mètres de la box : 25 Mbit/s en émission,
  15 Mbit/s en téléchargement.
- Réseaux **WPA2 et WPA à mot de passe** (AES-CCMP ou TKIP, y compris les
  réseaux mixtes) et réseaux ouverts.
- Non pris en charge : WPA3 seul, WPA-Entreprise (802.1X), WEP, réseaux dont
  la protection des trames de gestion est obligatoire. Une box en mode mixte
  WPA2/WPA3 est rejointe en WPA2 : c'est prévu par le code, mais n'a pas été
  essayé sur une vraie box.
- La présence d'un appareil 802.11g ralentit un peu les autres appareils du
  même réseau 2,4 GHz (c'est vrai de n'importe quel appareil de cette
  génération).
- La connexion n'apparaît pas dans le menu Wi-Fi de macOS ni dans les
  réglages Réseau : elle se pilote avec l'icône d'antenne de la barre de
  menus ou la commande `xg760a`.
- Un seul point d'accès à la fois, sans itinérance : si le signal est perdu,
  le pilote relance une recherche et se reconnecte.

## En cas de souci

- **`Clé Wi-Fi introuvable`** : débranchez et rebranchez la clé ; vérifiez
  qu'un autre programme (ou une machine virtuelle) ne l'a pas réservée.
- **`mot de passe Wi-Fi incorrect`** : la box a refusé la clé WPA. Le pilote
  s'arrête après deux refus pour ne pas se faire bannir par la box ;
  relancez `xg760a connect <réseau>`.
- **Connecté mais « pas encore d'adresse IP »** : c'est le DHCP de macOS sur
  l'interface `feth760` qui n'aboutit pas. `sudo ipconfig set feth760 DHCP`
  le relance ; `ifconfig feth760` montre l'état. Si cela ne suffit pas,
  `xg760a test <réseau>` (service arrêté) dira si le lien radio lui-même
  transporte bien le trafic, et le journal `/var/log/xg760a.log` donnera le
  détail.
- **Autre chose** : ouvrez un ticket sur
  <https://github.com/Gabriel-AGH/xg760a-mac/issues> en joignant la sortie
  de `xg760a status` et le journal. Ils ne contiennent ni mot de passe ni
  clé, mais on y lit le nom de votre réseau et l'adresse matérielle de votre
  box : masquez-les si vous le souhaitez.
- **Journal détaillé** : `sudo ./build/xg760a -v run <réseau>`.

## Sécurité

- Le service tourne avec les droits administrateur (root) : c'est
  indispensable pour créer l'interface réseau. Il n'écoute sur aucun port
  réseau ; il se pilote par un socket local réservé aux comptes
  administrateurs du Mac.
- Le mot de passe Wi-Fi n'est pas conservé : seule la clé qui en dérive
  l'est, dans un fichier lisible par root uniquement.
- Le chiffrement WPA est fait par ce programme et non par la puce. Il est
  vérifié sur les vecteurs officiels et des captures publiques, mais n'a
  fait l'objet d'aucun audit indépendant.

## D'où vient ce code

- Les fichiers de `vendor/zd1211rw/` (initialisation de la puce et des
  radios) sont ceux du pilote Linux `zd1211rw`, **compilés sans
  modification** grâce à la petite couche de `compat/`.
- Le micrologiciel de `firmware/` est celui publié par le projet zd1211
  (paquet `zd1211-firmware` 1.5), sous licence GPL.
- Tout le reste (`src/`) a été écrit pour ce projet : accès USB par IOKit,
  station 802.11, négociation WPA, chiffrement, interface réseau, service.

Auteur : **Gabriel-AGH**. L'ensemble est distribué sous licence **GNU GPL
version 2 ou ultérieure** (fichier `COPYING`), sans aucune garantie.
`NOTES-TECHNIQUES.md` décrit l'architecture et les vérifications effectuées.

Testé avec la seule Sagem XG-760A. Les identifiants de la Sagem XG-76NA
(ZD1211B) et des clés de référence ZyDAS sont reconnus mais n'ont jamais été
essayés.
