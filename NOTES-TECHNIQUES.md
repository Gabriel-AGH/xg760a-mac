# Notes techniques — pilote xg760a

Document pour qui reprend le code. L'usage est décrit dans `LISEZMOI.md`.

## Matériel

| | |
|---|---|
| Clé | Sagem XG-760A, USB `079b:004a`, bcdDevice `0x4330`, USB 2.0 |
| Puce | ZyDAS ZD1211 (pas « B »), radio Airoha AL2230 |
| Micrologiciel | `zd1211_uphr` 1.5, se déclare en version `4605` une fois chargé |
| Domaine réglementaire | `0x30` (ETSI), canaux 1 à 13 |
| Points de terminaison | EP1 OUT bulk (trames), EP2 IN bulk (trames), EP3 IN interruption (réponses, rapports), EP4 OUT interruption (commandes) |

Le micrologiciel vit en mémoire vive : il est rechargé à chaque ouverture
de la clé. Rien n'est jamais écrit dans son EEPROM.

## Architecture

```
 macOS (DHCP, TCP/IP...)
        │  trames Ethernet
   feth760 ══ feth5760          paire d'interfaces « fake Ethernet » du noyau
        │  BPF (lecture) / AF_NDRV (injection)
 ┌──────┴──────────────────────────────────────────────┐
 │ netif.c      interface système                      │  root
 │ service.c    réseaux connus, socket de commande,    │
 │              veille/réveil                          │
 │ wlan.c       station 802.11 : recherche, auth.,     │
 │              association, débit, surveillance       │
 │ wpa.c        négociation WPA/WPA2 (4 messages,      │
 │              clé de groupe)                         │
 │ crypto.c     PBKDF2, PRF, AES-CCMP, TKIP, Michael   │
 │ device.c     la clé vue comme une radio 802.11      │
 │ zd_usb.c     protocole USB du ZD1211, micrologiciel │
 │ vendor/zd1211rw/*  puce et radios (Linux, intact)   │
 │ usbdev.c     USB en espace utilisateur (IOKit)      │
 └──────┬──────────────────────────────────────────────┘
        │  USB
      la clé
```

Tout est un seul processus. Fils d'exécution : un pour les évènements USB
(boucle CFRunLoop), un pour l'émission, un pour l'entretien de la puce
(voyant, interruptions), un pour la station (toute la logique 802.11, seul
propriétaire de son état), plus, dans le service, la lecture BPF, la
configuration de l'interface, le socket de commande et les notifications
d'alimentation.

### Pourquoi pas une extension du noyau ou DriverKit

- Une kext Wi-Fi s'appuie sur `IO80211Family`, privé et instable ; il
  faudrait de toute façon abaisser la sécurité du Mac pour la charger.
- DriverKit exige des droits (« entitlements ») délivrés par Apple.
- En espace utilisateur, la clé est accessible par IOKit sans aucun droit
  particulier puisqu'aucun pilote d'Apple ne la réclame. Seule la création
  de l'interface réseau demande d'être root.

Contrepartie : la connexion n'apparaît pas dans le menu Wi-Fi de macOS.

### Reprise du pilote Linux

`vendor/zd1211rw/` contient `zd_chip.c`, `zd_rf*.c` et leurs en-têtes tels
que dans Linux 6.6. Ils sont compilés sans modification : `compat/` fournit
les quelques éléments du noyau qu'ils utilisent, et `src/zd_usb.h` /
`src/zd_mac.h` remplacent les en-têtes homonymes de Linux (la résolution se
fait par l'ordre des `-I`). Les tables de registres ne sont donc jamais
recopiées à la main.

`src/zd_usb.c` et `src/device.c` reprennent le protocole et les séquences
de `zd_usb.c` / `zd_mac.c` de Linux sur une plomberie différente (IOKit,
fils d'exécution). Sous Linux, la station et WPA sont assurés par mac80211
et wpa_supplicant ; ici ce sont `wlan.c` et `wpa.c`, écrits pour ce projet.

## Points découverts en chemin

1. **Réinitialiser le port USB avant de charger le micrologiciel.** Sans
   `USBDeviceReEnumerate`, le chargement réussit mais la première lecture de
   registre sur EP4/EP3 expire. Linux fait de même (`usb_reset_device`).
   C'est le point sur lequel bute un premier portage en espace utilisateur.
2. **`SetConfiguration` après le démarrage du micrologiciel**, puis
   seulement ouverture de l'interface et des tubes.
3. **La puce rend compte des émissions difficiles** sur EP3 (identifiant
   `0xa0`) : trame abandonnée, ou réussie après reprises avec le débit
   final. Les trames réussies du premier coup ne produisent rien. Mesuré :
   vers une adresse inexistante, 100 % de rapports d'échec ; vers la box, à
   1/11/24/54 Mbit/s, aucun rapport ; décalé d'un canal, réussites après
   reprise à 1–2 Mbit/s. Le choix du débit (`rc_*` dans `wlan.c`) repose
   là-dessus.
4. **La puce gère elle-même** acquittements, reprises, durées et repli de
   débit ; l'hôte fournit numéros de séquence et chiffrement (la puce est
   laissée en mode « sniffer », sans chiffrement matériel, comme sous Linux).
5. Les sockets Unix sont limités à 104 octets de chemin : attention aux
   essais dans des dossiers temporaires profonds.
6. Le compilateur Swift des « Command Line Tools » 16.x échoue sur le Mac
   de mise au point (`redefinition of module 'SwiftBridging'`) :
   l'application de barre de menus est donc en Objective-C.
7. Les interfaces `feth` refusent un MTU supérieur à
   `net.link.fake.max_mtu` (2048 par défaut) : `ifconfig ... mtu 16370`
   échoue par « Invalid argument ». Les deux bouts restent à 1500.

## Ce qui a été vérifié, et comment

| Vérification | Commande | Résultat (nuit du 15 au 16 novembre 2026) |
|---|---|---|
| Primitives et chiffrements sur vecteurs officiels (IEEE 802.11i, RFC 3394, RFC 3610) | `build/crypto_test` | 21/21 |
| Capture réelle WPA2, AES + groupe TKIP (Wireshark `wpa-Induction.pcap`, phrase « Induction ») rejouée dans `wpa.c` puis déchiffrée par `crypto.c` | `build/pcapcheck` | MIC 2/4 et 4/4 valides, 263 trames déchiffrées, 0 échec |
| Capture réelle produite par wpa_supplicant/hostapd (`wpa2-psk-ccmp-tkip.pcapng`, « 12345678 ») | `build/pcapcheck` | notre message 2/4 identique octet pour octet, 12 trames déchiffrées |
| Pile complète face à un point d'accès simulé : WPA2 AES, WPA2 + groupe TKIP, WPA2-TKIP, WPA1-TKIP, ouvert, mauvais mot de passe | `build/simap <scénario>` | 6 scénarios réussis, ~500 000 paquets chiffrés sans perte chacun, renouvellement de clé de groupe compris |
| Vie courante, toujours simulée : recherche en cours de connexion, panne du point d'accès, déconnexion forcée | `build/simap scan`, `panne`, `deauth` | connexion conservée pendant la recherche ; panne détectée en 8 s ; reconnexion spontanée et trafic rétabli |
| Clé réelle : chargement, initialisation, réception | `build/chipinit` | balises reçues sur les canaux 1, 6, 11 |
| Clé réelle : émission | `build/scantest`, `build/txreport` | réponses de sonde adressées à la clé ; acquittements de la box à 1, 11, 24 et 54 Mbit/s |
| Clé réelle : association à la Freebox (2,4 GHz, canal 6, WPA2) | `build/jointest` avec une phrase volontairement fausse | authentification 3 ms, association 8 ms, message 1/4 reçu, 2/4 envoyé, rejet diagnostiqué |
| Service et commandes, sans root | `xg760a --sans-root daemon` + client | état, recherche, connexion refusée, mémorisation, oubli, arrêt propre |
| Veille / réveil simulés | requêtes `SUSPEND` / `RESUME` | clé libérée puis redémarrée en 0,3 à 0,5 s |
| Endurance du service sur la clé réelle | 120 recherches, 12 cycles veille/réveil | 120/120, mémoire stable (≈ 8 Mo), nombre de fils constant, arrêt propre |
| Consommation au repos (clé prête, non connectée) | `top` | ≈ 0,1 % de processeur |
| Application de barre de menus | `--etat`, `--recherche`, `--menu` | réponses correctes ; lancement réel sans erreur |
| Erreurs mémoire (AddressSanitizer + UBSan) sur tout le code sans matériel | `build/san/*` | aucune |
| Robustesse face à des trames hostiles : 400 000 variantes abîmées de vraies trames | `build/san/simap fuzz` | aucun plantage ; déconnexion par fausse trame puis reconnexion spontanée |

### Premier essai réel complet (16 novembre 2026)

Lancé avec `essai.command` et le vrai mot de passe, sur une Freebox
(canal 6, WPA2 AES-CCMP), signal 65 %.

| Étape | Résultat |
|---|---|
| `xg760a test` : négociation WPA2 en 4 messages | réussie du premier coup |
| DHCP du mini-client | offre reçue en diffusion (clé de groupe), bail reçu en direct (clé de session) |
| Ping de la box / de 1.1.1.1 | 4/4, 2,6 ms / 4/4, 4,0 ms |
| Émission continue 3 s | 6 639 paquets de 1 400 octets, 0 perdu, 25,1 Mbit/s, débit radio 54 Mbit/s, 12 trames reprises |
| Échos de 1 400 octets pendant 4 s | 4 532 revenus sur 4 533, 12 Mbit/s dans chaque sens |
| `sudo xg760a run` : création de `feth760`, BPF, AF_NDRV | réussie |
| DHCP de macOS sur `feth760` | adresse obtenue 5,2 s après la connexion radio |
| `ping -b feth760` box / 1.1.1.1 | 4/4, 2,2 ms / 4/4, 5,2 ms |
| `curl --interface feth760`, 10 Mo | 1,9 Mo/s (15 Mbit/s) ; 7 461 paquets reçus, 108 trames reprises, 0 abandonnée |
| Arrêt par SIGTERM | interface retirée, plus rien sur le système (contrôlé après coup) |

Seule anomalie : `ifconfig: ioctl (set mtu): Invalid argument` à la création
de l'interface (point 7 ci-dessus), sans effet, corrigée dans
`create_interface` ; le journal du service installé ensuite ne la montre
plus.

### Paquet installé, clé seule connexion (16 novembre 2026)

`XG760A-1.0.pkg` installé, Wi-Fi intégré (`en0`) coupé.

| Point | Constaté |
|---|---|
| Installation | fichiers, LaunchDaemon, LaunchAgent, lien `/usr/local/bin/xg760a` en place ; service et application lancés par `postinstall` |
| Démarrage du service | clé prête en 0,2 s, `feth760` créée en 0,9 s, sans avertissement |
| Connexion demandée | association + WPA2 en 22 ms, adresse DHCP de macOS 5,2 s plus tard |
| Route par défaut, DNS | sur `feth760`, vers la box |
| IPv6 | adresses globales par autoconfiguration, `curl -6` réussi |
| Téléchargement de 10 Mo (route par défaut) | 2,15 Mo/s (17 Mbit/s), débit radio 54/54 Mbit/s, 0 trame abandonnée |
| Service en charge | 0,8 % de processeur, 8,4 Mo de mémoire |

Le délai de 5,2 s entre la liaison radio et l'adresse est le même dans les
deux essais ; le mini-client de `xg760a test` obtient son bail bien plus
vite. Ce temps est donc passé côté macOS (client DHCP du système), cause
non recherchée.

Les captures publiques se téléchargent depuis le dépôt de Wireshark
(`test/captures/`), les phrases secrètes sont celles de sa suite de tests.

Portée de ces preuves : le WPA2 AES-CCMP est vérifié contre deux
implémentations indépendantes, puis sur la Freebox réelle (ci-dessus) ; la
clé de groupe TKIP est vérifiée contre une implémentation indépendante
(capture « Induction »). Le WPA1 et le WPA2-TKIP en revanche ne sont
vérifiés que face à notre propre point d'accès simulé, donc à l'abri d'un
plantage mais pas d'une erreur de lecture de la norme partagée par les deux
côtés.

### Ce qui reste à voir fonctionner

Le paquet a ensuite servi plusieurs jours sans problème signalé, puis a été
désinstallé : contrôle fait après coup, il ne restait ni fichier, ni
service, ni reçu d'installation, ni interface `feth`.

Aucun essai consigné, en revanche, pour :

- le **redémarrage du Mac** (service et icône relancés seuls, reconnexion
  au réseau mémorisé), une **réinstallation** par-dessus, l'installation
  sur un **autre Mac** ou une autre version de macOS ;
- une **vraie mise en veille**, l'**arrachage physique** de la clé ;
- le renouvellement de la clé de groupe par la box et celui du bail DHCP,
  observés seulement en simulation.
- Le WPA1 et le WPA2-TKIP sur un vrai point d'accès.

## Limites et pistes

- Pas de WPA3-SAE (il faudrait de l'arithmétique sur courbe elliptique et
  la protection des trames de gestion), pas de 802.1X, pas de WEP.
- Pas de réassemblage des trames fragmentées en réception (rarissime).
- Pas de contre-mesures TKIP (les trames au MIC invalide sont ignorées).
- Pas d'itinérance entre points d'accès de même nom ; pas de recherche de
  fond une fois connecté. Une recherche demandée en cours de connexion
  quitte le canal environ 2 s (la box est prévenue par une trame
  d'économie d'énergie).
- Le créneau court (« short slot ») est annoncé comme le fait mac80211 mais,
  comme sous Linux, rien ne le programme dans la puce.
- Intégration plus poussée possible : apparaître comme service réseau dans
  les réglages, statistiques, IPv6 vérifié.

## Arborescence

```
src/         le pilote (voir le schéma)
compat/      mini couche de compatibilité noyau Linux
vendor/      fichiers repris tels quels de Linux
firmware/    micrologiciel ZD1211/ZD1211B et sa licence
app/         application de barre de menus (Objective-C)
packaging/   service launchd, scripts et ressources de l'installeur
tests/       programmes de mise au point et de vérification
tools/       mkfw.sh (micrologiciel -> C), accents.py (messages)
```

`make` construit `build/xg760a` et l'application ; `make tests` les
programmes de `tests/` ; `make check` lance toutes les vérifications qui ne
demandent ni clé ni réseau ; `make pkg` fabrique l'installeur.

## Reprendre

`essai.command` enchaîne `xg760a test` puis `sudo xg760a run` et
écrit `journal-essai.txt` (et `journal-service.txt`) : c'est le moyen le
plus rapide de savoir à quelle étape une régression se situe (association,
négociation WPA, DHCP du mini-client, création de `feth760`, DHCP de macOS).
Une fois le paquet installé, le journal du service est
`/var/log/xg760a.log` et `xg760a status` donne l'état courant.
