# Captures de référence

Ces deux fichiers viennent de la suite de tests de Wireshark
(<https://gitlab.com/wireshark/wireshark>, dossier `test/captures/`), où ils
servent à vérifier le déchiffrement WPA. Ils sont repris ici sans
modification pour vérifier notre propre code face à du trafic produit par
d'autres implémentations.

| Fichier | Contenu | Phrase secrète |
|---|---|---|
| `wpa-Induction.pcap` | réseau « Coherer », WPA2 (AES + clé de groupe TKIP), trafic web | `Induction` |
| `wpa2-psk-ccmp-tkip.pcapng` | réseau produit par hostapd/wpa_supplicant, AES + groupe TKIP | `12345678` |

`make check` les rejoue à travers `src/wpa.c` et `src/crypto.c`.
