#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Gabriel-AGH
"""Outil de mise au point : rétablit les accents des messages français.

Les messages du pilote ont d'abord été écrits en ASCII. Ce script les
corrige, uniquement à l'intérieur des chaînes de caractères du C (jamais dans
le code ni dans les commentaires), et affiche chaque chaîne modifiée pour
relecture. Il est idempotent : le relancer ne change plus rien.

usage : accents.py [--ecrire] fichier.c ...
"""
import re
import sys

# expressions à traiter en premier : le mot seul serait ambigu
PHRASES = [
    ("connecte a ", "connecté à "), ("Connecte a ", "Connecté à "),
    ("Connexion a ", "Connexion à "), ("connexion a ", "connexion à "),
    ("jusqu'a ", "jusqu'à "), ("a portee", "à portée"), ("a demeure", "à demeure"),
    ("a l'adresse", "à l'adresse"), ("a travers", "à travers"),
    ("a nos sondes", "à nos sondes"), ("pas a l'", "pas à l'"),
    ("pas a la ", "pas à la "), ("8 a 63", "8 à 63"), ("1 a 32", "1 à 32"),
    ("identique a celle", "identique à celle"), ("mise a niveau", "mise à niveau"),
    ("reponse a une", "réponse à une"), ("pour, a ", "pour, à "),
    ("octet pour octet, a celui", "octet pour octet, à celui"),
    ("arret demande", "arrêt demandé"), ("reseau demande", "réseau demandé"),
    ("est demande", "est demandé"), ("utile mesure", "utile mesuré"),
    ("bail accorde", "bail accordé"), ("nom masque", "nom masqué"),
    ("est protege", "est protégé"), ("s'arrete", "s'arrête"),
    ("nous deconnecte", "nous déconnecte"), ("Deconnecte.", "Déconnecté."),
    ("et verifie", "et vérifié"), ("cree une interface", "crée une interface"),
    ("des qu'il", "dès qu'il"), ("n'a pas ete", "n'a pas été"),
    ("lance par launchd", "lancé par launchd"), ("fois installe", "fois installé"),
    ("d'accuse de", "d'accusé de"), ("a echoue", "a échoué"),
    ("a refuse", "a refusé"), ("a rejete", "a rejeté"), ("pas accepte", "pas accepté"),
    ("non accepte", "non accepté"), ("pas lance", "pas lancé"),
    ("elle-meme", "elle-même"), ("delai depasse", "délai dépassé"),
    ("Reseau oublie", "Réseau oublié"), ("pris en charge (%s)", "pris en charge (%s)"),
    ("n'insiste pas au-dela", "n'insiste pas au-delà"),
    ("annoncee", "annoncée"), ("acquitte par", "acquitté par"),
    ("est configure", "est configuré"),
    ("la station a une", "la station à une"),
    ("\\treseau inconnu", "\\tréseau inconnu"),
    ("\\tcle invalide", "\\tclé invalide"),
    ("\\tcle Wi-Fi", "\\tclé Wi-Fi"),
]

MOTS = {
    "cle": "clé", "Cle": "Clé", "cles": "clés",
    "reseau": "réseau", "Reseau": "Réseau", "reseaux": "réseaux",
    "etat": "état", "Etat": "État",
    "connecte": "connecté", "Connecte": "Connecté",
    "deconnecte": "déconnecté", "deconnecter": "déconnecter",
    "acces": "accès", "Acces": "Accès",
    "debit": "débit", "Debit": "Débit", "debits": "débits",
    "emission": "émission", "Emission": "Émission", "emis": "émis",
    "emise": "émise", "emises": "émises",
    "reception": "réception",
    "recu": "reçu", "recus": "reçus", "recue": "reçue", "recues": "reçues",
    "reponse": "réponse", "reponses": "réponses", "repond": "répond",
    "repondra": "répondra",
    "echec": "échec", "Echec": "Échec", "ECHEC": "ÉCHEC", "echecs": "échecs",
    "echos": "échos", "echouee": "échouée",
    "delai": "délai", "depasse": "dépassé",
    "negociation": "négociation", "negociations": "négociations",
    "securite": "sécurité", "memorise": "mémorisé", "memoriser": "mémoriser",
    "memorises": "mémorisés",
    "desactivee": "désactivée", "activee": "activée", "creee": "créée",
    "configuree": "configurée", "installee": "installée",
    "renouvelee": "renouvelée", "etablie": "établie", "coupee": "coupée",
    "liberee": "libérée", "terminee": "terminée", "envoye": "envoyé",
    "envoyes": "envoyés", "verifie": "vérifie", "demarre": "démarré",
    "arrete": "arrêté", "arret": "arrêt", "arretez": "arrêtez",
    "arreter": "arrêter",
    "prefere": "préféré", "detailles": "détaillés", "tres": "très",
    "immediat": "immédiat", "deja": "déjà", "apres": "après",
    "integrite": "intégrité", "perimee": "périmée", "sature": "saturé",
    "inactivite": "inactivité", "precision": "précision",
    "capacites": "capacités", "acceptees": "acceptées", "acceptee": "acceptée",
    "refusee": "refusée", "refuse": "refusé", "refuses": "refusés",
    "methode": "méthode", "parametres": "paramètres", "expiree": "expirée",
    "expire": "expiré", "necessaire": "nécessaire",
    "caracteres": "caractères", "hexadecimal": "hexadécimal", "gere": "géré",
    "gerer": "gérer", "condense": "condensé", "secrete": "secrète",
    "systeme": "système", "demarrage": "démarrage", "Demarrage": "Démarrage",
    "reinitialisation": "réinitialisation", "reveil": "réveil",
    "debranchee": "débranchée", "branchee": "branchée", "prete": "prête",
    "portee": "portée", "abandonnees": "abandonnées",
    "dechiffrable": "déchiffrable", "dechiffrement": "déchiffrement",
    "dechiffrees": "déchiffrées", "indechiffrable": "indéchiffrable",
    "RESULTAT": "RÉSULTAT", "PROBLEME": "PROBLÈME", "duree": "durée",
    "arriere-plan": "arrière-plan", "reservee": "réservée",
    "creation": "création", "ecriture": "écriture",
    "different": "différent", "memoire": "mémoire", "selection": "sélection",
    "materielle": "matérielle", "rejouee": "rejouée", "rejouees": "rejouées",
    "ignoree": "ignorée", "prealable": "préalable", "donnees": "données",
    "simultanement": "simultanément", "exterieur": "extérieur",
    "Etats-Unis": "États-Unis", "decouverte": "découverte",
    "authentifie": "authentifié", "associe": "associé", "reussi": "réussi",
    "requete": "requête", "numero": "numéro", "element": "élément",
    "debut": "début", "meme": "même", "ete": "été", "interieur": "intérieur",
    "installe": "installé", "oublie": "oublié", "rejete": "rejeté",
    "echoue": "échoué", "desauthentification": "désauthentification",
    "verifiee": "vérifiée", "verifies": "vérifiés", "detectee": "détectée",
    "detecte": "détecté", "alteration": "altération", "cree": "créé",
    "simulee": "simulée", "presente": "présente", "protegees": "protégées",
    "Reseaux": "Réseaux", "premiere": "première", "reessayer": "réessayer",
    "echo": "écho", "deconnexion": "déconnexion", "indefiniment": "indéfiniment",
    "envoyee": "envoyée", "differe": "diffère", "en-tete": "en-tête",
    "diffusee": "diffusée", "chiffree": "chiffrée", "cote": "côté",
    "tete": "tête",
}

MOT_RE = re.compile(r"(?<![\w-])(" + "|".join(
    sorted(map(re.escape, MOTS), key=len, reverse=True)) + r")(?![\w-])")
LITERAL_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"')
# chaînes à ne jamais toucher : noms de commandes, de fichiers...
INTACTES = {'"etat"', '"cree"'}


def corrige(lit):
    if lit in INTACTES:
        return lit
    out = lit
    for avant, apres in PHRASES:
        out = out.replace(avant, apres)
    return MOT_RE.sub(lambda m: MOTS[m.group(1)], out)


def traite(source):
    """Applique corrige() aux chaînes, hors commentaires et #include."""
    res, i, n = [], 0, len(source)
    changes = []
    while i < n:
        if source.startswith("/*", i):
            j = source.find("*/", i + 2)
            j = n if j < 0 else j + 2
            res.append(source[i:j])
            i = j
        elif source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j < 0 else j
            res.append(source[i:j])
            i = j
        elif source[i] == "'":
            m = re.compile(r"'(?:[^'\\\n]|\\.)*'").match(source, i)
            j = m.end() if m else i + 1
            res.append(source[i:j])
            i = j
        elif source[i] == '"':
            m = LITERAL_RE.match(source, i)
            if not m:
                res.append(source[i])
                i += 1
                continue
            lit = m.group(0)
            debut_ligne = source.rfind("\n", 0, i) + 1
            if source[debut_ligne:i].lstrip().startswith("#include"):
                nouveau = lit
            else:
                nouveau = corrige(lit)
            if nouveau != lit:
                changes.append((lit, nouveau))
            res.append(nouveau)
            i = m.end()
        else:
            res.append(source[i])
            i += 1
    return "".join(res), changes


def main():
    ecrire = "--ecrire" in sys.argv
    total = 0
    for chemin in [a for a in sys.argv[1:] if not a.startswith("--")]:
        with open(chemin, encoding="utf-8") as f:
            source = f.read()
        nouveau, changes = traite(source)
        total += len(changes)
        for avant, apres in changes:
            print(f"{chemin}: {apres}")
        if ecrire and nouveau != source:
            with open(chemin, "w", encoding="utf-8") as f:
                f.write(nouveau)
    print(f"{total} chaîne(s) modifiée(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
