"""Un nom écrit pour ressembler à un autre, lu comme l'œil le lit.

« lnfosPRlME » ne contient pas « prime » : deux l minuscules y tiennent la
place de deux I. Le détecteur de caractères, qui cherchait des fautes
précises, n'y voyait rien (M-8d026c, 25 septembre 2026) ; chaque nouveau
déguisement lui échappait de la même façon.

Le squelette ramène les caractères que l'œil confond à un seul signe - la
méthode des « confusables » d'Unicode (TR39), réduite à l'ASCII. Il dit que
deux écritures se confondent, jamais laquelle est la bonne : « lnfosPRlME » et
« InfosPRIME » ont le même. Il ne sert donc jamais seul. Il compare un nom à
ce que le message revendique lui-même : sans cible, pas de charge, et
« Charlie » ou « Village » ne sont rien.
"""

from __future__ import annotations

import re
import unicodedata

# Les suites de lettres qu'on lit comme une autre, avant la table caractère par
# caractère : « rn » passe pour « m », « vv » pour « w ».
_SUITES = (("rn", "m"), ("vv", "w"))
# Après passage en minuscules : le I majuscule est devenu « i », qui se lit
# comme « l » ; le chiffre 1 et la barre aussi. Le zéro se lit comme « o ».
_SIGNES = str.maketrans({"i": "l", "1": "l", "|": "l", "!": "l", "0": "o"})
_HORS_NOM = re.compile(r"[^a-z0-9|!]+")
# Un mot plus court se retrouve par hasard dans n'importe quel nom.
_MIN_CIBLE = 4
# Une forme juridique n'est le nom de personne : « SARL » revendiqué dans un
# corps se lisait dans « Sari », la commune qui écrit à ses administrés.
_FORMES_JURIDIQUES = frozenset({"sarl", "eurl", "sasu", "gmbh", "corp"})


def _a_plat(value: str) -> str:
    decompose = unicodedata.normalize("NFKD", value.casefold())
    sans_accents = "".join(char for char in decompose if not unicodedata.combining(char))
    return _HORS_NOM.sub("", sans_accents)


def squelette(value: str) -> str:
    """La forme que l'œil retient d'un nom, sans casse, accents ni séparateurs."""
    forme = _a_plat(value)
    for suite, lue in _SUITES:
        forme = forme.replace(suite, lue)
    return forme.translate(_SIGNES)


def nom_deguise(nom_affiche: str, revendique: str) -> str:
    """Le mot revendiqué que le nom affiché imite sans l'écrire, ou rien.

    Le mot doit se lire dans un mot du nom - entier, à son début ou à sa fin -
    et manquer dans son écriture réelle : c'est l'écart entre les deux qui est
    un déguisement. Lu n'importe où, il se retrouvait par hasard au milieu d'un
    mot (« bill » dans « MOBILIER ») ou à cheval sur deux. Un nom qui écrit la
    marque en toutes lettres n'imite rien - qu'il ait le droit de l'écrire est
    une autre question, posée ailleurs.
    """
    from sentimail_v3.code.identity_relation import _tokens

    mots_du_nom = [
        mot for mot in re.split(r"[^a-z0-9|!]+", _en_mots(nom_affiche)) if mot
    ]
    for cible in _tokens(revendique):
        if len(cible) < _MIN_CIBLE or cible in _FORMES_JURIDIQUES:
            continue
        lue = squelette(cible)
        for mot in mots_du_nom:
            forme = squelette(mot)
            placee = forme == lue or forme.startswith(lue) or forme.endswith(lue)
            if placee and cible not in _a_plat(mot):
                return cible
    return ""


def ecriture_du_message(nom: str, texte: str) -> str:
    """Le nom revendiqué tel que le message l'écrit, quand il le déguise ici.

    « AppIe <noreply@jobfinder.fr> » (M-38cfc3, 26 octobre 2026) : le lecteur
    d'organisation a recopié le nom affiché, et DEEP-026 comparait le
    déguisement à lui-même. Le corps écrivait « Apple » six fois.

    Un mot du nom qui porte un caractère sosie prend l'écriture d'un mot du
    texte qui a le même squelette et n'en porte aucun. Seul ce sens est permis :
    une « Apple » affichée ne devient jamais l'« AppIe » d'un pied de page.
    """
    from sentimail_v3.observation.dossier.hooks.identity import _ascii_identity_markers

    def sosie(mot: str) -> bool:
        return bool(_ascii_identity_markers(mot, "display_name"))

    cherches = {
        squelette(mot)
        for mot in re.findall(r"\w+", nom)
        if len(mot) >= _MIN_CIBLE and sosie(mot)
    }
    if not cherches:
        return nom
    ecrits: dict[str, str] = {}
    for mot in re.findall(r"\w+", texte):
        forme = squelette(mot)
        if forme in cherches and forme not in ecrits and not sosie(mot):
            ecrits[forme] = mot

    def remplace(trouve: re.Match[str]) -> str:
        mot = trouve.group(0)
        ecrit = ecrits.get(squelette(mot)) if sosie(mot) else None
        return ecrit if ecrit and _a_plat(ecrit) != _a_plat(mot) else mot

    return re.sub(r"\w+", remplace, nom)


def _en_mots(value: str) -> str:
    """Comme `_a_plat`, en gardant les séparateurs qui délimitent les mots."""
    decompose = unicodedata.normalize("NFKD", value.casefold())
    return "".join(char for char in decompose if not unicodedata.combining(char))


# Une étiquette officielle plus courte se retrouve par hasard ailleurs : à cinq
# lettres, aucune collision de squelette parmi 5 025 apex observés.
_MIN_ETIQUETTE = 5


def domaine_sosie(from_apex: str, officiels: list[str], from_domain: str = "") -> str:
    """Le domaine officiel dont l'adresse d'envoi reprend le squelette sans l'écrire, ou rien.

    L'étiquette de l'apex, ou un morceau d'au moins cinq lettres du domaine
    complet, doit se lire comme l'étiquette d'un domaine officiel sans
    l'écrire : « exemp1ebanque » pour « exemplebanque », « rn » pour « m ».
    Les officiels sont ceux que la recherche a établis pour les organisations
    revendiquées par le courrier réel, jamais une liste écrite à la main.

    Le squelette seul, parce que c'est la seule lecture qui n'accusait
    personne à tort : sur toute la base, du 11 août au 29 septembre 2026, la
    distance d'édition d'une lettre touchait 15 messages dont 13 légitimes.

    Ce qu'elle ne voit pas : une faute de frappe (lettre ajoutée, retirée ou
    intervertie), un tiret ajouté, une autre extension. La même étiquette sous
    une autre extension ou dans un sous-domaine relève de l'appartenance, et
    le nom officiel accolé à un autre mot d'`appended_to_official`.
    """
    from sentimail_v3.code.identity_relation import _label

    etiquette = _label(from_apex)
    if not etiquette:
        return ""
    morceaux = {etiquette} | {
        morceau
        for morceau in re.split(r"[.\-]+", (from_domain or "").casefold())
        if len(morceau) >= _MIN_ETIQUETTE
    }
    for apex in officiels:
        officielle = _label(apex)
        if len(officielle) < _MIN_ETIQUETTE or apex.casefold() == from_apex.casefold():
            continue
        lue = squelette(officielle)
        for morceau in sorted(morceaux):
            # Écrit tel quel, ou accolé à un autre mot : d'autres constats.
            if morceau == officielle or officielle in morceau:
                continue
            if squelette(morceau) == lue:
                return apex
    return ""
