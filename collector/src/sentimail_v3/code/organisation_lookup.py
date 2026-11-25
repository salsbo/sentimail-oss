"""Les domaines officiels d'une organisation, cherchés au moment où on en doute.

Une table de marques ne peut pas suivre : elle contient ce qu'on a déjà vu, et
le montage suivant se réclamera d'un nom qui n'y est pas. « DISNEY+ RECOVERY »
est passé le 26 août parce que « disney » manquait au référentiel, et rien
d'autre ne pouvait constater qu'une école de langue australienne n'est pas le
service des abonnements de Disney.

Ce module pose donc la question dehors : quels domaines cette organisation
utilise-t-elle réellement ? Ce que la recherche rend n'est pas une réputation
ni un score - c'est une liste d'adresses officielles, à comparer au domaine qui
a écrit. La comparaison, elle, reste ici.

Ce qui sort d'ici : le nom que le message affiche, et rien d'autre. Ni le
destinataire, ni l'objet, ni une ligne du message.

Deux garde-fous, comme pour tout ce qui juge une identité :

- la recherche ne fabrique jamais une accusation. Elle confirme un soupçon déjà
  formé, ou elle l'annule quand le domaine figure parmi les sites officiels ;
- une recherche muette, en panne ou sans résultat exploitable laisse le soupçon
  tel quel, ni renforcé ni effacé.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# Les hébergeurs, encyclopédies et annuaires disent qui est une organisation
# sans être elle. Retenir leur domaine comme « officiel » ferait passer pour
# authentique tout message envoyé depuis une page Wikipédia.
_NOT_OFFICIAL = frozenset(
    {
        "wikipedia.org",
        "wikimedia.org",
        "wikidata.org",
        "linkedin.com",
        "facebook.com",
        "instagram.com",
        "x.com",
        "twitter.com",
        "youtube.com",
        "crunchbase.com",
        "bloomberg.com",
        "societe.com",
        "pappers.fr",
        "verif.com",
        "trustpilot.com",
        "glassdoor.com",
        "indeed.com",
        "apple.com",
        "play.google.com",
        "google.com",
        "amazon.com",
        "reddit.com",
        "medium.com",
        "github.com",
    }
)
# Un nom qui ne désigne personne : le chercher ne rendrait que du bruit.
_TOO_GENERIC = frozenset(
    {
        "service client",
        "support",
        "notification",
        "notifications",
        "no reply",
        "ne pas repondre",
        "info",
        "contact",
        "equipe",
        "team",
        "alerte",
        "securite",
        "administration",
    }
)
_MIN_NAME_CHARS = 3
# Au-delà, la liste ne dit plus « ses domaines » mais « tout ce qui parle
# d'elle » : les premiers résultats sont les seuls qui portent l'organisation.
MAX_RESULTS = 6


def _apex(host: str) -> str:
    """Le domaine enregistrable, tel que le reste du Code le compare."""
    host = host.strip().casefold().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return ""
    # Les suffixes à deux étiquettes (co.uk, com.au, gouv.fr) gardent trois
    # étiquettes : careerwiseenglish.com.au, pas com.au.
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def searchable(organisation: str) -> bool:
    """Ce nom désigne-t-il quelqu'un qu'on puisse chercher ?"""
    nom = _normalise(organisation)
    if len(nom.replace(" ", "")) < _MIN_NAME_CHARS:
        return False
    return nom not in _TOO_GENERIC


def search_query(organisation: str) -> str:
    """Ce qui part vers le moteur : un nom, et la question posée dessus."""
    return f"{organisation.strip()} site officiel domaine de l'entreprise"


def official_apexes(
    results: list[dict[str, object]], organisation: str = ""
) -> list[str]:
    """Les domaines que la recherche attribue à l'organisation.

    L'ordre des résultats est conservé : le premier est celui que le moteur
    tient pour le plus représentatif, et c'est celui qu'on cite.

    Quand le nom cherché est donné, un domaine n'est officiel que s'il le
    porte (`porte_le_nom`). La recherche sur « Nintendo » rendait gouv.fr et
    lechompenchaine.fr au milieu de nintendo.com : cités comme officiels, ils
    faisaient accuser nintendo-europe.com d'imiter une marque qui n'était pas
    la leur.
    """
    from sentimail_v3.code.identity_relation import _label, _tokens

    filtre = bool(organisation and _tokens(organisation))
    apexes: list[str] = []
    for result in results[:MAX_RESULTS]:
        url = str(result.get("url") or "")
        if not url:
            continue
        apex = _apex(urlsplit(url).hostname or "")
        if not apex or apex in _NOT_OFFICIAL or apex in apexes:
            continue
        if filtre and not porte_le_nom(_label(apex), organisation):
            continue
        apexes.append(apex)
    return apexes


def _morceaux(organisation: str) -> list[str]:
    """Tous les morceaux écrits du nom, courts compris ; « + » se lit « plus »."""
    from sentimail_v3.code.identity_relation import _sans_accents

    texte = _sans_accents(organisation.replace("+", " plus "))
    return [morceau for morceau in re.split(r"[^a-z0-9]+", texte) if morceau]


def porte_le_nom(etiquette: str, organisation: str) -> bool:
    """Le nom propre d'un domaine porte-t-il le nom cherché ?

    Un nom d'un mot : ce mot dans l'étiquette, comme toujours (nintendo.com,
    disneyplus.com). Un nom de plusieurs mots : l'étiquette en porte au moins
    deux (creditagricole pour « Crédit Agricole d'Ile-de-France »,
    primevideo), ou elle n'est faite que de morceaux du nom (laposte pour « La
    Poste-Colissimo », lidl pour « Lidl France », samsclub pour « Sam's Club
    Member Services »).

    Un seul mot trouvé à l'intérieur d'une étiquette qui porte autre chose ne
    suffit plus : pour « BOURGEOIS Muriel via PRONOTE », rbourgeois.fr portait
    « bourgeois » et a été cité comme domaine officiel d'une enseignante
    (M-633c24) ; philduval.com l'a été pour « Philippe DUVAL ».

    Chaque morceau trouvé est retiré de l'étiquette avant de chercher le
    suivant : deux mots qui se chevauchent n'en font pas deux.
    """
    from sentimail_v3.code.identity_relation import _tokens

    mots = _tokens(organisation)
    if not etiquette or not mots:
        return False
    if len(mots) == 1:
        return mots[0] in etiquette
    reste, trouves = etiquette, 0
    for mot in sorted(set(mots), key=len, reverse=True):
        if mot in reste:
            reste = reste.replace(mot, " ", 1)
            trouves += 1
    if trouves >= 2:
        return True
    if not trouves:
        return False
    for morceau in sorted(set(_morceaux(organisation)), key=len, reverse=True):
        while morceau in reste:
            reste = reste.replace(morceau, " ", 1)
    return not reste.strip()


def belongs(from_apex: str, apexes: list[str]) -> bool:
    """Le domaine qui a écrit figure-t-il parmi ceux de l'organisation ?

    La comparaison est celle du reste du Code : le même apex, ou un
    sous-domaine du sien. Une simple ressemblance de nom ne suffit pas - c'est
    précisément ce que les montages fabriquent.
    """
    domaine = _apex(from_apex) or from_apex.strip().casefold()
    if not domaine:
        return False
    return any(
        domaine == apex or domaine.endswith("." + apex) for apex in apexes
    )


def remembered_apexes(
    organisation: str, remembered: list[tuple[str, list[str]]]
) -> list[str]:
    """Les domaines officiels qu'une recherche passée a déjà établis pour ce nom.

    La recherche sur « Prime Video » rendait amazon.jobs, aboutamazon.com,
    amazon.com : aucun ne porte le nom cherché, aucun n'était retenu, et le
    démenti ne pouvait pas s'écrire (M-8d026c). La mémoire connaissait pourtant
    primevideo.com, trouvé sous « amazon prime video ». Elle n'était qu'écrite.

    Un nom retenu doit contenir tous les mots du nom cherché, et un domaine n'est
    repris que s'il les porte tous - le filtre d'`official_apexes`, en plus
    strict, parce que la page qui l'avait rendu n'est plus là pour en répondre.
    Un nom d'un seul mot n'en hérite pas : « Infos » se retrouverait dans
    n'importe quelle organisation retenue.
    """
    from sentimail_v3.code.identity_relation import _label, _tokens

    mots = _tokens(organisation)
    if len(mots) < 2:
        return []
    apexes: list[str] = []
    for nom, candidats in remembered:
        if not all(mot in _tokens(nom) for mot in mots):
            continue
        for apex in candidats:
            etiquette = _label(apex)
            if apex in apexes or apex in _NOT_OFFICIAL:
                continue
            if all(mot in etiquette for mot in mots):
                apexes.append(apex)
    return apexes


def officials_in_memory(remembered: list[tuple[str, list[str]]]) -> dict[str, str]:
    """Les domaines que les recherches passées ont établis officiels, et pour quel nom.

    La table garde des lignes écrites avant le filtre par le nom : relue telle
    quelle, elle tenait pour officiels nlm.nih.gov sous « disney+ » ou des
    domaines viticoles sous « product hunt daily ». Le filtre d'aujourd'hui y
    est donc réappliqué : 549 apex bruts au 29 septembre 2026, 208 retenus.
    Le premier nom qui établit un domaine est celui qu'on cite.
    """
    from sentimail_v3.code.identity_relation import _label

    out: dict[str, str] = {}
    for organisation, apexes in remembered:
        for apex in apexes:
            if apex in _NOT_OFFICIAL or not porte_le_nom(_label(apex), organisation):
                continue
            out.setdefault(apex, organisation)
    return out
