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


def official_apexes(results: list[dict[str, object]]) -> list[str]:
    """Les domaines que la recherche attribue à l'organisation.

    L'ordre des résultats est conservé : le premier est celui que le moteur
    tient pour le plus représentatif, et c'est celui qu'on cite.
    """
    apexes: list[str] = []
    for result in results[:MAX_RESULTS]:
        url = str(result.get("url") or "")
        if not url:
            continue
        apex = _apex(urlsplit(url).hostname or "")
        if not apex or apex in _NOT_OFFICIAL or apex in apexes:
            continue
        apexes.append(apex)
    return apexes


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


def _quoted(organisation: str, apexes: list[str]) -> list[str]:
    """Ceux qu'on peut citer sans se ridiculiser.

    Un moteur rend aussi du bruit : « nlm.nih.gov » est arrivé le 26 août dans
    les résultats pour Disney+. Le garder ne change pas la décision - le
    domaine émetteur reste étranger à tous - mais l'écrire dans un avis
    revient à affirmer une sottise à l'utilisateur. On cite donc en priorité
    les domaines qui portent le nom cherché, et à défaut les premiers rendus.

    La décision, elle, continue de porter sur la liste entière : retenir un
    domaine de trop ne peut qu'éviter une accusation, jamais en fabriquer une.
    """
    racine = _normalise(organisation).replace(" ", "")
    portant = [apex for apex in apexes if racine and racine[:6] in apex.replace("-", "")]
    return portant or apexes[:2]


def lookup_outcome(
    organisation: str, from_apex: str, apexes: list[str]
) -> dict[str, object] | None:
    """Ce que la recherche apprend sur un soupçon déjà formé.

    Trois issues, et une seule renforce : le domaine est étranger à tous les
    sites officiels trouvés. Qu'il en fasse partie annule le soupçon ; qu'on
    n'ait rien trouvé le laisse intact.
    """
    if not apexes:
        return None
    if belongs(from_apex, apexes):
        return {
            "verified": False,
            "cleared": True,
            "official_apexes": apexes,
            "organisation": organisation,
        }
    return {
        "verified": True,
        "cleared": False,
        "official_apexes": apexes,
        "organisation": organisation,
        "statement": (
            f"Les sites officiels de {organisation} sont "
            + ", ".join(_quoted(organisation, apexes)[:3])
            + f" ; le message vient de {_apex(from_apex) or from_apex}."
        ),
    }
