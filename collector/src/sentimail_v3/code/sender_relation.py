"""Le domaine qui écrit et ce que le message dit de lui : les constats.

Deux contrôles confrontaient l'expéditeur au message, et chacun décidait
d'abord s'il regardait : nom qui ne désigne rien, site muet, expéditeur déjà
connu, et la question n'était pas posée. Un « skip » ne laisse rien au dossier.
Le 16 septembre 2026, « Annuel-Famille <noreply@mozn.space> » a réuni les
trois silences et livré un faux reçu « Prime Famille » à 0,95 : la marque
empruntée était dans le corps, que ni l'un ni l'autre ne lisait.

La règle change de place : on regarde toujours, on n'accuse que sur pièces.
L'enquêteur `sender_relation` rend donc toujours un constat, et au plus un
second quand le nom affiché imite l'organisation revendiquée (DEEP-026).
L'enquêteur `cousin_domain` y prend le constat du domaine qui imite un
domaine officiel (IDENTITY-010). Les
constats à charge et à décharge existent déjà (DEEP-018, DEEP-019, DEEP-021,
DEEP-022) ; ce module écrit les trois constats neutres qui remplacent le
silence, et les deux lectures qui décident ce qu'il y a à confronter.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from sentimail_v3.code.activity_coherence import MIN_HEADLINE_CHARS
from sentimail_v3.code.sender_site import is_interstitial, is_navigation_chrome

ARTICLE = "DEEP-023"
# Au-delà, les extraits de recherche répètent la même page : quatre suffisent
# à dire un métier, et le modèle n'a pas à lire une page de résultats.
_ACTIVITY_CHARS = 700
_ACTIVITY_RESULTS = 4


def footprint_clue(
    from_apex: str, *, claimed: str, results_on_domain: int, site_read: bool
) -> dict[str, object]:
    """Personne ne répond publiquement de ce domaine. Un fait, pas une charge.

    Un petit expéditeur peu référencé a le droit d'exister : c'est ce silence
    des moteurs qui accusait « Grange Immobilier ». Le constat reste neutre,
    mais il est écrit : le juge le lit, et une convergence peut le compter.
    """
    if claimed:
        revendication = (
            f" Le nom « {claimed[:80]} » sous lequel il se présente ne désigne "
            "aucune organisation trouvable."
        )
    else:
        revendication = " Le message ne se présente au nom d'aucune organisation."
    return {
        "clue_code": "SENDER_WITHOUT_PUBLIC_FOOTPRINT",
        "article_code": ARTICLE,
        "direction": "neutral",
        "strength": 0,
        "confidence": 0.8,
        "statement": (
            f"Personne ne répond publiquement du domaine {from_apex} : aucun site "
            "lisible, rien dans la recherche." + revendication
            + " Ce n'est pas une charge, c'est un vide."
        ),
        "facts": {
            "from_apex": from_apex,
            "claimed_organisation": claimed[:80],
            "results_on_domain": int(results_on_domain),
            "site_read": bool(site_read),
            "verified_by": "search",
        },
    }


def unverified_clue(from_apex: str, *, reason: str) -> dict[str, object]:
    """La vérification n'a pas eu lieu : ni charge ni décharge, mais écrit.

    Distinct de « sans répondant » : une recherche en panne n'est pas une
    absence de répondant, et une convergence ne doit jamais se fonder dessus.
    """
    return {
        "clue_code": "SENDER_RELATION_UNVERIFIED",
        "article_code": ARTICLE,
        "direction": "neutral",
        "strength": 0,
        "confidence": 1.0,
        "statement": (
            f"Le rapport entre {from_apex} et ce que le message affiche n'a pas "
            f"pu être vérifié ({reason}) : ni charge ni décharge."
        ),
        "facts": {"from_apex": from_apex, "reason": reason[:80]},
    }


def consistent_clue(
    from_apex: str, *, organisation: str, how: str
) -> dict[str, object]:
    """Le nom affiché et le domaine concordent. Cela dit qui a écrit, rien de plus.

    Neutre à dessein : un rapport plausible n'est pas une preuve d'authenticité,
    et rassurer sur cette base referait l'erreur que ce contrôle existe pour
    corriger.
    """
    comment = (
        "porte ce nom" if how == "domain_label" else "lui est attribué par la recherche"
    )
    return {
        "clue_code": "SENDER_RELATION_CONSISTENT",
        "article_code": ARTICLE,
        "direction": "neutral",
        "strength": 0,
        "confidence": 0.8,
        "statement": (
            f"Le message se présente au nom de {organisation[:80]}, et le domaine "
            f"{from_apex} {comment}. Cela dit qui a écrit, pas que le message est honnête."
        ),
        "facts": {
            "from_apex": from_apex,
            "claimed_organisation": organisation[:80],
            "how": how,
        },
    }


def disguised_name_clue(
    from_apex: str, *, display_name: str, organisation: str, imite: str
) -> dict[str, object]:
    """Le nom affiché imite, par des caractères sosies, l'organisation revendiquée.

    Un caractère ambigu seul ne dit rien : de vrais noms en portent. Un nom qui
    ne se lit comme l'organisation annoncée qu'à la condition de confondre un l
    et un I, un 0 et un o, a été écrit pour tromper la lecture rapide. C'est
    une intention, pas une maladresse.
    """
    return {
        "clue_code": "IDENTITY_DISPLAY_NAME_DISGUISED",
        "article_code": "DEEP-026",
        "direction": "adverse",
        "strength": 70,
        "confidence": 0.85,
        "statement": (
            f"Le nom affiché « {display_name[:80]} » se lit « {imite} », comme "
            f"{organisation[:80]} que le message revendique, mais ne l’écrit pas : "
            "des caractères sosies y tiennent la place des vrais."
        ),
        "facts": {
            "from_apex": from_apex,
            "display_name": display_name[:80],
            "claimed_organisation": organisation[:80],
            "imite": imite,
        },
    }


def cousin_domain_clue(
    from_apex: str, *, from_domain: str, imite: str, organisation: str
) -> dict[str, object]:
    """L'adresse d'envoi imite, par des caractères sosies, un domaine officiel.

    Le domaine officiel est celui qu'une recherche a établi pour une
    organisation ; le message, lui, peut ne rien revendiquer. Les faits ne
    portent donc pas de `claimed_organisation` : la carte « Se présente
    comme » dirait ce que le détecteur n'a pas lu.
    """
    domaine = from_domain or from_apex
    return {
        "clue_code": "IDENTITY_COUSIN_DOMAIN",
        "article_code": "IDENTITY-010",
        "direction": "adverse",
        "strength": 65,
        "confidence": 0.85,
        "statement": (
            f"L’adresse d’envoi {domaine} se lit comme {imite}, domaine officiel "
            f"de {organisation[:80]} selon la recherche, mais ne l’écrit pas : "
            "des caractères sosies y tiennent la place des vrais."
        ),
        "facts": {
            "from_apex": from_apex,
            "from_domain": from_domain,
            "imite": imite,
            "official_apexes": [imite],
            "imitated_organisation": organisation[:80],
            "constat": "domaine_sosie",
        },
    }


def published_activity(
    site: dict[str, str] | None, domain_results: list[dict[str, Any]], *, from_apex: str = ""
) -> tuple[str, str]:
    """Ce que l'expéditeur publie de son métier, et d'où on le tient.

    La page d'accueil d'abord ; sans elle, ce que la recherche dit du domaine :
    une école de langue sans site lisible reste une école de langue pour qui
    la cherche.
    """
    texte = str((site or {}).get("text") or "").strip()
    if texte:
        return texte[:_ACTIVITY_CHARS], "site"
    lignes: list[str] = []
    for item in domain_results:
        host = (urlsplit(str(item.get("url") or "")).hostname or "").casefold()
        # Un moteur peut répondre à un domaine inconnu par des homonymes.
        # Ces pages ne décrivent pas son titulaire sans le nommer exactement.
        if from_apex and not (
            host == from_apex or host.endswith("." + from_apex)
            or from_apex in str(item.get("content") or "").casefold().split()
        ):
            continue
        titre = str(item.get("title") or "").strip()[:120]
        contenu = str(item.get("content") or "").strip()[:300]
        if titre or contenu:
            lignes.append(f"{titre} : {contenu}".strip(" :"))
        if len(lignes) >= _ACTIVITY_RESULTS:
            break
    recherche = " ".join(lignes).strip()
    if recherche:
        return recherche[:_ACTIVITY_CHARS], "search"
    return "", ""


def activity_readable(text: str) -> bool:
    """Ce texte dit-il un métier qu'on puisse confronter au propos ?

    Un mot de bienvenue, un menu de navigation ou le mur d'un hébergeur ne
    décrivent aucune activité : les comparer reviendrait à faire deviner.
    """
    valeur = text.strip()
    if len(valeur) < MIN_HEADLINE_CHARS:
        return False
    if is_navigation_chrome(valeur) or is_interstitial(valeur):
        return False
    return True
