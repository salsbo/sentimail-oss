"""Le domaine qui envoie appartient-il à l'organisation dont le nom s'affiche ?

Le contrôle de cohérence d'activité compare ce qu'un expéditeur publie avec ce
que son message raconte. Il exige donc une page d'accueil lisible - et un
domaine jetable n'en a pas. La question n'était alors pas posée du tout, et
l'absence de site produisait un silence, alors qu'elle est en soi remarquable
pour qui se réclame d'une banque ou d'un transporteur.

Ce module pose la question qui reste possible quand il n'y a rien à lire : ce
nom désigne-t-il une organisation identifiable, et ce domaine peut-il lui
appartenir ? C'est la forme calculée de ce que le référentiel de marques dit
par énumération - à ceci près qu'elle vaut pour toute organisation, y compris
celles qu'aucune table ne contiendra jamais.

Deux garde-fous portent tout le reste. Le premier : l'indice est adverse ou
absent, jamais favorable. Rassurer sur la foi d'un site qu'on n'a pas pu lire
serait refaire l'erreur que ce module existe pour corriger. Le second : dans le
doute, le modèle répond que le domaine peut appartenir - une accusation par
défaut coûterait plus cher qu'un silence.
"""

from __future__ import annotations

from typing import Any

# Un correspondant déjà confirmé n'a rien à prouver : l'historique dit mieux
# que n'importe quel jugement porté sur son nom.
_KNOWN_SENDER = frozenset(
    {"HISTORY_CONFIRMED_LEGITIMATE_SENDER", "AUTHENTICATED_SENDER_ALLOW"}
)

CLAIM_PROMPT = """Tu regardes deux choses : le nom qu'un message affiche comme
expéditeur, et le domaine depuis lequel il a réellement été envoyé.

Tu ne juges pas le message. Tu dis seulement si ce domaine peut appartenir à
l'organisation que ce nom désigne.

Réponds uniquement par cet objet JSON :
{"appartient": true, "organisation": "le nom de l'organisation désignée, ou une chaîne vide", "explication": "une phrase courte et concrète"}

Mets appartient=null si le nom ne désigne aucune organisation identifiable :
un prénom, un nom de personne, un intitulé générique comme « Service client »,
« Notifications » ou « Ne pas répondre ». Il n'y a alors rien à comparer.

Mets appartient=false seulement si le nom désigne une organisation reconnaissable
- banque, assureur, transporteur, administration, opérateur, plateforme,
enseigne - et que le domaine d'envoi lui est manifestement étranger : autre
raison sociale, autre pays d'activité, autre métier.

Mets appartient=true dans tous les autres cas, et notamment dès qu'un lien est
plausible : filiale, marque commerciale, prestataire d'envoi, domaine régional,
abréviation ou variante du même nom. Dans le doute, réponds true."""


def should_ask_claim(
    *, display_name: str, site_headline: str, clue_codes: set[str]
) -> bool:
    """La question a-t-elle lieu d'être posée ?

    Il suffit qu'un expéditeur inconnu affiche un nom qui revendique quelque
    chose. Un nom affiché qui recopie l'adresse ne revendique rien.

    Le site de l'expéditeur en dispensait, au motif que la cohérence d'activité
    prenait alors la main. Elle ne le faisait pas : elle compare un métier à un
    registre - livraison, paiement - et se tait sur tout le reste. Un faux
    « DISNEY+ » envoyé depuis le domaine bien vivant d'une école de langue
    tombait exactement entre les deux contrôles, le 26 août. Un site lisible dit
    ce que fait son propriétaire ; il ne dit rien du nom qu'un message emprunte.
    Le paramètre demeure : il décrit ce qu'on a pu lire, sans plus décider si
    la question se pose.
    """
    nom = display_name.strip()
    if not nom or "@" in nom:
        return False
    return not (_KNOWN_SENDER & clue_codes)


def claim_question(*, display_name: str, from_apex: str, subject: str) -> str:
    return (
        "NOM AFFICHÉ PAR LE MESSAGE :\n"
        + display_name.strip()
        + "\n\nDOMAINE QUI A ENVOYÉ LE MESSAGE :\n"
        + from_apex.strip()
        + "\n\nOBJET DU MESSAGE :\n"
        + subject.strip()[:300]
    )


def claim_clue(response: Any, *, from_apex: str) -> dict[str, object] | None:
    """L'indice tiré de la réponse, ou rien.

    Un modèle muet, hésitant ou hors format n'affirme rien. Et une réponse qui
    dit « le domaine peut appartenir » ne produit pas d'indice non plus : elle
    constate une absence de contradiction, pas une preuve d'appartenance.
    """
    if not isinstance(response, dict):
        return None
    if response.get("appartient") is not False:
        return None
    organisation = str(response.get("organisation") or "").strip()[:80]
    if not organisation:
        return None
    explication = str(response.get("explication") or "").strip()[:400]
    return {
        "clue_code": "IDENTITY_CLAIMED_ORGANISATION_UNRELATED",
        "article_code": "DEEP-021",
        "direction": "adverse",
        # Moins que la cohérence d'activité mesurée sur un site réel (55) : ce
        # jugement-ci repose sur un nom et un domaine, sans rien à lire.
        "strength": 45,
        "confidence": 0.7,
        "statement": (
            f"Le message se présente au nom de {organisation}, mais il est "
            f"envoyé depuis un domaine qui ne lui appartient pas. " + explication
        ).strip(),
        "facts": {
            "from_apex": from_apex,
            "claimed_organisation": organisation,
            "explication": explication,
        },
    }
