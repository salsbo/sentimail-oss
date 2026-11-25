"""Le propos d'un message correspond-il au métier de qui l'envoie ?

C'est la seule question qui trahit un serveur compromis : son authentification
reste parfaite, son domaine reste ancien, mais un installateur réseau se met à
parler de colis en attente. Rien dans le protocole ne le dit ; seul le sens le
dit.

Une première version de ce contrôle listait des secteurs d'activité et les
registres que chacun rendait plausibles. Cette approche est condamnée par
construction : le monde a plus de métiers qu'une liste n'en contiendra jamais,
et chaque absence devient soit un faux positif - une mutuelle dont le métier
n'était pas prévu s'est vu accuser d'avoir été détournée - soit une faille,
puisqu'un secteur manquant laisse passer. Apprécier une correspondance de sens
est un jugement, pas une mesure : il revient donc à un modèle, appelé pour
cette seule question.

Ce module ne parle jamais au modèle : il décide quand la question mérite d'être
posée, et transforme la réponse en indice. Le reste est du ressort de l'appel.
"""

from __future__ import annotations

import re
from typing import Any

from sentimail_v3.code.sender_site import is_navigation_chrome
from sentimail_v3.observation.message_parts import split_message_text

# En dessous, la page d'accueil ne dit rien d'exploitable : un mot de
# bienvenue, une bannière de cookies. Interroger un modèle là-dessus
# reviendrait à lui faire deviner. « Mutuelle santé, prévoyance et retraite
# complémentaire » fait quarante-huit caractères et suffit largement.
MIN_HEADLINE_CHARS = 40
# Un correspondant déjà confirmé n'a pas changé de métier depuis hier :
# l'historique dit mieux que le site, et la question ne coûterait qu'un appel.
#
# Un apex qui a déjà livré chez nous en fait partie, même si l'adresse exacte
# est inédite : les envoyeurs mutualisés tirent une adresse au hasard à chaque
# message - « no-reply-vtmimld8gib7io-l3pbdjg@ » chez SendGrid - de sorte que
# l'expéditeur y est éternellement inconnu à l'adresse et parfaitement établi
# à l'apex. Interroger un site sur un domaine dont vingt et un messages ont
# déjà été livrés n'apprend rien que l'historique ne dise mieux.
_KNOWN_SENDER = frozenset(
    {
        "HISTORY_CONFIRMED_LEGITIMATE_SENDER",
        "AUTHENTICATED_SENDER_ALLOW",
        "HISTORY_APEX_ESTABLISHED_LOCALLY",
    }
)
_UNIVERSAL_TRANSACTIONAL_PURPOSES = frozenset(
    {"one_time_authentication", "account_security"}
)
_CLAIMED_DISPLAY_NAME = re.compile(
    r"nom affich[ée]\s*[(:]\s*[«\"']?([^),;:\n»\"]+)",
    re.IGNORECASE,
)

COHERENCE_PROMPT = """Tu compares l'organisation qui a réellement envoyé un
message - celle dont on te donne la page d'accueil - avec ce que ce message
présente de lui-même : le nom qu'il affiche, et son propos.

Tu ne dis pas si le message est sollicité, ni s'il est honnête : d'autres s'en
chargent. Tu dis seulement s'il peut raisonnablement émaner de l'organisation
dont on te décrit l'activité.

Réponds uniquement par cet objet JSON :
{"coherent": true, "explication": "une phrase courte et concrète"}

Mets coherent=false dans deux cas, et seulement dans ceux-là.

1. Le nom affiché désigne une autre organisation que celle dont on te donne
   l'activité. Une banque, un transporteur, une administration, une plateforme
   nommés dans l'expéditeur alors que la page d'accueil décrit un tout autre
   métier : le message se présente sous une identité qui n'est pas celle de qui
   l'envoie. Un nom simplement différent ne suffit pas - une filiale, une marque
   commerciale, un service interne, une abréviation du même nom restent cohérents.

2. Le propos est manifestement étranger à l'activité publiée : un installateur
   de réseaux qui annonce un colis à dédouaner, un cabinet dentaire qui propose
   un prêt immobilier. Une organisation peut communiquer largement au-delà de
   son cœur de métier : facture, sécurité du compte, recrutement, actualité,
   invitation, enquête. Tout cela est cohérent partout.

Une personne qui écrit depuis le domaine d'une organisation peut être une
salariée ou une prestataire ; son nom personnel et son rôle RH ne désignent
pas à eux seuls une organisation étrangère. Les échanges avec clients et
fournisseurs, contrats, documents de référencement, coordonnées bancaires et
frais de mission font partie du fonctionnement courant d'une organisation.
Une page d'accueil commerciale ne décrit pas tous ses services internes.

Le texte actuel et le fil cité sont présentés séparément. Lis qui demande
quoi à qui : répondre en joignant des documents demandés ne revient pas à
réclamer ces documents au destinataire. Les citations expliquent le propos,
mais leur présentation ne prouve pas qu'un échange antérieur a eu lieu.

Dans l'explication, nomme concrètement l'organisation, son activité publiée et
le sujet du message que tu compares. Une formule générale comme « sans rapport
avec son activité » ne suffit pas.

Dans le doute, réponds coherent=true."""


def should_ask(
    site_headline: str,
    clue_codes: set[str],
    *,
    message_purpose: str = "",
) -> bool:
    """La question mérite-t-elle un appel ?

    Elle ne se pose que pour un expéditeur dont on ne sait encore rien, et
    seulement si sa page d'accueil dit quelque chose d'exploitable.
    """
    if len(site_headline.strip()) < MIN_HEADLINE_CHARS:
        return False
    # Une extraction qui n'a rapporté que le menu du site ne dit aucun métier,
    # et un menu est long : le seuil de longueur ne l'arrête pas.
    if is_navigation_chrome(site_headline):
        return False
    # La sécurité d'un compte et les codes à usage unique sont des fonctions
    # transverses : ils sont cohérents pour toute organisation qui possède des
    # comptes. Les comparer au cœur de métier ne peut donc rien apprendre.
    if message_purpose in _UNIVERSAL_TRANSACTIONAL_PURPOSES:
        return False
    return not (_KNOWN_SENDER & clue_codes)


def coherence_question(
    *,
    site_headline: str,
    display_name: str,
    subject: str,
    body: str,
    message_purpose: str = "",
) -> str:
    """Les trois éléments à comparer, chacun annoncé par son rôle.

    Le nom affiché en fait partie : sans lui, la question posée était « ce
    propos sied-il à ce métier ? », à laquelle « vous avez un nouveau message »
    répond oui pour toute organisation du monde. Le montage tient précisément
    dans l'écart entre le nom lu et le domaine qui envoie ; ne pas montrer le
    nom, c'est retirer de la question la seule chose qui le trahit.
    """
    current, quoted = split_message_text(body)
    return (
        "NOM AFFICHÉ PAR LE MESSAGE :\n"
        + (display_name.strip() or "(aucun)")
        + "\n\nSITE DE L’ORGANISATION QUI A ENVOYÉ LE MESSAGE :\n"
        + site_headline.strip()
        + "\n\nFINALITÉ DÉTECTÉE :\n"
        + (message_purpose or "(non déterminée)")
        + "\n\nMESSAGE :\nObjet : "
        + subject.strip()
        + "\nTEXTE ACTUEL :\n"
        + current[:1500]
        + ("\n\nFIL CITÉ (non authentifié) :\n" + quoted[:1500] if quoted else "")
    )


def coherence_clue(
    response: dict[str, Any] | None,
    *,
    sender_apex: str,
    display_name: str = "",
    published_activity: str = "",
    message_subject: str = "",
) -> dict[str, object] | None:
    """L'indice tiré de la réponse, ou None si elle n'est pas exploitable.

    Un modèle muet, hésitant ou hors format n'affirme rien : mieux vaut
    l'absence d'indice qu'un indice inventé à sa place.
    """
    if not isinstance(response, dict):
        return None
    verdict = response.get("coherent")
    if not isinstance(verdict, bool):
        return None
    explication = str(response.get("explication") or "").strip()[:400]
    if not explication:
        return None
    activity = re.sub(r"\s+", " ", published_activity).strip()[:260]
    subject = re.sub(r"\s+", " ", message_subject).strip()[:180]
    # Une accusation de rupture avec un métier doit conserver le métier
    # effectivement lu. Sans cette pièce, elle serait impossible à vérifier.
    if verdict is False and not activity:
        return None
    # Le modèle a déjà appelé l'objet « Vérifie ton compte » le nom affiché,
    # alors que l'en-tête disait « Seafy ». Une accusation fondée sur une
    # identité que le message n'affiche pas est inutilisable et disparaît.
    if verdict is False and display_name:
        nom_invoque = _CLAIMED_DISPLAY_NAME.search(explication)
        if nom_invoque and display_name.casefold() not in nom_invoque.group(1).casefold():
            return None
    facts = {
        "sender_apex": sender_apex,
        "claimed_name": display_name,
        "published_activity": activity,
        "message_subject": subject,
        "explication": explication,
    }
    if verdict:
        return {
            "clue_code": "SENDER_ACTIVITY_COHERENT",
            "article_code": "DEEP-018",
            "direction": "favorable",
            "strength": 20,
            "confidence": 0.75,
            "statement": (
                "Le propos de ce message correspond à l’activité que son "
                "expéditeur publie. " + explication
            ).strip(),
            "facts": facts,
        }
    return {
        "clue_code": "SENDER_ACTIVITY_INCOHERENT",
        "article_code": "DEEP-019",
        "direction": "adverse",
        "strength": 55,
        "confidence": 0.75,
        "statement": (
            "Le propos de ce message est étranger à l’activité que son "
            "expéditeur publie. " + explication
        ).strip(),
        "facts": facts,
    }
