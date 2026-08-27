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

from typing import Any

# En dessous, la page d'accueil ne dit rien d'exploitable : un mot de
# bienvenue, une bannière de cookies. Interroger un modèle là-dessus
# reviendrait à lui faire deviner. « Mutuelle santé, prévoyance et retraite
# complémentaire » fait quarante-huit caractères et suffit largement.
MIN_HEADLINE_CHARS = 40
# Un correspondant déjà confirmé n'a pas changé de métier depuis hier :
# l'historique dit mieux que le site, et la question ne coûterait qu'un appel.
_KNOWN_SENDER = frozenset(
    {"HISTORY_CONFIRMED_LEGITIMATE_SENDER", "AUTHENTICATED_SENDER_ALLOW"}
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

Dans le doute, réponds coherent=true."""


def should_ask(site_headline: str, clue_codes: set[str]) -> bool:
    """La question mérite-t-elle un appel ?

    Elle ne se pose que pour un expéditeur dont on ne sait encore rien, et
    seulement si sa page d'accueil dit quelque chose d'exploitable.
    """
    if len(site_headline.strip()) < MIN_HEADLINE_CHARS:
        return False
    return not (_KNOWN_SENDER & clue_codes)


def coherence_question(
    *, site_headline: str, display_name: str, subject: str, body: str
) -> str:
    """Les trois éléments à comparer, chacun annoncé par son rôle.

    Le nom affiché en fait partie : sans lui, la question posée était « ce
    propos sied-il à ce métier ? », à laquelle « vous avez un nouveau message »
    répond oui pour toute organisation du monde. Le montage tient précisément
    dans l'écart entre le nom lu et le domaine qui envoie ; ne pas montrer le
    nom, c'est retirer de la question la seule chose qui le trahit.
    """
    return (
        "NOM AFFICHÉ PAR LE MESSAGE :\n"
        + (display_name.strip() or "(aucun)")
        + "\n\nSITE DE L’ORGANISATION QUI A ENVOYÉ LE MESSAGE :\n"
        + site_headline.strip()
        + "\n\nMESSAGE :\nObjet : "
        + subject.strip()
        + "\n"
        + body[:1500]
    )


def coherence_clue(
    response: dict[str, Any] | None, *, sender_apex: str
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
            "facts": {"sender_apex": sender_apex, "explication": explication},
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
        "facts": {"sender_apex": sender_apex, "explication": explication},
    }
