"""Registres d'activité du message et pages d'accueil réellement lisibles.

Le rapprochement avec l'activité publiée est désormais confié au hook LLM
borné ``activity_coherence``. Ce module conserve seulement les faits locaux qui
déterminent si cette question mérite d'être posée et si la page obtenue décrit
bien l'expéditeur plutôt qu'un interstitiel d'hébergeur.
"""

from __future__ import annotations

import re
import unicodedata


# Registres transactionnels : ceux dont un message se réclame pour obtenir une
# action, et qui supposent une activité correspondante chez l'expéditeur.
_REGISTERS: dict[str, tuple[str, ...]] = {
    "livraison": (
        # Vocabulaire relevé sur le courrier réellement reçu : les campagnes
        # évitent « colis » et disent « paquet », « envoi » ou « retrait ».
        "colis", "paquet", "envoi", "livraison", "livrer", "livre",
        "expedition", "expedier", "transporteur", "retrait", "point relais",
        "suivi de commande", "frais de port", "frais de livraison", "douane",
        "remise", "remettre", "acheminement", "destinataire",
        "parcel", "package", "delivery", "deliver", "shipping", "shipment",
        "courier", "tracking", "redelivery", "consegna", "spedizione",
        "pacco", "logistique", "logistica",
    ),
    "paiement": (
        "virement", "iban", "coordonnees bancaires", "carte bancaire",
        "prelevement", "facture impayee", "reglement", "remboursement",
        "paiement", "payment", "invoice", "bank", "banque", "billing",
    ),
    # Le registre « compte » a existé ici, et il a produit un faux positif sur
    # un code de sécurité de mutuelle : n'importe quel service en ligne -
    # mutuelle, banque, commerçant, administration - envoie des codes de
    # vérification. Se réclamer d'un compte ne dit donc rien du métier, et ne
    # peut fonder aucune contradiction. Seules restent les activités qu'une
    # organisation exerce ou n'exerce pas.
}
# Ce qu'un hébergeur répond à notre place quand il ne veut pas nous laisser
# entrer. Ces pages n'appartiennent à personne : les lire comme la description
# d'un métier revient à reprocher à un expéditeur ce que son pare-feu a dit.
# Le 21 août, « Enable JavaScript and cookies to continue » - quarante et un
# caractères, un de plus que le seuil - a fait juger qu'une alerte de connexion
# OpenAI n'avait rien à voir avec l'activité d'OpenAI.
_INTERSTITIELS = (
    "enable javascript",
    "javascript is disabled",
    "turn javascript on",
    "activer javascript",
    "just a moment",
    "checking your browser",
    "verify you are human",
    "verifying you are human",
    "are you a robot",
    "attention required",
    "access denied",
    "request blocked",
    "unusual traffic",
    "ddos protection",
    "cloudflare ray id",
    "please enable cookies",
    "error 10",
)
# Au-delà, la page dit autre chose qu'un refus : un site qui décrit son métier
# sur quinze lignes et redemande JavaScript en pied de page reste lisible.
LONGUEUR_INTERSTITIEL_MAX = 400
# Un refus s'annonce d'emblée : c'est la première chose que la page dit. La
# même mention arrivant après une description de métier est une note de bas de
# page, pas un mur.
DEBUT_INTERSTITIEL = 150


def is_interstitial(site_text: str) -> bool:
    """La page lue est-elle un refus d'entrer plutôt qu'une page d'accueil ?

    Deux conditions, et les deux comptent. Le motif seul écarterait des sites
    parfaitement bavards qui mentionnent JavaScript au passage ; la brièveté
    seule écarterait une accroche courte mais vraie. C'est une page courte ET
    faite de ce vocabulaire-là qui ne décrit aucune activité.
    """
    texte = _normalize(site_text)
    if not texte.strip():
        return True
    if len(texte) > LONGUEUR_INTERSTITIEL_MAX:
        return False
    ouverture = texte[:DEBUT_INTERSTITIEL]
    return any(motif in ouverture for motif in _INTERSTITIELS)


# Le lien d'évitement que la norme d'accessibilité (WCAG 2.4.1) fait poser en
# tête de page, dans la langue du site. Sa présence en ouverture signe une
# extraction qui n'a rapporté que l'en-tête et son menu : des étiquettes de
# rubriques, pas une description de métier.
_LIENS_D_EVITEMENT = (
    "skip to main content",
    "skip to content",
    "skip navigation",
    "skip to footer",
    "aller au contenu",
    "aller directement au contenu",
    "passer au contenu",
    "saltar al contenido",
    "passa al contenuto",
    "zum inhalt springen",
    "salta al contenuto",
)
# Une ponctuation de phrase, même une virgule, suffit à distinguer une prose
# d'une liste d'étiquettes. « Mutuelle santé, prévoyance et retraite
# complémentaire » en porte une ; « Research Overview Alignment Economics
# Engineering » n'en porte aucune.
_PONCTUATION_DE_PHRASE = re.compile(r"[.,;:!?]")


def is_navigation_chrome(site_text: str) -> bool:
    """Le texte lu n'est-il que l'en-tête de navigation du site ?

    Deux conditions, comme pour un interstitiel, et les deux comptent. Le lien
    d'évitement seul écarterait un site bavard dont l'extraction a simplement
    commencé par son menu ; l'absence de ponctuation seule écarterait une
    accroche courte mais vraie. C'est un texte ouvert par un lien d'évitement
    ET dépourvu de toute phrase qui ne décrit aucune activité.

    Le 1er septembre 2026, la page d'accueil d'anthropic.com n'a rendu que
    « Home \\ Anthropic Skip to main content Skip to footer Research Overview
    Alignment Economics… ». Comparé à « votre accès à l'API est désactivé », ce
    menu a valu à une notification authentique d'être tenue pour le fait d'un
    expéditeur détourné.
    """
    texte = _normalize(site_text)
    if not texte.strip():
        return True
    ouverture = texte[:DEBUT_INTERSTITIEL]
    if not any(motif in ouverture for motif in _LIENS_D_EVITEMENT):
        return False
    return not _PONCTUATION_DE_PHRASE.search(site_text)


def _normalize(value: str) -> str:
    stripped = unicodedata.normalize("NFKD", value.casefold())
    ascii_only = "".join(c for c in stripped if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", " ", ascii_only)


def activity_registers(subject: str, body: str) -> set[str]:
    """Les registres transactionnels dont un message se réclame."""
    text = _normalize(f"{subject}\n{body}")
    return {
        register
        for register, markers in _REGISTERS.items()
        if any(marker in text for marker in markers)
    }
