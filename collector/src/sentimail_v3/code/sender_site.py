"""Ce que le site d'un expéditeur dit de son métier, comparé à son message.

Un fabricant de cuisines n'envoie pas d'avis de colis, et un installateur
réseau non plus. Les deux l'ont pourtant fait le 16 août, depuis leurs vrais
domaines et avec une authentification parfaite : leurs serveurs étaient
compromis. Aucun indice technique ne pouvait les trahir - tout était en règle.
Ce qui les trahissait tenait en une phrase de leur page d'accueil.

La comparaison porte sur des registres d'activité, pas sur des mots-clés isolés
ni sur des marques : « ce message invoque la livraison, or rien de ce que cette
organisation publie d'elle-même n'a de rapport avec la livraison ». Un
transporteur qui parle de colis ne déclenche rien, et un site illisible non
plus - l'absence d'information n'accuse personne.

Un second usage a existé ici : repérer une page qui se réclame d'une marque
sans appartenir à ses domaines. Il exigeait une table de marques écrite à la
main, supprimée le 27 août - une liste ne connaît que ce qu'on y a mis, et se
trompe sur ce qu'on y a mal mis. La question se pose désormais sur le nom
affiché du message, confronté à ce qu'une recherche rend du nom et du domaine.
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
# Le métier d'une organisation, tel qu'elle l'annonce en tête de son site, et
# les registres transactionnels que ce métier rend plausibles.
#
# La liste est le seul moyen honnête de conclure : affirmer « ce n'est pas son
# métier » suppose d'avoir reconnu son métier. Sans cela, le silence d'un site
# passait pour une contradiction, et un code de sécurité de mutuelle s'est
# retrouvé retenu - une mutuelle n'exerce ni la livraison ni l'hébergement, et
# n'avait donc aucun registre reconnu.
_SECTORS: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {
    "transport": (
        ("transport", "logistique", "logistics", "messagerie express", "fret",
         "colis", "livraison", "courier", "spedizioni", "corriere", "shipping"),
        frozenset({"livraison", "paiement"}),
    ),
    "commerce": (
        ("boutique", "e-commerce", "vente en ligne", "shop", "store",
         "magasin", "achat", "commande en ligne", "negozio"),
        frozenset({"livraison", "paiement"}),
    ),
    "finance": (
        ("banque", "bancaire", "assurance", "mutuelle", "prevoyance",
         "credit", "epargne", "placement", "courtier", "bank", "insurance",
         "assicurazione", "finance", "comptabilite", "expert-comptable"),
        frozenset({"paiement"}),
    ),
    "numerique": (
        ("hebergement", "cloud", "saas", "logiciel", "software", "hosting",
         "informatique", "ict", "networking", "cablaggio", "reseau",
         "telecom", "operateur"),
        frozenset({"paiement"}),
    ),
    "ameublement": (
        ("ameublement", "arredamenti", "arredo", "mobilier", "cuisine",
         "cucina", "meuble", "decoration", "furniture"),
        frozenset({"livraison", "paiement"}),
    ),
    "restauration": (
        ("restaurant", "traiteur", "brasserie", "pizzeria", "ristorante"),
        frozenset({"livraison", "paiement"}),
    ),
    "sante": (
        ("medecin", "cabinet medical", "clinique", "pharmacie", "sante",
         "hopital", "laboratoire d analyses", "dentiste"),
        frozenset({"paiement"}),
    ),
    "immobilier": (
        ("immobilier", "agence immobiliere", "location", "syndic",
         "immobiliare", "real estate"),
        frozenset({"paiement"}),
    ),
    "industrie": (
        ("industrie", "usine", "fabrication", "manufacture", "atelier",
         "construction", "batiment", "artisan"),
        frozenset({"livraison", "paiement"}),
    ),
}
MIN_SITE_CHARS = 80
# Une organisation annonce son métier en haut de sa page d'accueil : titre,
# accroche, menu. Plus bas viennent les mentions ordinaires du commerce - les
# conditions de livraison, les moyens de paiement - que presque tout site
# comporte. Les lire comme une activité ferait de chaque commerçant un
# transporteur, et la comparaison ne dirait plus rien.
SITE_HEADLINE_CHARS = 400


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


def site_sectors(site_text: str) -> set[str]:
    """Les métiers qu'un site annonce en tête de sa page d'accueil."""
    text = _normalize(site_text[:SITE_HEADLINE_CHARS])
    return {
        sector
        for sector, (markers, _) in _SECTORS.items()
        if any(marker in text for marker in markers)
    }


def site_registers(site_text: str) -> set[str]:
    """Les registres transactionnels que le métier du site rend plausibles."""
    plausibles: set[str] = set()
    for sector in site_sectors(site_text):
        plausibles |= _SECTORS[sector][1]
    return plausibles


def site_contradicts_message(site_text: str, registers: set[str]) -> bool:
    """Vrai quand le message invoque une activité que l'expéditeur n'exerce pas.

    Sans registre invoqué, il n'y a rien à contredire. Sans contenu lisible sur
    le site, on ne sait pas - et ne pas savoir n'est pas une charge.
    """
    if not registers or len(site_text.strip()) < MIN_SITE_CHARS:
        return False
    if not site_sectors(site_text):
        # Aucun métier reconnu : ne pas savoir n'est pas constater une
        # différence. C'est le principe déjà tenu pour un titulaire RDAP
        # masqué, et son oubli ici a retenu un code de sécurité légitime.
        return False
    return not (registers & site_registers(site_text))


# Presque tout site renvoie vers ses réseaux sociaux : « Suivez-nous sur
# Instagram ». Y lire une usurpation de marque a fait retenir un code de
# sécurité de mutuelle. Ces noms ne peuvent donc pas fonder ce constat.
