"""Validation et normalisation des saisies.

Un domaine saisi à la main arrive avec des majuscules, des espaces, parfois un
point final ou une adresse complète. Il est écrit en base sous une seule forme
- minuscules, IDNA - parce que ``tenancy.active_domains`` compare le domaine du
destinataire, replié en casse, à ce qui est stocké : toute autre forme serait
un domaine enrôlé qui ne protège personne.
"""

from __future__ import annotations

import ipaddress
import uuid
from email.utils import parseaddr
from urllib.parse import urlparse

from .presets import PRESETS

# Longueur maximale d'un nom de domaine et d'une étiquette (RFC 1035).
MAX_FQDN_LENGTH = 253
MAX_LABEL_LENGTH = 63

_LABEL_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


class SaisieInvalide(ValueError):
    """Saisie refusée. Le message est destiné à l'écran, en français."""


def normalize_fqdn(raw: object) -> str:
    """Renvoie le domaine normalisé, ou lève ``SaisieInvalide``.

    Accepte l'unicode (``café.fr`` devient ``xn--caf-dma.fr``), tolère le point
    final et la casse, refuse tout ce qui n'est pas un nom de domaine : adresse
    e-mail, URL, espace interne, étiquette vide ou hors alphabet.
    """
    value = str(raw or "").strip()
    if not value:
        raise SaisieInvalide("Indiquez un domaine.")
    if any(character.isspace() for character in value):
        raise SaisieInvalide("Un domaine ne contient pas d'espace.")
    if "@" in value:
        raise SaisieInvalide("Indiquez un domaine, pas une adresse e-mail.")
    if "/" in value or ":" in value:
        raise SaisieInvalide("Indiquez un domaine, pas une adresse web.")
    value = value.removesuffix(".")
    if value.startswith("."):
        raise SaisieInvalide("Le domaine commence par un point.")
    if ".." in value:
        raise SaisieInvalide("Le domaine contient un point en trop.")

    labels = value.split(".")
    if len(labels) < 2:
        raise SaisieInvalide("Indiquez un domaine complet, par exemple exemple.fr.")

    encoded: list[str] = []
    for label in labels:
        encoded.append(_encode_label(label))

    fqdn = ".".join(encoded)
    if len(fqdn) > MAX_FQDN_LENGTH:
        raise SaisieInvalide("Ce domaine est trop long.")
    extension = encoded[-1]
    if len(extension) < 2 or extension.isdigit():
        raise SaisieInvalide("L'extension du domaine est invalide.")
    return fqdn


def _encode_label(label: str) -> str:
    if not label:
        raise SaisieInvalide("Le domaine contient une partie vide.")
    candidate = label.casefold()
    if not candidate.isascii():
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError as error:  # pragma: no cover - message dépend d'idna
            raise SaisieInvalide(
                "Ce domaine contient des caractères qui ne peuvent pas être convertis."
            ) from error
    if len(candidate) > MAX_LABEL_LENGTH:
        raise SaisieInvalide("Une partie du domaine est trop longue.")
    if set(candidate) - _LABEL_ALPHABET:
        raise SaisieInvalide(
            "Le domaine ne peut contenir que des lettres, des chiffres et des tirets."
        )
    if candidate.startswith("-") or candidate.endswith("-"):
        raise SaisieInvalide("Une partie du domaine commence ou finit par un tiret.")
    return candidate


def normalize_admin_email(raw: object) -> str | None:
    """Contact du domaine. Facultatif, mais vérifié quand il est renseigné."""
    value = str(raw or "").strip()
    if not value:
        return None
    if any(character.isspace() for character in value):
        raise SaisieInvalide("L'adresse de contact ne peut pas contenir d'espace.")
    if value.count("@") != 1:
        raise SaisieInvalide("L'adresse de contact doit contenir un seul @.")
    local, _, domain = value.partition("@")
    if not local:
        raise SaisieInvalide("L'adresse de contact est incomplète.")
    if len(local) > 64:
        raise SaisieInvalide("L'adresse de contact est trop longue.")
    return f"{local.casefold()}@{normalize_fqdn(domain)}"


def verification_record(fqdn: str) -> str:
    """Nom de l'enregistrement TXT qui prouve la maîtrise du domaine."""
    return f"_sentimail.{fqdn}"


def normalize_identifier(raw: object) -> str:
    """Identifiant de domaine reçu d'un formulaire : un UUID, rien d'autre."""
    value = str(raw or "").strip()
    if not value:
        raise SaisieInvalide("Aucun domaine sélectionné.")
    try:
        return str(uuid.UUID(value))
    except ValueError as error:
        raise SaisieInvalide("Domaine inconnu.") from error


def normalize_client_name(raw: object) -> str:
    """Nom d'organisation affiché dans la console, sans contenu de contrôle."""
    value = " ".join(str(raw or "").strip().split())
    if not value:
        raise SaisieInvalide("Indiquez un nom de client.")
    if len(value) > 120:
        raise SaisieInvalide("Ce nom de client est trop long.")
    if any(ord(character) < 32 for character in value):
        raise SaisieInvalide("Ce nom de client contient un caractère de contrôle.")
    return value


def clamp_limit(raw: object, *, default: int, maximum: int) -> int:
    """Nombre de lignes demandé, ramené dans une plage tenable."""
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


# Un plafond à zéro n'est pas un réglage, c'est une panne : plus aucun appel ne
# passerait et tout le courrier basculerait en attente d'avis.
MIN_QUOTA = 1
MAX_QUOTA = 100_000
_MODEL_ALPHABET = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789.:-_/"
)


def normalize_quota(raw: object) -> int | None:
    """Un plafond saisi, ou rien du tout.

    Un champ vide signifie « comme l'instance », jamais « sans limite » : c'est
    l'absence de valeur qui fait hériter du défaut, et elle se dit en laissant
    le champ vide.
    """
    value = str(raw or "").strip()
    if not value:
        return None
    if not value.isdigit():
        raise SaisieInvalide("Un plafond s'écrit en chiffres, ou reste vide.")
    number = int(value)
    if number < MIN_QUOTA:
        raise SaisieInvalide(
            "Un plafond à zéro bloquerait toute analyse : laissez le champ "
            "vide pour suivre l'instance."
        )
    if number > MAX_QUOTA:
        raise SaisieInvalide("Ce plafond est trop élevé pour être un plafond.")
    return number


def normalize_model_name(raw: object) -> str:
    """Nom d'un modèle local, tel qu'Ollama le désigne."""
    value = str(raw or "").strip().lower()
    if not value:
        raise SaisieInvalide("Indiquez le nom du modèle.")
    if len(value) > 100:
        raise SaisieInvalide("Ce nom de modèle est trop long.")
    if set(value) - _MODEL_ALPHABET:
        raise SaisieInvalide("Ce nom de modèle contient un caractère inattendu.")
    return value


def normalize_role(raw: object) -> str:
    value = str(raw or "").strip().lower()
    if value not in {"conversation", "verdict"}:
        raise SaisieInvalide("Rôle inconnu.")
    return value


def normalize_local_role(raw: object) -> str:
    """Les rôles qu'Ollama peut servir, dont l'analyse non contraignante."""
    value = str(raw or "").strip().lower()
    if value not in {"conversation", "analysis", "verdict"}:
        raise SaisieInvalide("Rôle local inconnu.")
    return value


def normalize_base_url(raw: object) -> str:
    """L'adresse où part le courrier vers le moteur : http(s) uniquement.

    Un fournisseur nommé n'existe plus dans la configuration : c'est cette URL
    qui dit où part le courrier, telle que ``llm_role_providers`` la retient.
    Elle exige un schéma http(s), un hôte non vide, aucun caractère blanc ou de
    contrôle, aucun identifiant embarqué et un port valide s'il est présent.
    """
    value = str(raw or "").strip()
    if not value:
        raise SaisieInvalide("Indiquez l'adresse du moteur.")
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ):
        raise SaisieInvalide(
            "Cette adresse ne peut pas contenir d'espace ni de caractère de contrôle."
        )
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise SaisieInvalide("Cette adresse doit commencer par http:// ou https://.")
    if parsed.username is not None or parsed.password is not None:
        raise SaisieInvalide("Cette adresse ne doit pas contenir d'identifiants.")
    if not parsed.hostname:
        raise SaisieInvalide("Cette adresse doit contenir un nom d'hôte valide.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise SaisieInvalide("Le port de cette adresse est invalide.") from exc
    if port is not None and not (1 <= port <= 65535):
        raise SaisieInvalide("Le port de cette adresse est invalide.")
    return value


def normalize_preset(raw: object) -> str:
    """Le préréglage choisi, une clé de ``presets.PRESETS``, ou un refus."""
    value = str(raw or "").strip().casefold()
    if value not in PRESETS:
        raise SaisieInvalide("Préréglage inconnu.")
    return value


# Le CGNAT (100.64.0.0/10, utilisé par Tailscale) n'est pas couvert par
# is_private partout : exclu explicitement, comme côté collector.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# En dessous, une plage IPv4 bannit des pans entiers d'internet : ce n'est
# plus un registre de sources, c'est une coupure.
_MIN_IPV4_PREFIX = 16


def normalize_hostile_network(raw: object) -> str:
    """Renvoie l'adresse ou la plage normalisée, ou lève ``SaisieInvalide``.

    Publique uniquement : bannir un réseau privé, le loopback ou le CGNAT
    reviendrait à bloquer sa propre infrastructure.
    """
    value = str(raw or "").strip()
    if not value:
        raise SaisieInvalide("Indiquez une adresse IP ou une plage CIDR.")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SaisieInvalide(
            "Indiquez une adresse IP (93.184.216.99) ou une plage (93.184.216.0/24)."
        ) from exc
    address = network.network_address
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or (address.version == 4 and address in _CGNAT)
    ):
        raise SaisieInvalide(
            "Cette plage recouvre l'infrastructure interne : refusée."
        )
    if network.version == 4 and network.prefixlen < _MIN_IPV4_PREFIX:
        raise SaisieInvalide("Plage trop large : /16 au plus.")
    return str(network)


# --- Identité de l'instance ---------------------------------------------------
#
# L'adresse d'action, ses alias, l'expéditeur MAIA et le destinataire de la
# sonde traversent toutes le même contrôle : un saut de ligne, où qu'il soit
# dans la saisie, est le vecteur d'une injection d'en-tête SMTP (un ``Bcc:``
# ajouté à la faveur d'un champ mal filtré), et il est refusé avant même que
# ``parseaddr`` ne voie la valeur.


def _refuse_le_saut_de_ligne(value: str, message: str) -> None:
    if "\n" in value or "\r" in value:
        raise SaisieInvalide(message)


def normalize_email_address(raw: object) -> str:
    """Une adresse électronique nue, sans nom affiché.

    Basée sur ``email.utils.parseaddr`` : un nom affiché saisi par erreur
    (un copier-coller depuis un client mail) est toléré, mais seule l'adresse
    est retenue - ce champ ne porte jamais de ``From`` complet.
    """
    value = str(raw or "")
    _refuse_le_saut_de_ligne(value, "Cette adresse ne peut pas contenir de saut de ligne.")
    value = value.strip()
    if not value:
        raise SaisieInvalide("Indiquez une adresse électronique.")
    _, addr_spec = parseaddr(value)
    if "@" not in addr_spec:
        raise SaisieInvalide("Indiquez une adresse électronique valide.")
    return addr_spec.strip().casefold()


def normalize_sender_address(raw: object) -> str:
    """L'expéditeur MAIA : une adresse, avec un nom affiché facultatif.

    Le format accepté est celui d'un en-tête ``From`` - ``Nom <adresse>`` ou
    une adresse nue - parce que c'est la valeur qui part telle quelle dans cet
    en-tête.
    """
    value = str(raw or "")
    _refuse_le_saut_de_ligne(
        value, "Cet expéditeur ne peut pas contenir de saut de ligne."
    )
    value = value.strip()
    if not value:
        raise SaisieInvalide("Indiquez l'expéditeur des avis.")
    display_name, addr_spec = parseaddr(value)
    if "@" not in addr_spec:
        raise SaisieInvalide("Indiquez une adresse électronique valide.")
    if display_name:
        return f"{display_name} <{addr_spec}>"
    return addr_spec


def normalize_address_list(raw: object) -> list[str]:
    """Des alias, séparés par des virgules - chacun une adresse nue.

    Une liste vide reste vide : l'adresse d'action n'a besoin d'aucun alias
    pour fonctionner.
    """
    value = str(raw or "")
    _refuse_le_saut_de_ligne(
        value, "Cette liste ne peut pas contenir de saut de ligne."
    )
    return [
        normalize_email_address(item) for item in value.split(",") if item.strip()
    ]
