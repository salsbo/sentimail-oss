"""Ce qui protège une page sans compte utilisateur.

Deux règles, indépendantes du serveur qui les applique, donc testables seules :

1. Une modification n'arrive que par POST. Un lien visité, une page préchargée,
   une image chargée depuis un autre site ne changent jamais un état.
2. La requête doit venir de la console elle-même. Le navigateur envoie toujours
   ``Origin`` sur un POST inter-site ; une origine absente ou étrangère est un
   refus, pas un doute qu'on tranche en faveur de l'appelant.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from urllib.parse import urlsplit


class OrigineRefusee(Exception):
    """Requête refusée : elle ne vient pas de la console."""


def expected_origins(host_header: str | None, configured: tuple[str, ...]) -> set[str]:
    """Origines admises : celles configurées, sinon l'hôte de la requête."""
    if configured:
        return {origin.rstrip("/").casefold() for origin in configured if origin}
    host = (host_header or "").strip().casefold()
    if not host:
        return set()
    return {f"http://{host}", f"https://{host}"}


def _origin_of(value: str) -> str:
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.casefold()}://{parts.netloc.casefold()}"


def check_same_origin(
    headers: Mapping[str, str], configured: tuple[str, ...] = ()
) -> None:
    """Lève ``OrigineRefusee`` si la requête ne vient pas de la console."""
    lowered = {key.casefold(): value for key, value in headers.items()}
    admitted = expected_origins(lowered.get("host"), configured)
    if not admitted:
        raise OrigineRefusee("L'hôte de la requête est inconnu.")

    origin = lowered.get("origin", "").strip()
    if origin and origin.casefold() != "null":
        if _origin_of(origin) not in admitted:
            raise OrigineRefusee("Cette requête vient d'un autre site.")
        return

    referer = lowered.get("referer", "").strip()
    if referer:
        if _origin_of(referer) not in admitted:
            raise OrigineRefusee("Cette requête vient d'un autre site.")
        return

    raise OrigineRefusee("L'origine de la requête n'est pas vérifiable.")


def parse_form(content_type: str | None, body: bytes) -> dict[str, str]:
    """Lit un formulaire urlencodé, et rien d'autre.

    Refuser les autres types coupe la voie du formulaire inter-site en
    ``text/plain``, que le navigateur envoie sans requête préalable.
    """
    from urllib.parse import parse_qsl

    media_type = (content_type or "").split(";", 1)[0].strip().casefold()
    if media_type != "application/x-www-form-urlencoded":
        raise OrigineRefusee("Ce formulaire n'a pas été envoyé par la console.")
    return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))


def client_ip(
    peer: str | None,
    headers: Mapping[str, str],
    trusted_proxies: frozenset[str] = frozenset(),
) -> str:
    """Adresse de l'appelant, telle qu'elle sera inscrite dans l'audit.

    ``X-Forwarded-For`` n'est lu que si le pair immédiat est un relais déclaré
    de confiance : sinon n'importe qui choisirait la ligne d'audit qu'on lui
    attribue. Quand rien n'est déterminable, on l'écrit tel quel plutôt que de
    laisser la modification sans attribution.
    """
    peer_address = (peer or "").strip()
    if peer_address and peer_address in trusted_proxies:
        lowered = {key.casefold(): value for key, value in headers.items()}
        forwarded = lowered.get("x-forwarded-for", "")
        for candidate in forwarded.split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                break
    if not peer_address:
        return "inconnue"
    try:
        return str(ipaddress.ip_address(peer_address))
    except ValueError:
        return "inconnue"
