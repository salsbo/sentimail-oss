"""Qui a réellement envoyé un message, et que retenir quand on le bannit.

Le nom affiché et l'adresse From sont écrits par l'expéditeur : un faux
« CIC » <info@cic.fr> envoyé depuis truc.fr porte les deux. Bannir ce qu'il
affiche retiendrait le vrai CIC et laisserait passer le prochain envoi de
truc.fr. Seule l'authentification dit qui écrit :

- DMARC aligné : l'adresse From est réelle ;
- signature DKIM valide : le domaine signataire a approuvé le message ;
- SPF valide : l'adresse d'enveloppe est réelle.

Une messagerie publique (gmail.com) ou une plateforme d'envoi mutualisée
(sendgrid.net) n'est l'identité de personne : on y retient l'adresse exacte, ou
rien si l'adresse n'est pas stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from typing import Any

import tldextract

from sentimail_v3.code.organisation import PUBLIC_MAILBOXES
from sentimail_v3.code.shared_esp import shared_esp_provider

# Domaines dont chaque sous-domaine est un client distinct : l'apex réunirait
# des inconnus, le domaine complet désigne le locataire.
SHARED_TENANT_APEXES = frozenset(
    {"onmicrosoft.com", "gappssmtp.com", "googlegroups.com"}
)

_extract = tldextract.TLDExtract(suffix_list_urls=())


def _apex(domain: str) -> str:
    value = _extract(domain.casefold().rstrip("."))
    return ".".join(part for part in (value.domain, value.suffix) if part)


def _address(value: object) -> str:
    address = parseaddr(str(value or ""))[1].strip().casefold()
    return address if address.count("@") == 1 and "." in address else ""


@dataclass(frozen=True)
class ProvenIdentity:
    """Ce que l'authentification prouve d'un message."""

    addresses: tuple[str, ...]
    domains: tuple[str, ...]
    block_target: tuple[str, str] | None

    @property
    def proven(self) -> bool:
        return bool(self.addresses or self.domains)


def proven_identity(
    from_header: object,
    envelope_from: object,
    *,
    dmarc_pass: bool,
    spf_pass: bool,
    dkim_domain: object = None,
) -> ProvenIdentity:
    """Les identités prouvées, et la cible d'un bannissement (scope, valeur)."""
    from_address = _address(from_header) if dmarc_pass else ""
    envelope = _address(envelope_from) if spf_pass else ""
    signer = str(dkim_domain or "").strip().casefold().rstrip(".")
    if "." not in signer:
        signer = ""
    candidates: list[tuple[str, str]] = []
    if from_address:
        candidates.append(("address", from_address))
    if signer:
        candidates.append(("domain", signer))
    if envelope:
        candidates.append(("address", envelope))
    target: tuple[str, str] | None = None
    for kind, value in candidates:
        domain = value.rsplit("@", 1)[-1]
        apex = _apex(domain)
        if not apex or shared_esp_provider(apex):
            continue
        if apex in PUBLIC_MAILBOXES:
            if kind == "address":
                target = ("sender", value)
                break
            continue
        target = ("domain", domain if apex in SHARED_TENANT_APEXES else apex)
        break
    addresses = tuple(dict.fromkeys(v for k, v in candidates if k == "address"))
    domains = tuple(
        dict.fromkeys(
            v.rsplit("@", 1)[-1] if k == "address" else v for k, v in candidates
        )
    )
    return ProvenIdentity(addresses, domains, target)


async def read_proven_identity(
    connection: Any, message_id: str
) -> ProvenIdentity | None:
    """Relit l'authentification figée à la capture ; None si message inconnu."""
    row = await connection.fetchrow(
        """
        SELECT m.from_header, m.envelope_from,
               coalesce(bool_or(c.clue_code='AUTH_DMARC_PASS'),false) AS dmarc,
               coalesce(bool_or(c.clue_code='AUTH_SPF_PASS'),false) AS spf,
               max(c.facts->>'signing_domain') FILTER (
                   WHERE c.clue_code IN ('AUTH_DKIM_PASS','AUTH_DKIM_UNALIGNED')
               ) AS dkim
        FROM messages m
        LEFT JOIN investigations i ON i.message_id=m.id
        LEFT JOIN clues c ON c.investigation_id=i.id AND c.clue_code LIKE 'AUTH\\_%'
        WHERE m.id=$1::uuid
        GROUP BY m.id
        """,
        message_id,
    )
    if row is None:
        return None
    return proven_identity(
        row["from_header"],
        row["envelope_from"],
        dmarc_pass=bool(row["dmarc"]),
        spf_pass=bool(row["spf"]),
        dkim_domain=row["dkim"],
    )
