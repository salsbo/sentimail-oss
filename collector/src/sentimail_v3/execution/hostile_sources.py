"""Les serveurs SMTP qui livrent du spam confirmé laissent leur adresse.

Réputation interne, construite sur nos seules observations : chaque
classement en indésirable et chaque qualification humaine de spam conservent
l'IP source dans hostile_smtp_sources - la rétention peut ensuite purger le
message, la trace de la source demeure. Rien ne sort vers un service tiers.
La liste est un cache consultable ; elle pourra plus tard nourrir un blocage
au niveau de Postfix, décision qui n'est pas prise ici.

Les adresses internes ne s'enregistrent jamais : le relais, la sonde e2e et
les réseaux privés passent par elles, et les inscrire ferait bloquer sa
propre infrastructure.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import asyncpg

# 100.64.0.0/10 (CGNAT, utilisé par Tailscale) n'est pas couvert par
# is_private sur toutes les versions de Python : il est exclu explicitement.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_recordable_ip(value: object) -> bool:
    """Vrai pour une adresse publique routable, jamais pour l'infrastructure."""
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        return False
    if address.version == 4 and address in _CGNAT:
        return False
    return True


_RECEIVED_IP = re.compile(r"\[([0-9a-fA-F:.]+)\]")
# « from HELO (ptr [ip]) » : le rDNS que Postfix a déjà résolu à la réception.
_RECEIVED_SOURCE = re.compile(r"\(([A-Za-z0-9._-]+)\s+\[([0-9a-fA-F:.]+)\]")
_NO_PTR = {"unknown", "localhost"}


def source_from_received(
    received_values: list[str],
) -> tuple[str, str | None] | None:
    """(adresse publique, rDNS déjà résolu) du hop d'entrée, ou None.

    Le pair SMTP du collector est le MX interne (adresse Docker) : la source
    réelle est celle que le MX frontal a écrite dans son Received, avec le
    PTR qu'il avait déjà résolu - aucune requête sortante n'est nécessaire.
    Les hops sont lus du plus récent au plus ancien ; la première adresse
    publique est le client qui a livré le message à notre porte.
    """
    for value in received_values[:10]:
        text = str(value)
        for match in _RECEIVED_SOURCE.finditer(text):
            ptr, candidate = match.group(1), match.group(2)
            if is_recordable_ip(candidate):
                rdns = None if ptr.casefold() in _NO_PTR else ptr
                return candidate, rdns
        for candidate in _RECEIVED_IP.findall(text):
            if is_recordable_ip(candidate):
                return candidate, None
    return None


async def record_hostile_source(
    pool: asyncpg.Pool[Any], message_id: str, reason: str
) -> bool:
    """Conserve l'IP source d'un message confirmé hostile. Fail-soft à l'appel."""
    ip = await pool.fetchval(
        "SELECT smtp_peer_ip::text FROM messages WHERE id=$1::uuid", message_id
    )
    rdns: str | None = None
    if not is_recordable_ip(ip):
        # Le pair direct est notre propre relais : remonter la chaîne
        # Received jusqu'à la première adresse publique - la vraie source,
        # avec le rDNS que le MX avait déjà résolu.
        received = await pool.fetch(
            """
            SELECT value_decoded FROM headers
            WHERE message_id=$1::uuid AND name_normalized='received'
            ORDER BY ordinal
            """,
            message_id,
        )
        found = source_from_received(
            [str(row["value_decoded"]) for row in received]
        )
        ip, rdns = found if found else (None, None)
    if not is_recordable_ip(ip):
        return False
    await pool.execute(
        """
        INSERT INTO hostile_smtp_sources (ip, last_reason, rdns)
        VALUES ($1::inet, $2, $3)
        ON CONFLICT (ip) DO UPDATE SET
            last_seen=now(),
            hits=hostile_smtp_sources.hits + 1,
            last_reason=$2,
            rdns=COALESCE(EXCLUDED.rdns, hostile_smtp_sources.rdns)
        """,
        str(ip).strip(),
        str(reason)[:120],
        rdns[:200] if rdns else None,
    )
    return True
