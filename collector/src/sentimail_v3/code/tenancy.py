"""Qui est protégé, et par quel domaine.

L'autorisation était une constante : une adresse, écrite dans cinq services.
Elle se lit désormais en base, ce qui permet de couvrir tous les destinataires
d'un domaine enrôlé et d'en enrôler plusieurs.

Deux notions distinctes, longtemps confondues : le **destinataire protégé**, dont
le courrier est analysé et qui répond à MAIA, et l'**exploitant** de l'instance,
qui reçoit les alertes techniques. Le premier se résout en base, le second reste
une configuration de déploiement.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Any

import asyncpg

# Une lecture par message suffirait, mais le cache évite d'interroger la base à
# chaque destinataire d'un envoi groupé. Court, pour qu'une activation prenne
# effet sans redémarrage.
_CACHE_SECONDS = 30.0
_cache: tuple[float, dict[str, str | None]] = (0.0, {})


def domain_of(address: object) -> str:
    value = parseaddr(str(address or ""))[1].casefold()
    return value.rsplit("@", 1)[-1] if "@" in value else ""


async def active_domains(pool: asyncpg.Pool[Any]) -> dict[str, str | None]:
    """Domaines actifs et leur contact, tels qu'ils sont en base."""
    global _cache
    cached_at, value = _cache
    now = time.monotonic()
    if value and now - cached_at < _CACHE_SECONDS:
        return value
    # La preuve de maîtrise est un prérequis, pas une formalité : sans elle, une
    # activation faite d'un clic ferait analyser le courrier d'un domaine qu'on
    # ne contrôle pas. Actif et vérifié, les deux.
    rows = await pool.fetch(
        """
        SELECT fqdn, admin_email FROM domains
        WHERE status='active' AND verified_at IS NOT NULL
        """
    )
    fresh = {str(row["fqdn"]).casefold(): row["admin_email"] for row in rows}
    _cache = (now, fresh)
    return fresh


def forget_cache() -> None:
    """Oublie l'état mémorisé : utile aux tests et après une activation."""
    global _cache
    _cache = (0.0, {})


async def is_protected(pool: asyncpg.Pool[Any], address: object) -> bool:
    domain = domain_of(address)
    return bool(domain) and domain in await active_domains(pool)


async def protected_recipient(
    pool: asyncpg.Pool[Any], recipients: list[str]
) -> str | None:
    """Le destinataire couvert d'un envoi, quand il y en a un.

    Un message peut viser plusieurs adresses ; la conversation appartient à
    celle que SentiMail protège. Sans domaine actif, aucun interlocuteur n'est
    désigné : c'est un refus, jamais un repli silencieux sur un inconnu.

    Le choix est déterministe et trié, pas dicté par l'ordre de l'enveloppe :
    sinon un expéditeur, en ordonnant ses destinataires, choisirait sur quel
    domaine imputer le coût du verdict et à qui l'avis serait adressé.
    """
    domains = await active_domains(pool)
    covered = sorted(
        address
        for value in recipients
        if (address := parseaddr(str(value or ""))[1].casefold())
        and address.rsplit("@", 1)[-1] in domains
    )
    return covered[0] if covered else None


async def domain_admin(pool: asyncpg.Pool[Any], address: object) -> str | None:
    """Contact du domaine d'une adresse protégée."""
    return (await active_domains(pool)).get(domain_of(address))


@dataclass(frozen=True)
class Quota:
    """Ce qu'un domaine peut dépenser en appels au modèle."""

    assistant_hourly: int
    assistant_daily: int
    verdict_hourly: int
    verdict_daily: int


async def quota_of(
    pool: asyncpg.Pool[Any], domain: str, defaults: Quota
) -> Quota:
    """Plafonds du domaine, ou ceux de l'instance quand il n'en a pas.

    Un domaine sans plafond propre n'est pas illimité : il hérite de celui de
    l'instance. Une valeur nulle en base signifie « comme tout le monde », pas
    « sans limite ».
    """
    if not domain:
        return defaults
    row = await pool.fetchrow(
        """
        SELECT assistant_hourly_limit, assistant_daily_limit,
               verdict_hourly_limit, verdict_daily_limit
        FROM domains WHERE lower(fqdn)=lower($1)
        """,
        domain,
    )
    if row is None:
        return defaults
    return Quota(
        assistant_hourly=int(
            row["assistant_hourly_limit"] or defaults.assistant_hourly
        ),
        assistant_daily=int(row["assistant_daily_limit"] or defaults.assistant_daily),
        verdict_hourly=int(row["verdict_hourly_limit"] or defaults.verdict_hourly),
        verdict_daily=int(row["verdict_daily_limit"] or defaults.verdict_daily),
    )
