"""Qui répond au courrier, relu à chaud.

L'adresse d'action, ses alias, la signature de l'assistant et le destinataire
de la sonde vivaient dans l'environnement de déploiement, figés au démarrage.
Ils se posent désormais en base (`instance_identity`) pour changer sans
redémarrage - mais restent un singleton facultatif : tant qu'aucune ligne
n'est écrite, ou si la lecture échoue - base indisponible, table pas encore
migrée -, l'instance retombe sur son environnement. Fail-soft : une erreur
ici ne doit jamais empêcher l'analyse ou l'envoi du courrier.
"""

from __future__ import annotations

import time
from typing import Any, NamedTuple

import asyncpg

from .config import Settings


class Identity(NamedTuple):
    action_address: str
    action_aliases: tuple[str, ...]
    assistant_sender: str
    probe_recipient: str


def _from_settings(settings: Settings) -> Identity:
    return Identity(
        action_address=settings.action_address,
        action_aliases=tuple(settings.action_aliases),
        assistant_sender=settings.assistant_sender,
        probe_recipient=settings.probe_recipient,
    )


# Une lecture par message suffirait, mais le cache évite d'interroger la base
# à chaque courrier. Court, pour qu'une identité posée en admin prenne effet
# sans redémarrage.
_CACHE_SECONDS = 60.0
_cache: tuple[float, Identity | None] = (0.0, None)


async def instance_identity(pool: asyncpg.Pool[Any], settings: Settings) -> Identity:
    """Identité active : celle posée en base, sinon celle de l'environnement."""
    global _cache
    cached_at, value = _cache
    now = time.monotonic()
    if value is not None and now - cached_at < _CACHE_SECONDS:
        return value
    try:
        row = await pool.fetchrow(
            "SELECT action_address, action_aliases, assistant_sender, "
            "probe_recipient FROM instance_identity WHERE singleton = true"
        )
    except Exception:  # noqa: BLE001 - une base indisponible ne bloque pas le courrier
        row = None
    identity = (
        _from_settings(settings)
        if row is None
        else Identity(
            action_address=str(row["action_address"]),
            action_aliases=tuple(row["action_aliases"]),
            assistant_sender=str(row["assistant_sender"]),
            probe_recipient=str(row["probe_recipient"]),
        )
    )
    _cache = (now, identity)
    return identity


def reset_cache() -> None:
    """Oublie l'identité mémorisée : utile aux tests et après une écriture."""
    global _cache
    _cache = (0.0, None)
