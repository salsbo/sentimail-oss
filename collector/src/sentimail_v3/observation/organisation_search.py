"""Aller demander dehors les domaines d'une organisation, une fois par nom.

L'appel est isolé, court et fail-soft, comme toutes les questions posées à
l'extérieur : une panne, un quota épuisé ou une réponse hors format ne produit
aucun indice, et surtout aucune accusation par défaut.

Ce qui sort d'ici est strictement le nom que le message affiche. Le
destinataire, l'objet, le corps et l'adresse de l'expéditeur ne quittent jamais
la machine - la comparaison avec le domaine émetteur se fait au retour.

Un nom déjà cherché ne repart pas : la table `organisation_lookups` sert de
mémoire, ce qui borne le trafic sortant à la découverte réelle.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import asyncpg
import httpx

from sentimail_v3.code.organisation_lookup import (
    MAX_RESULTS,
    official_apexes,
    search_query,
    searchable,
)
from sentimail_v3.config import Settings

_LOG = logging.getLogger("sentimail.organisation_search")
# Au-delà, l'inspection profonde attendrait une réponse extérieure plus
# longtemps qu'elle n'attend son propre modèle.
_TIMEOUT_SECONDS = 8.0
# Une réponse vieille de plus d'un mois a pu manquer un changement de domaine ;
# en deçà, la redemander ne rendrait que la même chose.
_FRESH_DAYS = 30


def _log(event: str, **fields: Any) -> None:
    _LOG.info(json.dumps({"event": event, **fields}, ensure_ascii=False))


async def _cached(pool: asyncpg.Pool[Any], organisation: str) -> list[str] | None:
    row = await pool.fetchrow(
        """
        SELECT apexes FROM organisation_lookups
        WHERE organisation = $1
          AND checked_at > now() - ($2 || ' days')::interval
        """,
        organisation.casefold(),
        str(_FRESH_DAYS),
    )
    return None if row is None else [str(value) for value in row["apexes"]]


async def _remember(
    pool: asyncpg.Pool[Any], organisation: str, apexes: list[str], source: str
) -> None:
    await pool.execute(
        """
        INSERT INTO organisation_lookups (organisation, apexes, source, checked_at)
        VALUES ($1, $2::text[], $3, now())
        ON CONFLICT (organisation) DO UPDATE
        SET apexes = EXCLUDED.apexes,
            source = EXCLUDED.source,
            checked_at = EXCLUDED.checked_at
        """,
        organisation.casefold(),
        apexes,
        source,
    )


async def _remembered_search(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    key: str,
    kind: str,
    query: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """La recherche, une fois par question, gardée le temps qu'elle vaut.

    Sur sept jours de courrier réel, 311 messages appellent la confrontation
    mais ne portent que 115 noms et 96 domaines : la mémoire divise par trois
    ce qui part dehors, et le même expéditeur n'est plus redemandé chaque matin.
    Les extraits sont gardés avec les domaines, parce que c'est eux que le
    modèle lit.
    """
    row = await pool.fetchrow(
        """
        SELECT results, apexes FROM search_lookups
        WHERE query_key = $1 AND checked_at > now() - ($2 || ' days')::interval
        """,
        key,
        str(_FRESH_DAYS),
    )
    if row is not None:
        gardes = row["results"]
        if isinstance(gardes, str):
            gardes = json.loads(gardes)
        return list(gardes or []), [str(value) for value in row["apexes"]]
    results = await _search(client, settings, query)
    if not results:
        # Une recherche muette ne se garde pas : la panne d'aujourd'hui ne doit
        # pas passer pour l'absence de réponse de tout le mois.
        return [], []
    apexes = official_apexes(results)
    await pool.execute(
        """
        INSERT INTO search_lookups (query_key, kind, results, apexes, checked_at)
        VALUES ($1, $2, $3::jsonb, $4::text[], now())
        ON CONFLICT (query_key) DO UPDATE
        SET results = EXCLUDED.results,
            apexes = EXCLUDED.apexes,
            checked_at = EXCLUDED.checked_at
        """,
        key,
        kind,
        json.dumps(results, ensure_ascii=False),
        apexes,
    )
    return results, apexes


async def _search(
    client: httpx.AsyncClient, settings: Settings, query: str
) -> list[dict[str, Any]]:
    """Ce qu'un moteur rend pour une question, ou rien.

    Rien ne distingue ici une panne d'une absence de résultat : les deux
    laissent le jugement sans matière, et c'est exactement ce qu'on veut dire
    au modèle - « la recherche n'a rien donné », jamais « la preuve manque
    donc c'est louche ».
    """
    if not settings.search_api_key:
        return []
    try:
        response = await client.post(
            settings.search_base_url.rstrip("/") + "/search",
            json={
                "api_key": settings.search_api_key,
                "query": query,
                "max_results": MAX_RESULTS,
                "search_depth": "basic",
            },
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - une recherche sans réponse n'accuse pas
        _log("organisation_search.error", error=type(exc).__name__)
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    return [item for item in results if isinstance(item, dict)]


async def about_name(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    display_name: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Ce que la recherche dit d'un nom affiché, et les domaines qu'elle lui prête.

    Les extraits nourrissent le jugement ; les domaines servent au garde-fou
    déterministe, qui referme la question quand l'expéditeur figure parmi eux.
    """
    nom = display_name.strip()
    if not nom or not searchable(nom):
        return [], []
    results, apexes = await _remembered_search(
        pool,
        client,
        settings,
        key="nom:" + nom.casefold(),
        kind="name",
        query=search_query(nom),
    )
    if apexes:
        await _remember(pool, nom, apexes, "search")
    _log("organisation_search.name", nom=nom, apexes=apexes, resultats=len(results))
    return results, apexes


async def about_domain(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    apex: str,
) -> list[dict[str, Any]]:
    """Ce que la recherche dit du domaine qui a réellement envoyé.

    C'est la moitié qui manquait : sans elle, le modèle comparait un nom à une
    chaîne de caractères, et ne pouvait dire d'une école de langue australienne
    qu'elle n'est pas un service de streaming.
    """
    domaine = apex.strip().casefold()
    if not domaine:
        return []
    results, _ = await _remembered_search(
        pool,
        client,
        settings,
        key="domaine:" + domaine,
        kind="domain",
        query=f"{domaine} quelle organisation site",
    )
    _log("organisation_search.domain", apex=domaine, resultats=len(results))
    return results


async def official_domains(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    organisation: str,
) -> list[str]:
    """Les domaines officiels de cette organisation, ou une liste vide.

    Vide ne veut pas dire « aucun » : cela veut dire « on ne sait pas ». Rien ne
    doit donc s'en déduire contre l'expéditeur.
    """
    nom = organisation.strip()
    if not nom or not searchable(nom):
        return []
    cache = await _cached(pool, nom)
    if cache is not None:
        return cache
    if not settings.search_api_key:
        return []
    try:
        response = await client.post(
            settings.search_base_url.rstrip("/") + "/search",
            json={
                "api_key": settings.search_api_key,
                "query": search_query(nom),
                "max_results": MAX_RESULTS,
                "search_depth": "basic",
            },
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - une recherche sans réponse n'accuse pas
        _log("organisation_search.error", error=type(exc).__name__)
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    apexes = official_apexes(
        [item for item in results if isinstance(item, dict)]
    )
    await _remember(pool, nom, apexes, "search")
    _log("organisation_search.done", organisation=nom, apexes=apexes)
    return apexes
