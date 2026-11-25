"""Aller demander dehors les domaines d'une organisation, une fois par nom.

L'appel est isolé, court et fail-soft, comme toutes les questions posées à
l'extérieur : une panne, un quota épuisé ou une réponse hors format ne produit
aucun indice, et surtout aucune accusation par défaut.

Mais une panne se dit. Du 15 au 17 septembre 2026, le moteur a refusé la clé
de production (401) et chaque question a rendu une liste vide, que rien ne
distinguait d'une absence de réponse : « Amazon » n'avait plus de domaine
officiel, et des expéditeurs connus se sont vus écrire « personne ne répond
publiquement de ce domaine ». Le moteur lève donc `SearchUnavailable` quand
il n'a pas pu répondre ; une liste vide veut dire qu'il a répondu qu'il ne
savait rien.

Ce qui sort d'ici est strictement le nom sous lequel le message se présente :
le nom affiché, ou depuis le 16 septembre 2026 une marque écrite dans le corps
et vérifiée telle quelle par l'enquêteur `sender_relation`. Le destinataire,
l'objet, le reste du corps et l'adresse de l'expéditeur ne quittent jamais la
machine - la comparaison avec le domaine émetteur se fait au retour.

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
    officials_in_memory,
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
# Ces statuts disent que le fournisseur refuse la clé ou le compte (clé
# invalide, interdite, quota du plan atteint) : rien ne repartira tant que
# l'exploitant n'a pas agi. Tout le reste est passager.
_REJECTED_STATUSES = frozenset({401, 403, 432})


class SearchUnavailable(Exception):
    """Le moteur n'a pas répondu à la question : une panne, pas un vide.

    ``kind`` dit laquelle : ``rejected`` quand le fournisseur refuse la clé ou
    le compte, ``error`` pour un délai, une coupure réseau ou une erreur de
    son côté. Le superviseur sonne au premier refus ; il attend trois erreurs
    passagères dans l'heure.
    """

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def _log(event: str, **fields: Any) -> None:
    _LOG.info(json.dumps({"event": event, **fields}, ensure_ascii=False))


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
    """Ce qu'un moteur rend pour une question, ou rien, ou la panne.

    Une liste vide dit que le moteur a répondu qu'il ne savait rien : c'est
    ce qu'on veut dire au modèle - « la recherche n'a rien donné », jamais
    « la preuve manque donc c'est louche ». Une panne ne rend pas cette liste :
    elle lève `SearchUnavailable`, pour que le dossier écrive « non vérifié »
    et que le superviseur la compte. Sans clé configurée, rien ne part : ce
    cas-là est déjà écrit par l'enquêteur.
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
    except Exception as exc:  # noqa: BLE001 - un moteur injoignable n'accuse pas, il se note
        _log("organisation_search.error", kind="error", error=type(exc).__name__)
        raise SearchUnavailable("error", type(exc).__name__) from exc
    if response.status_code in _REJECTED_STATUSES:
        _log("organisation_search.error", kind="rejected", status=response.status_code)
        raise SearchUnavailable("rejected", f"HTTP {response.status_code}")
    if response.status_code >= 400:
        _log("organisation_search.error", kind="error", status=response.status_code)
        raise SearchUnavailable("error", f"HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        _log("organisation_search.error", kind="error", error="unparsed")
        raise SearchUnavailable("error", "unparsed") from exc
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
    results, _ = await _remembered_search(
        pool,
        client,
        settings,
        key="nom:" + nom.casefold(),
        kind="name",
        query=search_query(nom),
    )
    # Recalculés depuis les extraits, gardés ou frais : une liste mémorisée
    # avant le filtre par le nom resterait polluée sept jours.
    apexes = official_apexes(results, organisation=nom)
    if apexes:
        await _remember(pool, nom, apexes, "search")
    else:
        apexes = await _from_memory(pool, nom)
    _log("organisation_search.name", nom=nom, apexes=apexes, resultats=len(results))
    return results, apexes


async def _from_memory(pool: asyncpg.Pool[Any], nom: str) -> list[str]:
    """Ce que les recherches passées ont établi pour un nom plus complet.

    Une lecture manquée ne coûte que le secours : elle rend une liste vide,
    comme avant que la mémoire soit relue.
    """
    from sentimail_v3.code.identity_relation import _tokens
    from sentimail_v3.code.organisation_lookup import remembered_apexes

    mots = _tokens(nom)
    if len(mots) < 2:
        return []
    try:
        rows = await pool.fetch(
            """
            SELECT organisation, apexes FROM organisation_lookups
            WHERE organisation LIKE ALL($1::text[])
            ORDER BY checked_at DESC LIMIT 50
            """,
            [f"%{mot}%" for mot in mots],
        )
    except Exception as exc:  # noqa: BLE001 - la mémoire est un secours, pas une condition
        _log("organisation_search.memory_error", error=type(exc).__name__)
        return []
    apexes = remembered_apexes(
        nom, [(str(row["organisation"]), list(row["apexes"] or [])) for row in rows]
    )
    if apexes:
        _log("organisation_search.memory", nom=nom, apexes=apexes)
    return apexes


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


async def official_memory(pool: asyncpg.Pool[Any]) -> dict[str, str]:
    """Tous les domaines officiels que les recherches passées ont établis.

    Rien ne sort : la mémoire est relue, jamais complétée ici. Une lecture en
    panne remonte à l'enquêteur, que son registre inscrit en erreur sans
    indice : ne pas savoir n'accuse personne.
    """
    rows = await pool.fetch(
        "SELECT organisation, apexes FROM organisation_lookups ORDER BY organisation"
    )
    return officials_in_memory(
        [
            (str(row["organisation"]), [str(apex) for apex in row["apexes"] or []])
            for row in rows
        ]
    )
