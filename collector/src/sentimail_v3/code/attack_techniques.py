"""Le registre des techniques d'attaque : ce que le verdict a le droit de nommer.

Une étiquette dit ce qu'un message est ; une technique dit comment il s'y
prend, et c'est ce qui s'enseigne au destinataire. Le registre est une donnée,
versionnée avec le code : le modèle y choisit, il n'y écrit jamais. Un code
absent du registre est simplement ignoré - inventer une technique ne doit rien
produire, ni erreur exploitable, ni entrée nouvelle. Les références MITRE sont
dérivées d'ici, côté serveur : le modèle ne fabrique pas de « T15xx ».
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg

MAX_RECOGNIZED = 8


def _list(value: object) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return [str(item) for item in value] if isinstance(value, list) else []


async def registry(pool: asyncpg.Pool[Any]) -> dict[str, dict[str, object]]:
    """Le registre actif, indexé par code."""
    rows = await pool.fetch(
        """
        SELECT technique_code, name, category, description, indicator_clues,
               mitre_refs
        FROM attack_techniques WHERE enabled=true ORDER BY technique_code
        """
    )
    return {
        str(row["technique_code"]): {
            "technique_code": str(row["technique_code"]),
            "name": str(row["name"]),
            "category": str(row["category"]),
            "description": str(row["description"]),
            "indicator_clues": _list(row["indicator_clues"]),
            "mitre_refs": _list(row["mitre_refs"]),
        }
        for row in rows
    }


def dossier_view(techniques: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    """Ce que le verdict voit du registre : de quoi choisir, pas plus.

    La description pédagogique complète n'a rien à faire dans le prompt : elle
    est pour le destinataire, et elle gonflerait chaque appel.
    """
    return [
        {
            "technique_code": value["technique_code"],
            "name": value["name"],
            "category": value["category"],
            "indicator_clues": value["indicator_clues"],
            # Courtes et dérivées d'ici seulement : le modèle peut les voir,
            # il ne peut pas en fabriquer.
            "mitre_refs": value["mitre_refs"],
        }
        for value in techniques.values()
    ]


def recognized(
    raw: object, techniques: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    """Les techniques réellement nommables parmi ce que le modèle a désigné.

    Tout ce qui n'est pas au registre disparaît sans bruit : le validateur des
    indices, lui, rejette l'invention ; ici, une hallucination de technique ne
    doit pas coûter un verdict entier, seulement sa mention.
    """
    if not isinstance(raw, list):
        return []
    seen: list[dict[str, object]] = []
    for code in raw[:MAX_RECOGNIZED * 2]:
        entry = techniques.get(str(code))
        if entry is not None and entry not in seen:
            seen.append(entry)
        if len(seen) >= MAX_RECOGNIZED:
            break
    return seen


def summary(entries: list[dict[str, object]]) -> dict[str, object]:
    """La cartographie dérivée du registre, jamais du modèle."""
    return {
        "techniques": [str(entry["technique_code"]) for entry in entries],
        "categories": sorted(
            {str(entry.get("category") or "") for entry in entries} - {""}
        ),
        "mitre": sorted(
            {
                str(ref)
                for entry in entries
                for ref in (entry.get("mitre_refs") or [])  # type: ignore[union-attr]
            }
        ),
    }


async def record_observations(
    pool: asyncpg.Pool[Any], codes: list[str]
) -> None:
    """Tient le registre vivant : chaque reconnaissance compte et se date."""
    if not codes:
        return
    await pool.execute(
        """
        UPDATE attack_techniques
        SET observations=observations+1, last_seen_at=now(), updated_at=now()
        WHERE technique_code = ANY($1::text[])
        """,
        codes,
    )


async def pedagogy(
    pool: asyncpg.Pool[Any], codes: list[str]
) -> list[dict[str, str]]:
    """Nom et explication des techniques, pour l'avis envoyé au destinataire."""
    if not codes:
        return []
    rows = await pool.fetch(
        """
        SELECT technique_code, name, description, coalesce(advice,'') AS advice
        FROM attack_techniques
        WHERE technique_code = ANY($1::text[]) AND enabled=true
        ORDER BY technique_code
        """,
        codes[:MAX_RECOGNIZED],
    )
    return [
        {
            "name": str(row["name"]),
            "description": str(row["description"]),
            # Nommer une manœuvre sans dire quoi en faire laisse la
            # personne devant sa décision, là même où l'attaque la veut.
            "advice": str(row["advice"]),
        }
        for row in rows
    ]
