"""Stabilité observée : combien d'épisodes dégradés, combien de temps, pourquoi.

Une alerte répond à « que se passe-t-il maintenant ». Cette commande répond à
« est-ce que ça arrive souvent », qui est une question différente et à laquelle
un instantané ne peut pas répondre.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings


async def episodes(
    pool: asyncpg.Pool[Any], days: int
) -> list[dict[str, object]]:
    """Épisodes non nominaux, avec leur durée et leurs causes."""
    rows = await pool.fetch(
        """
        SELECT status, previous_status, reasons, observed_at,
               lead(observed_at) OVER (ORDER BY observed_at) AS ended_at
        FROM operational_events
        WHERE component='sentimail-v3'
          AND observed_at > now() - ($1 * interval '1 day')
        ORDER BY observed_at
        """,
        days,
    )
    return [
        {
            "status": str(row["status"]),
            "started_at": row["observed_at"],
            "ended_at": row["ended_at"],
            "reasons": list(row["reasons"] or []),
        }
        for row in rows
        if str(row["status"]) != "ok"
    ]


def summarize(found: list[dict[str, object]], days: int) -> str:
    if not found:
        return f"Aucun épisode dégradé sur les {days} derniers jours."
    causes: dict[str, int] = {}
    total_seconds = 0.0
    open_episodes = 0
    for episode in found:
        for reason in episode["reasons"] or ["(sans cause enregistrée)"]:
            causes[str(reason)] = causes.get(str(reason), 0) + 1
        ended = episode["ended_at"]
        if ended is None:
            open_episodes += 1
            continue
        total_seconds += (ended - episode["started_at"]).total_seconds()
    lines = [
        f"{len(found)} épisode(s) non nominaux sur {days} jour(s).",
        f"Temps cumulé hors état nominal : {round(total_seconds / 60)} minute(s)"
        + (f", plus {open_episodes} épisode(s) en cours." if open_episodes else "."),
        "",
        "Causes les plus fréquentes :",
    ]
    lines.extend(
        f"- {reason} : {count}"
        for reason, count in sorted(causes.items(), key=lambda item: -item[1])[:10]
    )
    lines.extend(["", "Derniers épisodes :"])
    for episode in found[-10:]:
        ended = episode["ended_at"]
        duration = (
            f"{round((ended - episode['started_at']).total_seconds() / 60)} min"
            if ended is not None
            else "en cours"
        )
        lines.append(
            f"- {episode['started_at']:%Y-%m-%d %H:%M} | {episode['status']} | "
            f"{duration} | {', '.join(str(value) for value in episode['reasons'])}"
        )
    return "\n".join(lines)


async def run(days: int) -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        print(summarize(await episodes(pool, days), days))
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.uptime",
        description="Resume les episodes degrades observes par le superviseur.",
    )
    parser.add_argument(
        "--days", type=int, default=7, help="fenetre d'observation (defaut : 7)"
    )
    arguments = parser.parse_args()
    asyncio.run(run(max(1, arguments.days)))


if __name__ == "__main__":
    main()
