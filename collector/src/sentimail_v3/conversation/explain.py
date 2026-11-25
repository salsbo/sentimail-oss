"""Le dossier complet d'un message, pour qui veut la preuve et pas le résumé.

L'avis envoyé au destinataire dit ce qui se passe en français courant. Cette
commande sert l'autre besoin, celui de l'administrateur : voir chaque indice
avec sa force, son article, sa provenance et le détail factuel qui le fonde.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.conversation.conversation import clue_illustration


async def dossier(pool: asyncpg.Pool[Any], selector: str) -> str:
    escaped_selector = (
        selector.casefold()
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    message = await pool.fetchrow(
        """
        SELECT m.id::text AS id, m.subject, m.from_header, m.envelope_from,
               m.captured_at, m.delivery_status, m.raw_eml_encryption,
               i.id AS investigation_id, i.status AS investigation_status,
               i.favorable_points, i.adverse_points
        FROM messages m
        LEFT JOIN investigations i ON i.message_id=m.id
        WHERE m.id::text LIKE $1 || '%' ESCAPE '\\'
        ORDER BY i.started_at DESC NULLS LAST
        LIMIT 1
        """,
        escaped_selector,
    )
    if message is None:
        return f"Aucun message ne correspond à « {selector} »."
    lines = [
        f"Message   : {message['id']}",
        f"Objet     : {message['subject'] or '(sans objet)'}",
        f"De        : {message['from_header'] or message['envelope_from']}",
        f"Reçu le   : {message['captured_at']:%Y-%m-%d %H:%M:%S} UTC",
        f"État      : {message['delivery_status']}",
        f"Stockage  : {message['raw_eml_encryption'] or 'clair (hérité)'}",
        (
            f"Enquête   : {message['investigation_status'] or 'absente'}"
            f" (+{message['favorable_points'] or 0}"
            f" / -{message['adverse_points'] or 0})"
        ),
        "",
    ]
    clues = await pool.fetch(
        """
        SELECT clue_code, article_code, direction, strength, confidence,
               statement, facts
        FROM clues WHERE investigation_id=$1
        ORDER BY CASE direction
            WHEN 'adverse' THEN 1 WHEN 'favorable' THEN 2 ELSE 3 END,
            strength DESC
        """,
        message["investigation_id"],
    )
    lines.append("INDICES")
    for row in clues:
        lines.append(
            f"  [{row['direction']:<9}] {row['strength']:>3}/100 "
            f"{row['clue_code']} ({row['article_code']}) — {row['statement']}"
        )
        detail = clue_illustration(row["clue_code"], row["facts"])
        if detail:
            lines.append(f"      {detail}")
    if not clues:
        lines.append("  (aucun indice enregistré)")

    verdict = await pool.fetchrow(
        """
        SELECT vr.status, vr.attempts, vr.model_name, vr.prompt_version,
               vr.error_type, vr.response
        FROM verdict_runs vr
        WHERE vr.investigation_id=$1
        ORDER BY vr.created_at DESC LIMIT 1
        """,
        message["investigation_id"],
    )
    lines.extend(["", "VERDICT FINAL"])
    if verdict is None:
        lines.append("  (aucun verdict)")
    else:
        response = verdict["response"] or {}
        if isinstance(response, str):
            import json

            response = json.loads(response)
        lines.extend(
            [
                (
                    f"  état          : {verdict['status']} (tentative "
                    f"{verdict['attempts']}, "
                    f"{verdict['error_type'] or 'sans erreur'})"
                ),
                f"  modèle        : {verdict['model_name']} / {verdict['prompt_version']}",
                f"  classification: {response.get('classification')}",
                f"  décision      : {response.get('delivery_decision')}",
                f"  confiance     : {response.get('confidence')}",
                f"  motivation    : {str(response.get('rationale') or '')[:1500]}",
            ]
        )
    return "\n".join(lines)


async def run(selector: str) -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        print(await dossier(pool, selector))
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.conversation.explain",
        description="Affiche le dossier probatoire complet d'un message.",
    )
    parser.add_argument("message", help="prefixe d'identifiant de message")
    arguments = parser.parse_args()
    asyncio.run(run(arguments.message))


if __name__ == "__main__":
    main()
