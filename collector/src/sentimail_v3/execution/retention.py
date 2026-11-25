"""Fenêtre de rétention : le contenu s'efface, les directives restent.

Deux étages successifs et bornés :

1. dégonflage, après `RETENTION_REDACT_AFTER_DAYS` : l'EML brut, les corps,
   les captures et les en-têtes non probatoires sont effacés ; les décisions,
   indices, labels et directives sont conservés ;
2. suppression, après `RETENTION_DELETE_AFTER_DAYS` : le message et ses tables
   filles disparaissent. Les labels survivent grâce à leurs colonnes propres
   (`sender_normalized`, `participant_email`, `subject`) et à la clé étrangère
   `ON DELETE SET NULL`.

Un message encore en cours de décision n'est jamais touché : sans EML brut,
une libération demandée par l'utilisateur deviendrait impossible.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import asyncpg

from sentimail_v3.config import Settings, load_settings
from sentimail_v3.supervision.health import pulse, set_status
from sentimail_v3.code.reference import nommer_dossier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-retention")

OPEN_STATUSES = [
    "captured",
    "analyzing",
    "held",
    "deferred",
    "release_pending",
]
# Un abandon ferme la conversation sans livrer l'original : son état SMTP
# reste held. Il ne faut pas le conserver comme une retenue encore libérable.
RETENTION_ELIGIBLE_SQL = """(
    NOT (m.delivery_status = ANY($2::text[]))
    OR (m.delivery_status='held' AND EXISTS (
        SELECT 1 FROM delivery_cases dc
        WHERE dc.message_id=m.id AND dc.state='ignored'
    ))
)"""
MINIMUM_REDACT_DAYS = 7
TECHNICAL_AUDIT_ACTIONS = ["investigation.created", "verdict.proposed"]


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    level = logging.ERROR if event.endswith(".error") else logging.INFO
    logger.log(level, _json({"event": event, **fields}))


def validate_windows(settings: Settings) -> None:
    """Refuse une fenêtre trop courte ou incohérente avant toute écriture."""
    if settings.retention_redact_after_days < MINIMUM_REDACT_DAYS:
        raise ValueError(
            f"retention window must keep at least {MINIMUM_REDACT_DAYS} days of content"
        )
    if settings.retention_delete_after_days < settings.retention_redact_after_days:
        raise ValueError("delete window must not precede the redaction window")


def _rows(result: str) -> int:
    return int(result.rsplit(" ", 1)[-1]) if result else 0


async def _expired_message_ids(
    connection: asyncpg.Connection, days: int, batch: int, redacted: bool
) -> list[str]:
    clause = (
        "redacted_at IS NOT NULL" if redacted else "redacted_at IS NULL"
    )
    rows = await connection.fetch(
        f"""
        SELECT m.id,m.delivery_status FROM messages m
        WHERE m.captured_at < now() - ($1 * interval '1 day')
          AND {RETENTION_ELIGIBLE_SQL}
          AND {clause}
        ORDER BY captured_at
        LIMIT $3
        FOR UPDATE OF m SKIP LOCKED
        """,
        days,
        OPEN_STATUSES,
        batch,
    )
    held = [row["id"] for row in rows if row["delivery_status"] == "held"]
    locked_holds = set()
    if held:
        # La livraison réserve aussi le message puis le dossier. Si un autre
        # chemin tient déjà le dossier, attendre ici pourrait former un cycle
        # de verrous : ce dossier attendra simplement la prochaine passe.
        locked_holds = {
            row["message_id"] for row in await connection.fetch(
                """SELECT message_id FROM delivery_cases
                   WHERE message_id=ANY($1::uuid[]) AND state='ignored'
                   FOR UPDATE SKIP LOCKED""",
                held,
            )
        }
    return [
        row["id"] for row in rows
        if row["delivery_status"] != "held" or row["id"] in locked_holds
    ]


async def redact_expired(
    pool: asyncpg.Pool[Any], days: int, batch: int
) -> dict[str, int]:
    """Efface le contenu des messages sortis de la fenêtre de conservation."""
    counts = {"messages": 0, "mime_parts": 0, "headers": 0, "previews": 0}
    async with pool.acquire() as connection, connection.transaction():
        ids = await _expired_message_ids(connection, days, batch, redacted=False)
        if not ids:
            return counts
        counts["messages"] = _rows(
            await connection.execute(
                """
                UPDATE messages
                SET raw_eml=NULL, body_text=NULL, body_html=NULL,
                    facts=facts-'visible_content', redacted_at=now()
                WHERE id = ANY($1::uuid[])
                """,
                ids,
            )
        )
        await connection.execute("DELETE FROM observation_cache WHERE message_id=ANY($1::uuid[])", ids)
        counts["mime_parts"] = _rows(
            await connection.execute(
                """
                UPDATE mime_parts SET text_content=NULL
                WHERE message_id = ANY($1::uuid[]) AND text_content IS NOT NULL
                """,
                ids,
            )
        )
        # Les en-têtes de trace et de sécurité restent lisibles : ils portent la
        # preuve du trajet et de l'authentification, pas le contenu du message.
        counts["headers"] = _rows(
            await connection.execute(
                """
                UPDATE headers SET value_raw='', value_decoded=''
                WHERE message_id = ANY($1::uuid[])
                  AND is_trace=false AND is_security=false
                  AND value_length > 0 AND value_raw <> ''
                """,
                ids,
            )
        )
        counts["previews"] = _rows(
            await connection.execute(
                """
                UPDATE review_notices SET preview_content=NULL
                WHERE preview_content IS NOT NULL AND case_id IN (
                    SELECT id FROM delivery_cases WHERE message_id = ANY($1::uuid[])
                )
                """,
                ids,
            )
        )
    return counts


async def redact_expired_conversations(
    pool: asyncpg.Pool[Any], days: int
) -> dict[str, int]:
    """Efface les corps échangés avec MAIA en conservant la directive écrite."""
    async with pool.acquire() as connection, connection.transaction():
        conversation_rows = _rows(
            await connection.execute(
                """
                UPDATE conversation_messages SET body_text=NULL
                WHERE created_at < now() - ($1 * interval '1 day')
                  AND body_text IS NOT NULL
                """,
                days,
            )
        )
        outbox_rows = _rows(
            await connection.execute(
                """
                UPDATE assistant_outbox
                SET body_text='', body_html=NULL, attachment_content=NULL,
                    inline_content=NULL
                WHERE created_at < now() - ($1 * interval '1 day')
                  AND status='sent'
                  AND (body_text <> '' OR coalesce(body_html,'') <> ''
                       OR attachment_content IS NOT NULL OR inline_content IS NOT NULL)
                """,
                days,
            )
        )
        tokens = _rows(
            await connection.execute(
                """
                UPDATE smtp_actions SET token_hash=NULL
                WHERE token_hash IS NOT NULL
                  AND expires_at < now() - ($1 * interval '1 day')
                """,
                days,
            )
        )
    return {
        "conversation_messages": conversation_rows,
        "assistant_outbox": outbox_rows,
        "expired_tokens": tokens,
    }


async def delete_expired(
    pool: asyncpg.Pool[Any], days: int, batch: int
) -> dict[str, int]:
    """Supprime les messages hors fenêtre ; les règles apprises survivent."""
    counts = {
        "messages": 0,
        "llm_events": 0,
        "enrichments": 0,
        "operational_events": 0,
        "audit_rows": 0,
    }
    async with pool.acquire() as connection, connection.transaction():
        ids = await _expired_message_ids(connection, days, batch, redacted=True)
        if ids:
            counts["messages"] = _rows(
                await connection.execute(
                    "DELETE FROM messages WHERE id = ANY($1::uuid[])", ids
                )
            )
        await connection.execute("DELETE FROM observation_cache WHERE expires_at <= now()")
        await connection.execute(
            "DELETE FROM llm_attempt_events WHERE created_at < now()-($1*interval '1 day')", days
        )
        counts["llm_events"] = _rows(
            await connection.execute(
                """
                DELETE FROM llm_call_events
                WHERE created_at < now() - ($1 * interval '1 day')
                """,
                days,
            )
        )
        counts["enrichments"] = _rows(
            await connection.execute(
                """
                DELETE FROM enrichments
                WHERE observed_at < now() - ($1 * interval '1 day')
                  AND NOT EXISTS (
                      SELECT 1 FROM entities e WHERE e.enrichment_id = enrichments.id
                  )
                """,
                days,
            )
        )
        counts["operational_events"] = _rows(
            await connection.execute(
                """
                DELETE FROM operational_events
                WHERE observed_at < now() - ($1 * interval '1 day')
                """,
                days,
            )
        )
        # Seules les entrées techniques à fort volume sont purgées : les
        # directives, les changements de règles et les incidents restent tracés.
        counts["audit_rows"] = _rows(
            await connection.execute(
                """
                DELETE FROM audit_log
                WHERE created_at < now() - ($1 * interval '1 day')
                  AND action = ANY($2::text[])
                """,
                days,
                TECHNICAL_AUDIT_ACTIONS,
            )
        )
    return counts


async def run_once(pool: asyncpg.Pool[Any], settings: Settings) -> dict[str, object]:
    validate_windows(settings)
    redacted = await redact_expired(
        pool, settings.retention_redact_after_days, settings.retention_batch_size
    )
    conversations = await redact_expired_conversations(
        pool, settings.retention_redact_after_days
    )
    deleted = await delete_expired(
        pool, settings.retention_delete_after_days, settings.retention_batch_size
    )
    report = {
        "redact_after_days": settings.retention_redact_after_days,
        "delete_after_days": settings.retention_delete_after_days,
        "redacted": redacted,
        "conversations": conversations,
        "deleted": deleted,
    }
    changed = any(
        value
        for group in (redacted, conversations, deleted)
        for value in group.values()
    )
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute(
            """
            INSERT INTO operational_status (component, status, details, observed_at)
            VALUES ('retention','ok',$1::jsonb, now())
            ON CONFLICT (component) DO UPDATE SET
                status=EXCLUDED.status, details=EXCLUDED.details,
                observed_at=EXCLUDED.observed_at
            """,
            _json(report),
        )
        if changed:
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('retention','retention.pass_completed',$1::jsonb)",
                _json(report),
            )
    return report


async def main() -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    while True:
        pulse("retention")
        if not settings.retention_enabled:
            set_status("retention", "ok")
            await asyncio.sleep(settings.retention_interval_seconds)
            continue
        try:
            report = await run_once(pool, settings)
            set_status("retention", "ok")
            _log("retention.pass", **report)
        except Exception as exc:  # noqa: BLE001 - la boucle doit survivre
            set_status("retention", "error")
            _log("retention.error", error=type(exc).__name__, detail=str(exc)[:300])
        pulse("retention")
        await asyncio.sleep(settings.retention_interval_seconds)


if __name__ == "__main__":
    asyncio.run(main())
