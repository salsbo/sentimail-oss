"""Fin de vie d'une retenue : relancer, puis trancher.

Un message retenu attend une décision humaine. Sans échéance, cette attente
devient un abandon silencieux : l'expéditeur croit avoir livré, le destinataire
a oublié l'avis, et le message reste indéfiniment dans un état intermédiaire.

Deux étapes bornées. Une relance rappelle le dossier et rouvre un canal de
réponse. Puis, à l'échéance, la retenue est tranchée : ce qu'un verdict a
qualifié de dangereux est classé sans livraison, le reste est livré avec sa
mise en garde. Chaque issue est tracée, aucune n'est silencieuse.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import asyncpg

from sentimail_v3.config import Settings
from sentimail_v3.conversation.digest import send_daily_digests
from sentimail_v3.execution.outbox import queue_response
from sentimail_v3.identity import instance_identity
from sentimail_v3.code.reference import nommer_dossier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-hold-lifecycle")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


async def _pending_holds(
    pool: asyncpg.Pool[Any], days: int, action: str, limit: int
) -> list[asyncpg.Record]:
    """Retenues sans nouvelle du destinataire depuis la durée demandée."""
    return await pool.fetch(
        """
        SELECT m.id::text AS message_id, m.subject, m.from_header, m.captured_at,
               dc.id AS case_id, c.id::text AS conversation_id,
               c.participant_email,
               (
                   SELECT vr.response->'verdict'->>'classification'
                   FROM verdict_runs vr
                   JOIN investigations i ON i.id=vr.investigation_id
                   WHERE i.message_id=m.id AND vr.status='complete'
                   ORDER BY vr.completed_at DESC LIMIT 1
               ) AS classification
        FROM messages m
        JOIN delivery_cases dc ON dc.message_id=m.id
        JOIN conversations c ON c.case_id=dc.id
        WHERE m.delivery_status='held'
          AND dc.state IN ('review_notice_pending','awaiting_reply')
          AND m.captured_at < now() - ($1 * interval '1 day')
          AND NOT EXISTS (
              -- Une réponse ancienne n'est pas une décision : un dossier laissé
              -- retenu après un échange doit être relancé, puis tranché, comme
              -- un dossier resté sans réponse.
              SELECT 1 FROM conversation_messages cm
              WHERE cm.conversation_id=c.id AND cm.direction='inbound'
                AND cm.created_at > now() - ($1 * interval '1 day')
          )
          AND NOT EXISTS (
              SELECT 1 FROM audit_log a
              WHERE a.action=$2 AND a.payload->>'message_id'=m.id::text
                AND a.created_at > now() - ($1 * interval '1 day')
          )
        ORDER BY m.captured_at
        LIMIT $3
        """,
        days,
        action,
        limit,
    )


async def remind_stale_holds(
    pool: asyncpg.Pool[Any], settings: Settings, limit: int = 20
) -> int:
    """Rappelle un dossier oublié et rouvre un canal de réponse."""
    rows = await _pending_holds(
        pool, settings.hold_reminder_after_days, "hold.reminder_sent", limit
    )
    identite = await instance_identity(pool, settings)
    for row in rows:
        days = settings.hold_reminder_after_days
        decision = settings.hold_decision_after_days
        body = "\n".join(
            [
                f"Dossier : {row['subject'] or '(sans objet)'}",
                f"Expéditeur : {row['from_header'] or '(inconnu)'}",
                "",
                (
                    f"Ce message attend ton avis depuis plus de {days} jours et "
                    "reste retenu ; il n’a jamais été livré."
                ),
                "",
                (
                    "Réponds A pour le livrer et autoriser cet expéditeur, B pour "
                    "le refuser et le retenir à l’avenir, ou C suivi de ton "
                    "explication."
                ),
                "",
                (
                    f"Sans réponse d’ici {decision} jours après sa réception, je "
                    "trancherai moi-même : un message qualifié de dangereux sera "
                    "classé sans être livré, les autres te seront livrés avec "
                    "leur mise en garde."
                ),
                "",
                "— MAIA, SentiMail V3",
            ]
        )
        async with pool.acquire() as connection, connection.transaction():
            await queue_response(
                connection,
                str(row["conversation_id"]),
                row["case_id"],
                str(row["participant_email"]),
                identite.assistant_sender,
                identite.action_address,
                f"[SentiMail] Toujours en attente : {row['subject'] or 'ton avis'}"[:200],
                body,
            )
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('assistant','hold.reminder_sent',$1::jsonb)",
                _json(
                    {
                        "message_id": row["message_id"],
                        "case_id": str(row["case_id"]),
                        "held_since": row["captured_at"],
                    }
                ),
            )
        _log("hold.reminder_sent", message_id=row["message_id"])
    return len(rows)


async def settle_expired_holds(
    pool: asyncpg.Pool[Any], settings: Settings, limit: int = 20
) -> int:
    """A l'échéance, un dossier sans réponse est abandonné, pas tranché.

    L'échéance livrait tout ce qui n'était pas qualifié de dangereux. Le
    silence valait donc accord : un faux CIC que personne n'avait réclamé
    finissait dans la boîte par le seul effet du temps. Or ne pas répondre à un
    message douteux est le comportement normal - c'est même le plus fréquent.

    Le silence ne décide plus rien, dans aucun sens. Le message n'est pas livré
    (il ne l'a jamais été), il n'est pas classé indésirable (personne ne l'a
    dit), rien n'en est appris, et il sort des mesures : il n'est ni une
    réussite ni un échec. Il reste consultable dans la console jusqu'à ce que
    la rétention l'efface.

    Aucun courrier n'accompagne l'abandon. Celui d'avant annonçait une décision
    qui n'existe plus, et écrire pour dire qu'on renonce à demander serait une
    demande de plus. Le récapitulatif suivant le mentionne en une ligne.
    """
    rows = await _pending_holds(
        pool, settings.hold_decision_after_days, "hold.ignored_without_reply", limit
    )
    for row in rows:
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                UPDATE delivery_cases
                SET state='ignored', original_delivery_allowed=false,
                    updated_at=now(), details=details || $2::jsonb
                WHERE id=$1
                """,
                row["case_id"],
                _json(
                    {
                        "closed_by": "ignored_no_human_reply",
                        "excluded_from_statistics": True,
                        "classification": row["classification"],
                    }
                ),
            )
            # La conversation se termine avec le dossier : la laisser en
            # attente ferait espérer une réponse qu'on ne demande plus.
            await connection.execute(
                "UPDATE conversations SET status='closed',updated_at=now() "
                "WHERE id=$1::uuid",
                row["conversation_id"],
            )
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('assistant','hold.ignored_without_reply',$1::jsonb)",
                _json(
                    {
                        "message_id": row["message_id"],
                        "case_id": str(row["case_id"]),
                        "classification": row["classification"],
                        "held_since": row["captured_at"],
                        "reason": "no_human_reply_is_not_a_signal",
                    }
                ),
            )
        _log("hold.ignored_without_reply", message_id=row["message_id"])
    return len(rows)


async def run_hold_lifecycle(pool: asyncpg.Pool[Any], settings: Settings) -> int:
    if not settings.hold_lifecycle_enabled:
        return 0
    settled = await settle_expired_holds(pool, settings)
    # Le récapitulatif quotidien tient lieu de relance : rappeler en plus
    # chaque dossier séparément ferait deux courriers pour la même chose.
    reminded = (
        await send_daily_digests(pool, settings)
        if settings.digest_enabled
        else await remind_stale_holds(pool, settings)
    )
    return settled + reminded
