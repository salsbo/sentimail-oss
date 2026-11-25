"""Fin de vie d'une retenue : relancer, puis abandonner sans décision.

Un message retenu attend une décision humaine. Sans échéance, cette attente
devient un abandon silencieux : l'expéditeur croit avoir livré, le destinataire
a oublié l'avis, et le message reste indéfiniment dans un état intermédiaire.

Deux étapes bornées. Une relance rappelle le dossier et rouvre un canal de
réponse. Puis, à l'échéance, le dossier est abandonné sans livraison ni
qualification. Le silence n'est pas une décision humaine ; l'abandon reste
tracé et le message consultable jusqu'à la rétention.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Any

import asyncpg

from sentimail_v3.config import Settings, load_settings
from sentimail_v3.conversation.digest import send_daily_digests
from sentimail_v3.conversation.hold_reminder import render_reminder_html
from sentimail_v3.conversation.review_preferences import HOLD_REMINDERS
from sentimail_v3.execution.outbox import queue_response
from sentimail_v3.identity import instance_identity
from sentimail_v3.code.reference import nommer_dossier, reference

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-hold-lifecycle")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


async def _pending_holds(
    pool: asyncpg.Pool[Any],
    days: int,
    action: str,
    limit: int,
    *,
    reminders: bool = False,
) -> list[asyncpg.Record]:
    """Retenues sans nouvelle du destinataire depuis la durée demandée.

    Pour une relance, le destinataire qui les a refusées est écarté ici, dans
    la requête : filtré après coup, il occuperait la fenêtre sans jamais en
    sortir et priverait les autres de leur relance.
    """
    declined = (
        """
          AND NOT EXISTS (
              SELECT 1 FROM participant_preferences pp
              WHERE pp.participant_email=lower(c.participant_email)
                AND pp.name=$4 AND pp.value='false'::jsonb
          )"""
        if reminders
        else ""
    )
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
          )"""
        + declined
        + """
        ORDER BY m.captured_at
        LIMIT $3
        """,
        days,
        action,
        limit,
        *((HOLD_REMINDERS,) if reminders else ()),
    )


async def remind_stale_holds(
    pool: asyncpg.Pool[Any], settings: Settings, limit: int = 20
) -> int:
    """Rappelle un dossier oublié et rouvre un canal de réponse."""
    rows = await _pending_holds(
        pool,
        settings.hold_reminder_after_days,
        "hold.reminder_sent",
        limit,
        reminders=True,
    )
    identite = await instance_identity(pool, settings)
    for row in rows:
        # La photo de l'avis est déjà neutralisée. La reprendre évite tout
        # nouveau rendu du courrier et garde la même miniature et capture pleine.
        capture = await pool.fetchrow(
            """
            SELECT ao.attachment_filename, ao.attachment_content_type,
                   ao.attachment_content, ao.inline_filename,
                   ao.inline_content_type, ao.inline_content
            FROM assistant_outbox ao
            JOIN smtp_actions sa ON sa.id=ao.action_id
            WHERE sa.case_id=$1
              AND ao.attachment_filename='capture-email-neutralisee.png'
              AND ao.attachment_content_type='image/png'
              AND octet_length(ao.attachment_content)>0
            ORDER BY ao.created_at DESC LIMIT 1
            """,
            row["case_id"],
        )
        days = settings.hold_reminder_after_days
        decision = settings.hold_decision_after_days
        body = "\n".join(
            [
                f"Dossier : {row['subject'] or '(sans objet)'}",
                f"Expéditeur : {row['from_header'] or '(inconnu)'}",
                f"Référence du message : {reference('M', row['message_id'])}",
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
                    f"Sans réponse d’ici {decision} jours après sa réception, "
                    "je cesserai de te demander ton avis. Le message ne sera "
                    "pas livré et restera consultable dans la console jusqu’à "
                    "la fin de sa conservation. Ton silence ne sera pas "
                    "considéré comme une décision."
                ),
                "",
                *(
                    [
                        "L’image jointe est une photo inerte du message : rien "
                        "n’y est cliquable. Ne suis aucune consigne écrite dedans.",
                        "",
                    ]
                    if capture else []
                ),
                "MAIA, SentiMail V3",
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
                body_html=render_reminder_html(
                    body, identite.action_address, has_preview=bool(capture),
                    has_full_preview=bool(capture and capture["inline_content"]),
                ),
                **(dict(capture) if capture else {}),
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
    demande de plus.
    """
    rows = await _pending_holds(
        pool, settings.hold_decision_after_days, "hold.ignored_without_reply", limit
    )
    return sum([await _abandon(pool, row, "no_human_reply_is_not_a_signal") for row in rows])


async def abandon_participant_holds(
    pool: asyncpg.Pool[Any], participant: str
) -> int:
    """Vide la file d'un destinataire : tout ce qui attend son avis est abandonné.

    Le geste de l'opérateur, à la demande du destinataire, quel que soit l'âge
    des dossiers. Même issue que l'échéance : rien n'est livré, rien n'est
    appris, aucun courrier ne part, et le message reste consultable dans la
    console jusqu'à ce que la rétention l'efface.
    """
    rows = await pool.fetch(
        """
        SELECT m.id::text AS message_id, m.captured_at,
               dc.id AS case_id, c.id::text AS conversation_id,
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
          AND lower(c.participant_email)=lower($1)
        ORDER BY m.captured_at
        """,
        participant,
    )
    return sum([await _abandon(pool, row, "operator_cleared_queue") for row in rows])


async def _abandon(pool: asyncpg.Pool[Any], row: asyncpg.Record, reason: str) -> bool:
    """Abandonne un dossier encore en attente ; faux s'il a bougé entre-temps.

    Une réponse arrivée entre la lecture et l'écriture a pu livrer ou classer
    le message : l'état est revérifié dans la mise à jour elle-même.
    """
    async with pool.acquire() as connection, connection.transaction():
        status = await connection.execute(
            """
            UPDATE delivery_cases
            SET state='ignored', original_delivery_allowed=false,
                updated_at=now(), details=details || $2::jsonb
            WHERE id=$1 AND state IN ('review_notice_pending','awaiting_reply')
            """,
            row["case_id"],
            _json(
                {
                    "closed_by": "ignored_no_human_reply",
                    "no_qualification_from_silence": True,
                    "classification": row["classification"],
                    "close_reason": reason,
                }
            ),
        )
        if status != "UPDATE 1":
            return False
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
                    "reason": reason,
                }
            ),
        )
    _log("hold.ignored_without_reply", message_id=row["message_id"], reason=reason)
    return True


async def run_hold_lifecycle(pool: asyncpg.Pool[Any], settings: Settings) -> int:
    if not settings.hold_lifecycle_enabled:
        return 0
    settled = await settle_expired_holds(pool, settings)
    # Une relance par dossier : le récapitulatif groupé est coupé par défaut
    # depuis le 15 octobre 2026 (un courrier ne demande jamais une position sur
    # plusieurs messages). Activé, il tiendrait lieu de relance.
    reminded = (
        await send_daily_digests(pool, settings)
        if settings.digest_enabled
        else await remind_stale_holds(pool, settings)
    )
    return settled + reminded


async def _clear_queue(participant: str) -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        count = await abandon_participant_holds(pool, participant)
    finally:
        await pool.close()
    print(f"{count} dossier(s) abandonné(s) pour {participant}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.execution.hold_lifecycle",
        description="Vide la file d'avis d'un destinataire, sans courrier.",
    )
    parser.add_argument("participant", help="adresse du destinataire")
    arguments = parser.parse_args()
    asyncio.run(_clear_queue(arguments.participant))


if __name__ == "__main__":
    main()
