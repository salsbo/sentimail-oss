from __future__ import annotations

import json
from typing import Any, Protocol

import asyncpg

from sentimail_v3.config import Settings
from sentimail_v3.execution.delivery import close_undeliverable_message, release_original

MAX_NOTICE_ATTEMPTS = 5
MISSING_NOTICE_GRACE_SECONDS = 60
STALLED_NOTICE_SECONDS = 600


class InvitationQueue(Protocol):
    async def queue_invitation(
        self, message_id: str, *, decision_mode: bool | None = None
    ) -> bool: ...


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


async def _audit(
    pool: asyncpg.Pool[Any], action: str, message_id: str, **details: object
) -> None:
    await pool.execute(
        """
        INSERT INTO audit_log(actor,action,payload)
        VALUES ('review-delivery-guard',$1,$2::jsonb)
        """,
        action,
        _json({"message_id": message_id, **details}),
    )


async def fail_open_held_message(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    message_id: str,
    *,
    reason: str,
    error: Exception | None = None,
) -> str:
    """Livre l'original quand MAIA ne peut garantir la demande de décision."""
    await pool.execute(
        """
        UPDATE delivery_cases SET details=details || $2::jsonb,updated_at=now()
        WHERE message_id=$1::uuid
        """,
        message_id,
        _json(
            {
                "review_guard": "fail_open",
                "review_guard_reason": reason,
                "review_guard_error": type(error).__name__ if error else None,
            }
        ),
    )
    await pool.execute(
        """
        UPDATE smtp_actions SET status='revoked'
        WHERE case_id=(SELECT id FROM delivery_cases WHERE message_id=$1::uuid)
          AND action='release_original' AND status='pending'
        """,
        message_id,
    )
    await _audit(
        pool,
        "review.fail_open_requested",
        message_id,
        reason=reason,
        error_type=type(error).__name__ if error else None,
    )
    try:
        result = await release_original(
            pool,
            settings,
            message_id,
            reason=reason,
        )
    except Exception as exc:  # noqa: BLE001 - SMTP deferred is retried
        await _audit(
            pool,
            "review.fail_open_deferred",
            message_id,
            reason=reason,
            error_type=type(exc).__name__,
        )
        return "delivery_deferred"
    await _audit(pool, "review.fail_open_completed", message_id, result=result)
    return result


async def hold_with_review_or_fail_open(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    invitations: InvitationQueue,
    message_id: str,
) -> str:
    """Ne confirme une retenue qu'après mise en file atomique de l'avis MAIA."""
    try:
        queued = await invitations.queue_invitation(message_id, decision_mode=True)
    except Exception as exc:  # noqa: BLE001 - notification failures must fail open
        return await fail_open_held_message(
            pool,
            settings,
            message_id,
            reason="review_notice_queue_failed_fail_open",
            error=exc,
        )
    if queued:
        await _audit(pool, "review.hold_protected", message_id)
        return "review_notice_queued"
    return await fail_open_held_message(
        pool,
        settings,
        message_id,
        reason="review_notice_not_queued_fail_open",
    )


async def reconcile_one_review_hold(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    invitations: InvitationQueue,
) -> bool:
    """Répare une ancienne retenue orpheline ou libère un avis définitivement bloqué."""
    missing = await pool.fetchval(
        """
        SELECT m.id::text
        FROM messages m
        JOIN delivery_cases dc ON dc.message_id=m.id
        WHERE m.delivery_status='held'
          AND dc.state IN ('review_notice_pending','awaiting_reply')
          AND dc.updated_at < now()-($1 * interval '1 second')
          AND NOT EXISTS (
              SELECT 1 FROM smtp_actions sa
              JOIN assistant_outbox ao ON ao.action_id=sa.id
              WHERE sa.case_id=dc.id AND sa.action='release_original'
          )
        ORDER BY dc.updated_at LIMIT 1
        """,
        MISSING_NOTICE_GRACE_SECONDS,
    )
    if missing is not None:
        await hold_with_review_or_fail_open(
            pool, settings, invitations, str(missing)
        )
        return True

    candidate = await pool.fetchrow(
        """
        SELECT ao.id,ao.status,ao.attempts,m.id::text AS message_id
        FROM messages m
        JOIN delivery_cases dc ON dc.message_id=m.id
        JOIN smtp_actions sa ON sa.case_id=dc.id AND sa.action='release_original'
        JOIN assistant_outbox ao ON ao.action_id=sa.id
        WHERE m.delivery_status='held'
          AND dc.state IN ('review_notice_pending','awaiting_reply')
          AND ao.status!='sent'
          AND (
              (ao.status='error' AND ao.attempts >= $1)
              OR (
                  ao.status IN ('pending','sending','error')
                  -- Depuis la dernière tentative, pas la création : un avis
                  -- re-pris à l'instant n'est pas un avis bloqué.
                  AND coalesce(ao.last_attempt_at, ao.created_at)
                        < now()-($2 * interval '1 second')
              )
          )
        ORDER BY ao.created_at LIMIT 1
        """,
        MAX_NOTICE_ATTEMPTS,
        STALLED_NOTICE_SECONDS,
    )
    if candidate is None:
        return False
    claimed = await pool.fetchval(
        """
        UPDATE assistant_outbox SET status='error',attempts=$4,
            last_error='abandoned by review guard: original delivered fail-open'
        WHERE id=$1 AND status=$2 AND attempts=$3
        RETURNING id::text
        """,
        candidate["id"],
        candidate["status"],
        candidate["attempts"],
        MAX_NOTICE_ATTEMPTS,
    )
    if claimed is None:
        return False
    await fail_open_held_message(
        pool,
        settings,
        str(candidate["message_id"]),
        reason="review_notice_stalled_fail_open",
    )
    return True


async def abandon_undeliverable_notice(
    pool: asyncpg.Pool[Any],
    action_id: str | None,
    *,
    error: str | None = None,
) -> str | None:
    """Conclut le dossier quand l'avis MAIA est définitivement refusé."""
    if action_id is None:
        return None
    message_id = await pool.fetchval(
        """
        SELECT m.id::text
        FROM smtp_actions sa
        JOIN delivery_cases dc ON dc.id=sa.case_id
        JOIN messages m ON m.id=dc.message_id
        WHERE sa.id=$1::uuid
        """,
        action_id,
    )
    if message_id is None:
        return None
    return await close_undeliverable_message(
        pool,
        str(message_id),
        reason="review_notice_recipient_rejected",
        error=error,
    )


async def fail_open_for_exhausted_outbox(
    pool: asyncpg.Pool[Any], settings: Settings, action_id: str | None
) -> str | None:
    if action_id is None:
        return None
    message_id = await pool.fetchval(
        """
        SELECT m.id::text
        FROM smtp_actions sa
        JOIN delivery_cases dc ON dc.id=sa.case_id
        JOIN messages m ON m.id=dc.message_id
        WHERE sa.id=$1::uuid AND sa.action='release_original'
          AND m.delivery_status='held'
        """,
        action_id,
    )
    if message_id is None:
        return None
    return await fail_open_held_message(
        pool,
        settings,
        str(message_id),
        reason="review_notice_delivery_exhausted_fail_open",
    )
