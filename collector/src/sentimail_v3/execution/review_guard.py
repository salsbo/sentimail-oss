"""Le gardien des retenues : un avis garanti, sinon un secours qui relit le jugement.

Une retenue n'a de sens que si le destinataire est averti. Quand l'avis MAIA
ne peut pas être garanti, le secours agit à sa place. Longtemps il livrait
l'original en clair, quel que soit le jugement : un message que le Code tenait
pour dangereux pouvait arriver en boîte de réception au premier incident de
mise en file. Le secours relit désormais le dernier jugement du dossier, sans
jamais le retoucher, et choisit une route.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Protocol

import asyncpg

from sentimail_v3.code.attack_techniques import pedagogy
from sentimail_v3.code.material_danger import has_material_danger
from sentimail_v3.code.plain_words import classification_reasons, identity_card
from sentimail_v3.code.reference import nommer_dossier
from sentimail_v3.config import Settings
from sentimail_v3.execution.delivery import close_undeliverable_message, release_original
from sentimail_v3.execution.delivery_state import HELD, move

logger = logging.getLogger("sentimail-v3-review-guard")

MAX_NOTICE_ATTEMPTS = 5
MISSING_NOTICE_GRACE_SECONDS = 60
STALLED_NOTICE_SECONDS = 600
# Une panne passagère de la base ou du bac à sable de rendu ne doit pas
# déclencher le secours au premier essai : trois mises en file, espacées
# d'une puis de trois secondes.
NOTICE_QUEUE_ATTEMPTS = 3
NOTICE_QUEUE_BACKOFF_SECONDS = (1.0, 3.0)
# Une retenue fermée dont l'avis n'est jamais parti est retentée par le
# réconciliateur trois fois au plus, à dix minutes d'intervalle.
FAIL_CLOSED_RETRIES = 3
FAIL_CLOSED_RETRY_SECONDS = 600

ROUTE_HOLD, ROUTE_JUNK, ROUTE_INBOX = "hold", "junk", "inbox"

# Le compteur de retentatives ne s'écrit que par jsonb_build_object avec un
# entier. La lecture le vérifie quand même : une valeur d'une autre forme
# ferait échouer toute la réconciliation à chaque passage.
_ATTEMPTS = (
    "CASE WHEN jsonb_typeof({d}->'review_guard_attempts')='number' "
    "THEN ({d}->>'review_guard_attempts')::numeric::int ELSE 0 END"
)


class InvitationQueue(Protocol):
    async def queue_invitation(
        self, message_id: str, *, decision_mode: bool | None = None
    ) -> bool: ...


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


async def _audit(
    pool: asyncpg.Pool[Any] | asyncpg.Connection[Any],
    action: str,
    message_id: str,
    **details: object,
) -> None:
    await pool.execute(
        """
        INSERT INTO audit_log(actor,action,payload)
        VALUES ('review-delivery-guard',$1,$2::jsonb)
        """,
        action,
        _json({"message_id": message_id, **details}),
    )


async def held_route(
    pool: asyncpg.Pool[Any], message_id: str
) -> tuple[str, str | None, bool]:
    """La route du secours, lue dans le dernier jugement du dossier.

    Dangereux, ou porteur d'une preuve matérielle de danger : retenu. Classé
    indésirable : Indésirables, sous enveloppe neutralisée. Le reste (douteux,
    indéterminé, jugement absent) : boîte de réception, comme avant.

    Pas de fail-soft ici : si la lecture échoue, l'exception remonte et rien
    n'est livré. Tout ce chemin dépend de la base, et deviner une route au
    moment de livrer serait le pire choix. La règle fail-soft du projet vise
    l'absence d'un signal d'enquête, pas l'acte de livrer. Sur le chemin
    d'erreur du verdict (trois échecs, aucun jugement), la classification est
    absente : seule une preuve matérielle déjà écrite peut alors retenir.
    """
    classification = await pool.fetchval(
        """
        SELECT details->'final_judgment'->>'classification'
        FROM delivery_cases WHERE message_id=$1::uuid
        """,
        message_id,
    )
    classification = str(classification) if classification is not None else None
    material = await has_material_danger(pool, message_id)
    if classification == "dangerous" or material:
        return ROUTE_HOLD, classification, material
    if classification == "spam":
        return ROUTE_JUNK, classification, material
    return ROUTE_INBOX, classification, material


async def _junk_annotation(
    pool: asyncpg.Pool[Any], message_id: str
) -> tuple[list[str], list[dict[str, str]], dict[str, object] | None]:
    """Les motifs, les techniques et la carte d'un indésirable, comme le juge les compose.

    Mêmes lectures et mêmes fonctions que la livraison d'un indésirable
    confirmé : l'avis du secours ne doit pas se distinguer de celui-là.
    """
    rows = [
        dict(row)
        for row in await pool.fetch(
            """
            SELECT DISTINCT c.clue_code, c.statement, c.facts
            FROM clues c JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction='adverse'
            ORDER BY c.clue_code
            """,
            message_id,
        )
    ]
    context = await pool.fetchrow(
        """
        SELECT v.rationale, vr.techniques
        FROM delivery_cases dc
        JOIN investigations i ON i.id=dc.investigation_id
        LEFT JOIN LATERAL (
            SELECT rationale FROM verdicts
            WHERE investigation_id=i.id ORDER BY created_at DESC LIMIT 1
        ) v ON true
        LEFT JOIN LATERAL (
            SELECT response->'verdict'->'attack'->'techniques' AS techniques
            FROM verdict_runs
            WHERE investigation_id=i.id AND status='complete'
            ORDER BY completed_at DESC LIMIT 1
        ) vr ON true
        WHERE dc.message_id=$1::uuid
        """,
        message_id,
    )
    rationale = str(context["rationale"] or "") if context is not None else ""
    techniques: object = context["techniques"] if context is not None else None
    # Sans codec déclaré, asyncpg rend le jsonb en texte.
    if isinstance(techniques, str):
        try:
            techniques = json.loads(techniques)
        except ValueError:
            techniques = None
    codes = [str(code) for code in techniques] if isinstance(techniques, list) else []
    return (
        classification_reasons(rows, rationale, telegraphique=True),
        await pedagogy(pool, codes),
        identity_card(rows),
    )


async def _hold_fail_closed(
    pool: asyncpg.Pool[Any],
    message_id: str,
    *,
    reason: str,
    error: Exception | None,
    classification: str | None,
    material: bool,
) -> str:
    """Garde retenu, sous alerte, un message que le Code tient pour dangereux.

    L'action de l'avis n'est pas révoquée : elle doit rester valable si l'avis
    repart. Les écritures sont séquentielles, comme le reste du module ; une
    écriture partielle laisse un message retenu que le superviseur compte déjà.
    """
    async with pool.acquire() as connection, connection.transaction():
        status = await connection.fetchval(
            """
            SELECT m.delivery_status
            FROM messages m
            JOIN delivery_cases dc ON dc.message_id=m.id
            WHERE m.id=$1::uuid FOR UPDATE OF m,dc
            """,
            message_id,
        )
        if status not in ("captured", "analyzing", "held"):
            # Un message déjà livré, clos ou en cours de livraison ne se reprend pas.
            return "already_resolved"
        # Quand la mise en file échoue, sa transaction - qui retenait le message
        # et posait l'attente de réponse - est annulée : le message est encore
        # « en analyse », le dossier en observation. Sans cette transition, le
        # superviseur dirait qu'aucun juge ne l'a encore pris.
        await move(connection, message_id, HELD)
        await connection.execute(
            f"""
            UPDATE delivery_cases SET
                state=CASE WHEN state='observation_only' THEN 'review_notice_pending'
                           ELSE state END,
                original_delivery_allowed=false, updated_at=now(),
                details=details || $2::jsonb || jsonb_build_object(
                    'review_guard_attempts', {_ATTEMPTS.format(d="details")} + 1
                )
            WHERE message_id=$1::uuid
            """,
            message_id,
            _json(
                {
                    "review_guard": "fail_closed",
                    "review_guard_reason": reason,
                    "review_guard_error": type(error).__name__ if error else None,
                }
            ),
        )
        await _audit(
            connection,
            "review.fail_closed",
            message_id,
            reason=reason,
            error_type=type(error).__name__ if error else None,
            classification=classification,
            material_danger=material,
        )
    _log(
        "review.fail_closed",
        message_id=message_id,
        reason=reason,
        error=type(error).__name__ if error else None,
        classification=classification,
        material_danger=material,
    )
    return "held_fail_closed"


async def fail_open_held_message(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    message_id: str,
    *,
    reason: str,
    error: Exception | None = None,
) -> str:
    """Le secours d'une retenue dont l'avis MAIA ne peut pas être garanti.

    La règle reste de ne pas perdre un message en silence : un douteux ou un
    indéterminé est livré en boîte de réception, un indésirable part dans
    Indésirables sous enveloppe neutralisée. Son exception : une défaillance
    ne livre jamais en clair ce que le Code a établi dangereux (classé
    dangereux, ou porteur d'une preuve matérielle). Ce message reste retenu,
    sous alerte. Le jugement n'est pas retouché : classification, décision et
    classement restent ceux que le juge a écrits ; c'est leur exécution qui
    attend de pouvoir se faire sans risque.

    Note d'exploitation : `reason` garde ses valeurs historiques en
    « _fail_open » (review_notice_queue_failed_fail_open, ..._not_queued_...,
    ..._stalled_..., ..._delivery_exhausted_...) même quand la route choisie
    est la retenue fermée. C'est le déclencheur qu'elles nomment, pas l'issue :
    l'audit garde ainsi sa continuité.
    """
    # La route se lit avant toute écriture : une retenue fermée ne doit ni
    # révoquer l'action de l'avis, ni s'auditer comme une livraison de secours.
    route, classification, material = await held_route(pool, message_id)
    if route == ROUTE_HOLD:
        return await _hold_fail_closed(
            pool,
            message_id,
            reason=reason,
            error=error,
            classification=classification,
            material=material,
        )
    reasons: list[str] = []
    lessons: list[dict[str, str]] = []
    identity: dict[str, object] | None = None
    if route == ROUTE_JUNK:
        try:
            reasons, lessons, identity = await _junk_annotation(pool, message_id)
        except Exception as exc:  # noqa: BLE001 - des motifs absents ne retiennent pas un indésirable
            _log(
                "review.junk_annotation_error",
                message_id=message_id,
                error=type(exc).__name__,
            )
    async with pool.acquire() as connection, connection.transaction():
        await connection.fetchval(
            "SELECT id FROM delivery_cases WHERE message_id=$1::uuid FOR UPDATE",
            message_id,
        )
        await connection.execute(
            """
            UPDATE delivery_cases SET details=details || $2::jsonb,updated_at=now()
            WHERE message_id=$1::uuid
            """,
            message_id,
            _json(
                {
                    # « fail_open » est la valeur historique : elle reste celle de
                    # la boîte de réception.
                    "review_guard": "fail_open_junk" if route == ROUTE_JUNK else "fail_open",
                    "review_guard_reason": reason,
                    "review_guard_error": type(error).__name__ if error else None,
                }
            ),
        )
        await connection.execute(
            """
            UPDATE smtp_actions SET status='revoked'
            WHERE case_id=(SELECT id FROM delivery_cases WHERE message_id=$1::uuid)
              AND action='release_original' AND status='pending'
            """,
            message_id,
        )
        await _audit(
            connection,
            "review.fail_open_requested",
            message_id,
            reason=reason,
            error_type=type(error).__name__ if error else None,
            route=route,
            classification=classification,
        )
        if route == ROUTE_JUNK:
            # Persisté avant l'envoi : une reprise différée doit repartir dans
            # Indésirables, et le jugement, lui, ne se retouche pas.
            await connection.execute(
                """
                UPDATE delivery_cases SET details=details || $2::jsonb
                WHERE message_id=$1::uuid
                """,
                message_id,
                _json(
                    {
                        "fail_open_classify_as": "spam",
                        "junk_reasons": reasons,
                        "junk_lessons": lessons,
                        "junk_identity": identity,
                    }
                ),
            )
    try:
        if route == ROUTE_JUNK:
            result = await release_original(
                pool,
                settings,
                message_id,
                reason=reason,
                classify_as="spam",
                classify_reasons=reasons,
                classify_lessons=lessons,
                classify_identity=identity,
            )
        else:
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
            route=route,
        )
        return "delivery_deferred"
    await _audit(
        pool, "review.fail_open_completed", message_id, result=result, route=route
    )
    return result


async def _queue_with_retry(
    invitations: InvitationQueue, message_id: str
) -> tuple[bool, Exception | None, int]:
    """Met l'avis en file, en retentant une panne passagère.

    Un refus (False) n'est pas retenté : il vient d'un fait qui ne change pas
    d'un essai à l'autre - dossier introuvable, aucun domaine protégé, avis
    existant épuisé. La mise en file est rejouable : ses écritures tiennent
    dans une transaction, seules les captures du bac à sable la précèdent.
    """
    error: Exception | None = None
    for attempt in range(1, NOTICE_QUEUE_ATTEMPTS + 1):
        if attempt > 1:
            await asyncio.sleep(NOTICE_QUEUE_BACKOFF_SECONDS[attempt - 2])
        try:
            queued = await invitations.queue_invitation(message_id, decision_mode=True)
            return bool(queued), None, attempt
        except Exception as exc:  # noqa: BLE001 - une panne passagère se retente
            error = exc
    return False, error, NOTICE_QUEUE_ATTEMPTS


async def hold_with_review_or_fail_open(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    invitations: InvitationQueue,
    message_id: str,
) -> str:
    """Ne confirme une retenue qu'après mise en file atomique de l'avis MAIA."""
    queued, error, attempts = await _queue_with_retry(invitations, message_id)
    if queued:
        await _audit(pool, "review.hold_protected", message_id, attempts=attempts)
        # Un avis enfin parti lève la retenue fermée : le message reste retenu,
        # mais protégé, et le superviseur n'a plus à le signaler.
        await pool.execute(
            """
            UPDATE delivery_cases SET details=details || '{"review_guard":"recovered"}'::jsonb
            WHERE message_id=$1::uuid AND details->>'review_guard'='fail_closed'
            """,
            message_id,
        )
        return "review_notice_queued"
    if error is not None:
        return await fail_open_held_message(
            pool,
            settings,
            message_id,
            reason="review_notice_queue_failed_fail_open",
            error=error,
        )
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
    """Répare une ancienne retenue orpheline ou conclut un avis définitivement bloqué."""
    # Une retenue fermée dont l'avis n'est jamais parti se retente, trois
    # fois au plus, à dix minutes d'intervalle : la cause (base, bac à sable)
    # a pu être réparée entre-temps.
    missing = await pool.fetchval(
        f"""
        WITH candidate AS (
            SELECT dc.id, m.id::text AS message_id
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
              AND (
                  coalesce(dc.details->>'review_guard','') <> 'fail_closed'
                  OR (
                      {_ATTEMPTS.format(d="dc.details")} <= $2
                      AND dc.updated_at < now()-($3 * interval '1 second')
                  )
              )
            ORDER BY dc.updated_at
            FOR UPDATE OF dc SKIP LOCKED
            LIMIT 1
        )
        UPDATE delivery_cases dc
        SET updated_at=now()
        FROM candidate
        WHERE dc.id=candidate.id
        RETURNING candidate.message_id
        """,
        MISSING_NOTICE_GRACE_SECONDS,
        FAIL_CLOSED_RETRIES,
        FAIL_CLOSED_RETRY_SECONDS,
    )
    if missing is not None:
        await hold_with_review_or_fail_open(
            pool, settings, invitations, str(missing)
        )
        return True

    # Une retenue fermée n'est pas reprise ici. Son avis est épuisé ou bloqué :
    # la mise en file le refuserait de nouveau, et remettre la file à zéro
    # bouclerait sur une panne déterministe. Sans cette exclusion, le même
    # dossier serait réclamé à chaque passage du worker et du rapport
    # d'entretien. Il attend l'exploitant.
    candidate = await pool.fetchrow(
        """
        SELECT ao.id,ao.status,ao.attempts,m.id::text AS message_id
        FROM messages m
        JOIN delivery_cases dc ON dc.message_id=m.id
        JOIN smtp_actions sa ON sa.case_id=dc.id AND sa.action='release_original'
        JOIN assistant_outbox ao ON ao.action_id=sa.id
        WHERE m.delivery_status='held'
          AND dc.state IN ('review_notice_pending','awaiting_reply')
          AND coalesce(dc.details->>'review_guard','') <> 'fail_closed'
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
    # Le texte précède le choix de la route : il ne dit pas ce qu'il advient
    # du message, seulement que l'avis est abandonné.
    claimed = await pool.fetchval(
        """
        UPDATE assistant_outbox SET status='error',attempts=$4,
            last_error='abandoned by review guard'
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
