"""Effets durables d'une décision humaine authentifiée.

Une réponse individuelle et une ligne de récapitulatif qualifient le même
message. Elles doivent donc conserver les mêmes indices, la même vérité terrain
et la même politique d'expéditeur dans une transaction déjà ouverte par
l'appelant.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import asyncpg

from sentimail_v3.code.rulebook import set_sender_list_policy
from sentimail_v3.code.mail_profile import read_mail_profile
from sentimail_v3.code.sender_identity import read_proven_identity
from sentimail_v3.supervision.training_store import store_ground_truth_sample


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class HumanDecision:
    message_id: str
    participant_email: str
    sender: str
    subject: str | None
    classification: str | None = None
    list_action: str | None = None
    policy_source: str = "authenticated_smtp_feedback"
    label_context: dict[str, object] = field(default_factory=dict)
    model_name: str | None = None
    model_version: str | None = None
    case_id: object | None = None
    close_current: bool = False
    close_details: dict[str, object] = field(default_factory=dict)
    audit_choice: str | None = None


async def observed_signals(
    connection: asyncpg.Connection, message_id: str
) -> list[str]:
    """Fige les indices orientés présents lorsque l'humain tranche."""
    return [
        str(row["clue_code"])
        for row in await connection.fetch(
            """
            SELECT DISTINCT c.clue_code
            FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction <> 'neutral'
            ORDER BY c.clue_code
            """,
            message_id,
        )
    ][:40]


async def block_proven_sender(
    connection: asyncpg.Connection,
    participant: str,
    message_id: str,
    *,
    source: str,
) -> tuple[str, str] | None:
    """Retient l'expéditeur réel du message, jamais ce qu'il affiche.

    Un faux « CIC » envoyé depuis truc.fr fait bannir truc.fr, pas cic.fr.
    Sans identité prouvée, aucune règle : bannir l'adresse affichée
    retiendrait la victime de l'usurpation. Le verdict humain reste acquis.
    """
    identity = await read_proven_identity(connection, message_id)
    target = identity.block_target if identity else None
    payload: dict[str, object] = {
        "participant": participant,
        "message_id": message_id,
        "source": source,
    }
    if target is None:
        await connection.execute(
            "INSERT INTO audit_log(actor,action,payload) VALUES "
            "('assistant','sender_list.identity_unproven',$1::jsonb)",
            _json(payload),
        )
        return None
    scope, value = target
    await set_sender_list_policy(
        connection,
        participant,
        value,
        "hold",
        source=source,
        observed_sender=True,
        scope=scope,
    )
    await connection.execute(
        "INSERT INTO audit_log(actor,action,payload) VALUES "
        "('assistant','sender_list.proven_block_applied',$1::jsonb)",
        _json({**payload, "scope": scope, "value": value}),
    )
    return target


async def apply_human_decision(
    connection: asyncpg.Connection, decision: HumanDecision
) -> list[str]:
    """Applique label, apprentissage, liste et clôture sans ouvrir de transaction."""
    signals: list[str] = []
    if decision.classification:
        signals = await observed_signals(connection, decision.message_id)
        context = {**decision.label_context, "signals": signals}
        profile = await read_mail_profile(connection, decision.message_id)
        if profile:
            context.update(mail_profile=profile, mail_profile_message_id=decision.message_id)
        await connection.execute(
            """
            INSERT INTO labels (
                message_id, source, label, confidence, is_ground_truth,
                model_name, model_version, context,
                sender_normalized, participant_email, subject
            ) VALUES ($1::uuid,'smtp_feedback_user',$2,1,true,$3,$4,$5::jsonb,$6,$7,$8)
            ON CONFLICT DO NOTHING
            """,
            decision.message_id,
            decision.classification,
            decision.model_name,
            decision.model_version,
            _json(context),
            decision.sender or None,
            decision.participant_email.casefold(),
            decision.subject,
        )
        await store_ground_truth_sample(
            connection, decision.message_id, decision.classification
        )
    if decision.list_action:
        if not decision.sender or "@" not in decision.sender:
            raise ValueError("sender identity unavailable for authenticated choice")
        target: tuple[str, str] | None = None
        if decision.list_action == "hold":
            target = await block_proven_sender(
                connection,
                decision.participant_email,
                decision.message_id,
                source=decision.policy_source,
            )
        else:
            await set_sender_list_policy(
                connection,
                decision.participant_email,
                decision.sender,
                decision.list_action,
                source=decision.policy_source,
                observed_sender=True,
            )
        if decision.audit_choice:
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('assistant','sender_list.choice_applied',$1::jsonb)",
                _json(
                    {
                        "participant": decision.participant_email,
                        "sender": decision.sender,
                        "choice": decision.audit_choice,
                        "list_action": decision.list_action,
                        "message_id": decision.message_id,
                        "scope": target[0] if target else None,
                        "value": target[1] if target else None,
                    }
                ),
            )
    if decision.close_current and decision.case_id:
        await connection.execute(
            """
            UPDATE delivery_cases
            SET state='closed', original_delivery_allowed=false,
                updated_at=now(), details=details || $2::jsonb
            WHERE id=$1
            """,
            decision.case_id,
            _json(decision.close_details),
        )
    return signals
