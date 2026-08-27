"""Mise en file d'un message de MAIA, avec le jeton qui rouvre le dossier.

Chaque message sortant crée son action SMTP : c'est ce jeton, transporté par le
`Message-ID`, qui permet à l'utilisateur de répondre et d'être rattaché au bon
dossier. Une réponse sans jeton disponible n'a plus de dossier ; la file est
donc le seul endroit où ce lien se crée.
"""

from __future__ import annotations

import json

import asyncpg


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


async def queue_response(
    connection: asyncpg.Connection,
    conversation_id: str,
    case_id: object,
    participant: str,
    sender: str,
    reply_to: str,
    subject: str,
    body: str,
    attachment_filename: str | None = None,
    attachment_content_type: str | None = None,
    attachment_content: bytes | None = None,
    purpose: str | None = None,
    context_extra: dict[str, object] | None = None,
    # Ajouté en dernier, pour ne pas décaler les appels qui passent la pièce
    # jointe par position.
    body_html: str | None = None,
) -> None:
    # Une lettre sans expéditeur ni adresse de réponse ne peut recevoir aucune
    # réponse : la question posée est sans retour possible. Six courriers sont
    # partis ainsi le 18 août, vers trois destinataires, parce qu'un appelant
    # passait des chaînes vides et que rien ne le voyait. Le refus est ici,
    # au seul endroit où toute lettre passe.
    for nom, valeur in (
        ("destinataire", participant),
        ("expéditeur", sender),
        ("adresse de réponse", reply_to),
    ):
        if not str(valeur or "").strip():
            raise ValueError(f"{nom} manquant : la lettre serait sans retour")
    context: dict[str, object] = {
        "conversation_id": conversation_id,
        "binding": False,
    }
    if purpose:
        context["purpose"] = purpose
    if context_extra:
        context.update(context_extra)
    action_id = await connection.fetchval(
        """
        INSERT INTO smtp_actions (
            case_id, action, token_hash, reply_address, expires_at, context
        ) VALUES ($1,'give_directive',NULL,$2,now()+interval '30 days',$3::jsonb)
        RETURNING id
        """,
        case_id,
        reply_to,
        _json(context),
    )
    await connection.execute(
        """
        INSERT INTO assistant_outbox (
            conversation_id, action_id, recipient, sender, reply_to, subject,
            body_text, attachment_filename, attachment_content_type,
            attachment_content, body_html
        ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        """,
        conversation_id,
        action_id,
        participant,
        sender,
        reply_to,
        subject[:998],
        body,
        attachment_filename,
        attachment_content_type,
        attachment_content,
        body_html,
    )
    await connection.execute(
        "UPDATE conversations SET status='awaiting_user',updated_at=now() WHERE id=$1::uuid",
        conversation_id,
    )
