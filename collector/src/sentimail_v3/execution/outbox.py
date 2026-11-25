"""Mise en file d'un message de MAIA, avec le jeton qui rouvre le dossier.

Chaque message sortant crée son action SMTP : c'est ce jeton, transporté par le
`Message-ID`, qui permet à l'utilisateur de répondre et d'être rattaché au bon
dossier. Une réponse sans jeton disponible n'a plus de dossier ; la file est
donc le seul endroit où ce lien se crée.
"""

from __future__ import annotations

import json
import re
from uuid import UUID, uuid5

import asyncpg

from sentimail_v3.conversation.action_tokens import action_token, new_nonce, token_hash


async def bind_digest_ballots(
    pool: asyncpg.Pool, parent_id: str, html: str, secret: str
) -> str:
    """Un jeton à usage unique par lot, limité aux dossiers montrés par son bouton.

    Les identifiants restent stables en cas de nouvel essai SMTP. Les jetons ne
    vivent que dans le courrier ; seule leur empreinte est enregistrée en base.
    """
    # Seul l'objet des liens produits par le rendu porte un marqueur. Un nom
    # d'expéditeur ou un motif qui en reproduit le texte n'est pas une action.
    pattern = re.compile(
        r'(href="mailto:[^"?]*\?subject=[^"&]*?)'
        r'S3-BALLOT-([0-9]+(?:_[0-9]+)*)-TOKEN-PLACEHOLDER(&amp;body=)'
    )
    markers = dict.fromkeys(match.group(2) for match in pattern.finditer(html))
    if not markers:
        return html
    raw = await pool.fetchval("SELECT context FROM smtp_actions WHERE id=$1::uuid", parent_id)
    context = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(context, dict) or context.get("purpose") != "daily_digest":
        raise ValueError("action de récapitulatif absente")
    mapping = context.get("digest") or {}
    tokens = {}
    for numbers in markers:
        keys = numbers.split("_")
        if any(key not in mapping for key in keys):
            raise ValueError("lot étranger au récapitulatif")
        child_id = str(uuid5(UUID(parent_id), "digest-ballot:" + numbers))
        token = action_token(secret, child_id, new_nonce())
        child_context = {
            **context,
            "digest": {key: mapping[key] for key in keys},
            "digest_parent_action": parent_id,
        }
        child_context.pop("nonce", None)
        created = await pool.fetchval(
            """
            INSERT INTO smtp_actions (
                id,case_id,action,token_hash,reply_address,expires_at,context
            ) SELECT $2::uuid,case_id,action,$3,reply_address,expires_at,$4::jsonb
              FROM smtp_actions WHERE id=$1::uuid AND status='pending'
            ON CONFLICT (id) DO UPDATE SET token_hash=EXCLUDED.token_hash
                WHERE smtp_actions.status='pending'
            RETURNING id
            """,
            parent_id, child_id, token_hash(token), _json(child_context),
        )
        if created is None:
            raise ValueError("lot déjà utilisé ou récapitulatif indisponible")
        tokens[numbers] = token
    return pattern.sub(
        lambda match: match.group(1) + f"S3-ACTION:{tokens[match.group(2)]}" + match.group(3),
        html,
    )


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
    inline_filename: str | None = None,
    inline_content_type: str | None = None,
    inline_content: bytes | None = None,
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
            attachment_content, body_html, inline_filename, inline_content_type,
            inline_content
        ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
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
        inline_filename,
        inline_content_type,
        inline_content,
    )
    await connection.execute(
        "UPDATE conversations SET status='awaiting_user',updated_at=now() WHERE id=$1::uuid",
        conversation_id,
    )
