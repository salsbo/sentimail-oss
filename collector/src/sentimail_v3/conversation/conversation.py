from __future__ import annotations

import hashlib
import html
import json
import re
from email.utils import parseaddr
from typing import Any

import asyncpg

from sentimail_v3.config import Settings
from sentimail_v3.conversation.action_tokens import ACTION_MARKER_RE, REFERENCE_TOKEN_RE, token_hash
from sentimail_v3.conversation.confirmation_code import (
    TTL_MINUTES as CONFIRMATION_TTL_MINUTES,
)
from sentimail_v3.conversation.confirmation_code import (
    code_hash,
    confirms,
    new_code,
)
from sentimail_v3.crypto import reveal
from sentimail_v3.identity import Identity, instance_identity
from sentimail_v3.execution.delivery_state import CONSUMED, HELD, move
from sentimail_v3.conversation.digest import PURPOSE as DIGEST_PURPOSE
from sentimail_v3.observation.dossier.hooks.visible_text import visible_html_text
from sentimail_v3.code.attack_techniques import pedagogy
from sentimail_v3.code.plain_words import (
    plain_limits,
    plain_points,
    short_conclusion,
)
from sentimail_v3.code.reference import reference
from sentimail_v3.conversation.review_notice import render_notice_html
from sentimail_v3.observation.preview import screenshot, thumbnail
from sentimail_v3.observation.risk_text import risky_text_excerpts
from sentimail_v3.code.tenancy import is_protected, protected_recipient
from sentimail_v3.code.trust import pool_trusts_sender

# La première ligne lue de l'avis. « Il attend ta réponse » laissait croire que
# le message répondrait de lui-même ; ce qui est attendu est une directive.
# Le mot « livré » y reste : la couleur d'alerte du bandeau se règle dessus.
HOLD_STATUS_TEXT = (
    "L’email ci-dessous n’a pas été livré : j’attends tes directives."
)

_CONFIRM_RE = re.compile(r"^\s*confirme\s+(?:maia|kitt)[.!]?\s*$", re.IGNORECASE)
_QUOTED_MARKERS = (
    re.compile(r"^On .+ wrote:$", re.IGNORECASE),
    re.compile(r"^Le .+ a écrit\s*:$", re.IGNORECASE),
    re.compile(r"^From:\s", re.IGNORECASE),
    re.compile(r"^De\s*:\s", re.IGNORECASE),
)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


_FACT_LABELS = {
    "categories": "données",
    "sensitive_categories": "données",
    "final_apexes": "destinations",
    "url_references": "URL concernées",
    "attachment_references": "fichiers concernés",
    "markers": "marqueurs",
    "zero_width": "caractères invisibles",
    "bidi_controls": "contrôles bidi",
    "base64_like_tokens": "segments encodés hors URL",
    "symbols": "symboles",
    "symbol_scores": "scores des symboles",
    "score": "score",
    "checked_symbol_count": "symboles Rspamd examinés",
    "method": "méthode",
    "result": "résultat",
    "apex": "apex",
    "pairs": "trajets",
    "purpose": "finalité",
    "urgency_kind": "type d’urgence",
    "action_types": "actions",
}


def _safe_fact_value(value: object) -> object:
    if isinstance(value, str):
        return value[:300]
    if isinstance(value, list):
        return [_safe_fact_value(item) for item in value[:6]]
    if isinstance(value, dict):
        return {
            str(key): _safe_fact_value(item)
            for key, item in list(value.items())[:8]
            if not any(secret in str(key).casefold() for secret in ("token", "full_url", "body"))
            and not (str(key) == "error" and value.get("technical_reason"))
        }
    return value


def clue_illustration(clue_code: str, facts: object) -> str | None:
    """Transforme la pièce structurée en détail lisible, sans exposer de jeton."""
    if isinstance(facts, str):
        try:
            facts = json.loads(facts)
        except ValueError:
            return None
    if not isinstance(facts, dict) or not facts:
        return None
    preferred = list(_FACT_LABELS)
    if clue_code == "URL_SANDBOX_INCOMPLETE":
        preferred = ["url_references", "occurrences"]
    elif clue_code == "ATTACHMENT_SANDBOX_INCOMPLETE":
        preferred = ["attachment_references", "occurrences"]
    elif clue_code in {"URL_SANDBOX_FORM", "URL_AMBIENT_SENSITIVE_FORM"}:
        preferred = ["sensitive_categories", "final_apexes", "context", "occurrences"]
    elif clue_code == "CONTENT_OBFUSCATION":
        preferred = ["markers", "zero_width", "bidi_controls", "base64_like_tokens"]
    selected = [
        (key, facts[key])
        for key in preferred
        if key in facts and facts[key] not in (None, [], {}, "")
    ]
    if not selected:
        selected = [
            (str(key), value)
            for key, value in list(facts.items())[:4]
            if value not in (None, [], {}, "")
            and not any(
                secret in str(key).casefold()
                for secret in ("token", "url", "body", "raw")
            )
        ]
    if not selected:
        return None
    return " ; ".join(
        f"{_FACT_LABELS.get(key, key)} = "
        + json.dumps(_safe_fact_value(value), ensure_ascii=False, default=str)
        for key, value in selected[:5]
    )


def readable_body(body_text: object, body_html: object) -> str:
    """Ce que la personne a écrit, que son client ait envoyé du texte ou non.

    Outlook et la plupart des clients mobiles répondent en HTML seul. Ne lire
    que la partie texte revenait à recevoir une directive vide : la réponse
    était bien arrivée, mais personne ne l'avait lue.
    """
    text = str(body_text or "").strip()
    if text:
        return text
    html = str(body_html or "")
    return visible_html_text(html).strip() if html else ""


def strip_quoted_reply(body: str) -> str:
    """Isole le texte saisi par l'utilisateur du contenu cite non fiable."""
    kept: list[str] = []
    for line in body.replace("\r\n", "\n").split("\n"):
        if line.strip() == "--":
            break
        if line.lstrip().startswith(">"):
            continue
        if any(marker.match(line.strip()) for marker in _QUOTED_MARKERS):
            break
        kept.append(line)
    return ACTION_MARKER_RE.sub("", "\n".join(kept)).strip()[:8000]


def aligned_sender(envelope_from: str, from_header: str) -> str | None:
    """Retourne l'adresse seulement si l'identité SMTP et le From sont alignés."""
    envelope = parseaddr(envelope_from)[1].casefold()
    visible = parseaddr(from_header)[1].casefold()
    if not envelope or not visible or envelope != visible:
        return None
    return visible


class ConversationStore:
    def __init__(
        self,
        pool: asyncpg.Pool[Any],
        action_address: str,
        assistant_sender: str,
        render_sandbox_url: str | None = None,
        action_aliases: tuple[str, ...] = (),
        encryption_key: bytes | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.pool = pool
        self.action_address = action_address.casefold()
        self.assistant_sender = assistant_sender
        self.render_sandbox_url = render_sandbox_url
        self.action_recipients = {self.action_address, *action_aliases}
        self.encryption_key = encryption_key
        # Optionnel et rétro-compatible : sans `settings` (vieux constructeurs,
        # tests), l'instance garde les valeurs figées ci-dessus. Avec lui, elle
        # relit l'identité à chaud (cache 60 s) à chaque composition de
        # courrier ou décision de routage - c'est la promesse de la fonction
        # « changer l'adresse dans l'admin sans redémarrage ».
        self.settings = settings

    async def _identity(self) -> Identity:
        if self.settings is None:
            return Identity(
                action_address=self.action_address,
                action_aliases=tuple(self.action_recipients - {self.action_address}),
                assistant_sender=self.assistant_sender,
                probe_recipient="",
            )
        return await instance_identity(self.pool, self.settings)

    async def is_action_recipient(self, recipients: list[str]) -> bool:
        identite = await self._identity()
        action_recipients = {
            identite.action_address.casefold(),
            *(alias.casefold() for alias in identite.action_aliases),
        }
        return any(
            parseaddr(value)[1].casefold() in action_recipients
            for value in recipients
        )

    async def queue_invitation(
        self, message_id: str, *, decision_mode: bool | None = None
    ) -> bool:
        identite = await self._identity()
        preview: bytes | None = None
        preview_inline: bytes | None = None
        preview_inline_type: str | None = None
        if self.render_sandbox_url:
            raw = await self.pool.fetchval(
                "SELECT raw_eml FROM messages WHERE id=$1::uuid", message_id
            )
            original = reveal(raw, self.encryption_key)
            if isinstance(original, bytes):
                preview = await screenshot(original, self.render_sandbox_url)
                if preview:
                    # L'avis affiche la miniature et joint l'original.
                    # Une miniature absente n'est pas une panne : l'original
                    # tient alors les deux rôles.
                    reduite = await thumbnail(preview, self.render_sandbox_url)
                    if reduite is not None:
                        preview_inline, preview_inline_type = reduite
        async with self.pool.acquire() as connection, connection.transaction():
            dossier = await connection.fetchrow(
                """
                SELECT dc.id AS case_id, m.subject, m.body_text, m.envelope_recipients,
                       m.from_header, i.favorable_points, i.adverse_points,
                       m.delivery_status, v.classification, v.confidence, v.rationale,
                       vr.attack_techniques
                FROM delivery_cases dc
                JOIN messages m ON m.id=dc.message_id
                JOIN investigations i ON i.id=dc.investigation_id
                LEFT JOIN LATERAL (
                    SELECT classification, confidence, rationale
                    FROM verdicts
                    WHERE investigation_id=i.id
                    ORDER BY created_at DESC LIMIT 1
                ) v ON true
                LEFT JOIN LATERAL (
                    SELECT response->'verdict'->'attack'->'techniques'
                        AS attack_techniques
                    FROM verdict_runs
                    WHERE investigation_id=i.id AND status='complete'
                    ORDER BY completed_at DESC LIMIT 1
                ) vr ON true
                WHERE m.id=$1::uuid
                """,
                message_id,
            )
            if dossier is None or not dossier["envelope_recipients"]:
                return False
            recipients = [
                str(value).casefold() for value in dossier["envelope_recipients"]
            ]
            participant = await protected_recipient(self.pool, recipients)
            if participant is None:
                # Aucun domaine actif ne couvre ce message : il n'y a personne à
                # qui demander un avis, et personne à qui écrire.
                return False
            hold_original = (
                dossier["delivery_status"] == "held"
                if decision_mode is None
                else decision_mode
            )
            if hold_original and dossier["delivery_status"] not in {
                "captured", "analyzing", "held"
            }:
                return dossier["delivery_status"] == "delivered"
            conversation_id = await connection.fetchval(
                """
                INSERT INTO conversations (case_id, participant_email, status)
                VALUES ($1,$2,'awaiting_user')
                ON CONFLICT (case_id) WHERE case_id IS NOT NULL DO UPDATE SET
                    participant_email=EXCLUDED.participant_email,
                    status='awaiting_user',updated_at=now()
                RETURNING id::text
                """,
                dossier["case_id"],
                participant,
            )
            existing = await connection.fetchrow(
                """
                SELECT ao.status,ao.attempts
                FROM smtp_actions sa
                JOIN assistant_outbox ao ON ao.action_id=sa.id
                WHERE sa.case_id=$1 AND sa.action=$2
                ORDER BY ao.created_at DESC LIMIT 1
                """,
                dossier["case_id"],
                "release_original" if hold_original else "give_directive",
            )
            if existing is not None:
                retryable = existing["status"] in {"pending", "sending"} or (
                    existing["status"] == "error" and int(existing["attempts"]) < 5
                )
                protected = bool(existing["status"] == "sent" or retryable)
                # Un avis déjà émis dispense d'en écrire un second, jamais de
                # conclure l'état du message : sans cela un dossier rejugé
                # resterait indéfiniment « en analyse » et deviendrait un
                # backlog silencieux.
                if protected and hold_original:
                    await move(connection, message_id, HELD)
                return protected
            action_id = await connection.fetchval(
                """
                INSERT INTO smtp_actions (
                    case_id, action, token_hash, reply_address, expires_at, context
                ) VALUES ($1,$2,NULL,$3,now()+interval '30 days',$4::jsonb)
                RETURNING id::text
                """,
                dossier["case_id"],
                "release_original" if hold_original else "give_directive",
                identite.action_address,
                _json(
                    {
                        "conversation_id": conversation_id,
                        "binding": hold_original,
                        "purpose": (
                            "review_notice" if hold_original else "observation_feedback"
                        ),
                    }
                ),
            )
            clues = await connection.fetch(
                """
                WITH deduplicated AS (
                    SELECT DISTINCT ON (c.clue_code,c.direction)
                           c.clue_code,c.direction,c.strength,c.statement,c.facts,c.id
                    FROM clues c
                    JOIN investigations i ON i.id=c.investigation_id
                    WHERE i.message_id=$1::uuid
                    ORDER BY c.clue_code,c.direction,c.strength DESC,c.id
                ), ranked AS (
                    SELECT *,row_number() OVER (
                        PARTITION BY direction ORDER BY strength DESC,id
                    ) AS rank
                    FROM deduplicated
                )
                SELECT clue_code,direction,strength,statement,facts FROM ranked
                WHERE (direction IN ('adverse','favorable') AND rank<=5)
                   OR (
                       direction='neutral' AND clue_code IN (
                           'URL_SANDBOX_INCOMPLETE',
                           'ATTACHMENT_SANDBOX_INCOMPLETE',
                           'EVIDENCE_INCOMPLETE',
                           'AUTH_NO_TRUSTED_RESULTS',
                           'RSPAMD_RESULT_MISSING',
                           'URL_PROTECTED_ACTION_NOT_VISITED'
                       )
                   )
                ORDER BY CASE direction
                    WHEN 'adverse' THEN 1 WHEN 'favorable' THEN 2 ELSE 3 END,
                    strength DESC,id
                """,
                message_id,
            )
            by_direction = {
                direction: [row for row in clues if row["direction"] == direction]
                for direction in ("adverse", "favorable", "neutral")
            }

            subject = str(dossier["subject"] or "(sans objet)")
            sender_name = str(dossier["from_header"] or "(expéditeur inconnu)")
            concerns = plain_points([dict(row) for row in by_direction["adverse"]], 3)
            reassurances = plain_points(
                [dict(row) for row in by_direction["favorable"]], 2
            )
            limits = plain_limits([dict(row) for row in by_direction["neutral"]], 2)
            # La motivation complète reste au dossier ; la lettre n'en garde
            # que ce que les deux colonnes n'ont pas déjà dit. Redire ligne à
            # ligne ce qu'on vient de lire enterre la seule phrase qui répond
            # à « et donc ? ».
            decision = short_conclusion(
                str(dossier["rationale"] or ""),
                listed=[*concerns, *reassurances, *limits],
            )
            risk_excerpts = risky_text_excerpts(
                subject, str(dossier["body_text"] or "")
            )

            def block(title: str, values: list[str], empty: str) -> str:
                lines = [f"- {value}" for value in values] or [f"- {empty}"]
                return title + "\n" + "\n".join(lines)

            def block_html(title: str, values: list[str], empty: str, color: str) -> str:
                items = "".join(
                    f'<li style="margin:4px 0">{html.escape(value)}</li>'
                    for value in values
                ) or f'<li style="margin:4px 0">{html.escape(empty)}</li>'
                return (
                    f'<h3 style="color:{color};margin-bottom:4px">{html.escape(title)}</h3>'
                    f'<ul style="margin:0;padding-left:20px">{items}</ul>'
                )

            trusted = await pool_trusts_sender(self.pool, dossier)
            status_text = (
                HOLD_STATUS_TEXT
                if hold_original
                else "Ce message t’a été livré ; ta réponse me sert à mieux faire."
            )
            if hold_original and trusted:
                # Deranger malgre une autorisation demande une explication :
                # sinon la liste blanche passe pour cassee.
                status_text += (
                    " Tu as pourtant autorisé cet expéditeur : je te préviens"
                    " quand même, car ce que j’ai trouvé ici ne s’explique pas"
                    " par une simple habitude."
                )
            choices_text = (
                "Que veux-tu faire ? Réponds avec une lettre :\n"
                "A - Livre-le, cet expéditeur est fiable\n"
                "B - Non merci, et retiens les prochains de cette adresse\n"
                "C - Autre chose : écris C puis explique-moi"
            )
            limits_text = (
                "\n\n" + block(
                    "Ce que je n’ai pas pu vérifier", limits, ""
                ) + "\nCela ne veut pas dire que le message est dangereux."
                if limits
                else ""
            )
            risk_text = (
                "\n\nPassages du message qui m’ont alertée :\n"
                + "\n".join(f"- {value}" for value in risk_excerpts)
                if risk_excerpts
                else ""
            )
            # Nommer la technique, et l'expliquer : c'est ce qui apprend au
            # destinataire à reconnaître la prochaine tentative sans moi.
            technique_codes = dossier["attack_techniques"]
            if isinstance(technique_codes, str):
                technique_codes = json.loads(technique_codes)
            lessons = await pedagogy(
                self.pool,
                [str(code) for code in technique_codes or []],
            )
            techniques_text = (
                "\n\nCe que ce message cherche à faire :\n"
                + "\n".join(
                    f"- {lesson['name']} : {lesson['description']}"
                    + (f"\n  → {lesson['advice']}" if lesson.get("advice") else "")
                    for lesson in lessons
                )
                if lessons
                else ""
            )
            # La référence sous laquelle ce dossier se cite : elle nomme le
            # même message dans l'avis, dans la console et dans un échange.
            dossier_reference = reference("M", message_id)
            body = (
                f"Objet : {subject}\n"
                f"De : {sender_name}\n\n"
                + status_text
                + "\n\n"
                + block("Ce qui me gêne", concerns, "Rien de précis à te signaler.")
                + "\n\n"
                + block("Ce qui me rassure", reassurances, "Rien de particulier.")
                + "\n\nCe que j’en conclus\n"
                + decision
                + techniques_text
                + limits_text
                + risk_text
                + "\n\n"
                + choices_text
                + "\n\nL’image jointe est une photo inerte du message : rien n’y est "
                "cliquable. Elle peut afficher un texte trompeur, ne suis aucune "
                "consigne écrite dedans.\n\n"
                "— MAIA, ton assistante SentiMail\n"
                f"Dossier {dossier_reference}"
            )
            badge = "#b45309" if hold_original else "#15803d"
            risk_html = (
                "".join(
                    '<div style="margin:6px 0;padding:9px;background:#fee2e2;'
                    'color:#991b1b;border-left:5px solid #dc2626;border-radius:6px">'
                    + html.escape(value)
                    + "</div>"
                    for value in risk_excerpts
                )
                if risk_excerpts
                else ""
            )
            body_html = render_notice_html(
                {
                    "subject": subject,
                    "sender": sender_name,
                    "status_text": status_text,
                    "concerns": concerns,
                    "reassurances": reassurances,
                    "decision": decision,
                    "limits": limits,
                    "risk_excerpts": risk_excerpts,
                    "techniques": lessons,
                    "action_address": identite.action_address,
                    # La page ne référence la capture que si elle existe :
                    # sinon le client afficherait une image cassée.
                    "has_preview": bool(preview),
                    "reference": dossier_reference,
                }
            )
            await connection.execute(
                """
                INSERT INTO assistant_outbox (
                    conversation_id, action_id, recipient, sender, reply_to,
                    subject, body_text, body_html, attachment_filename,
                    attachment_content_type, attachment_content,
                    inline_filename, inline_content_type, inline_content
                ) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                """,
                conversation_id,
                action_id,
                participant,
                identite.assistant_sender,
                identite.action_address,
                f"[SentiMail] Ton avis sur : {subject}"[:998],
                body,
                body_html,
                "capture-email-neutralisee.png" if preview else None,
                "image/png" if preview else None,
                preview,
                (
                    "apercu-email.jpg"
                    if preview_inline_type == "image/jpeg"
                    else "apercu-email.png"
                ) if preview_inline else None,
                preview_inline_type if preview_inline else None,
                preview_inline,
            )
            await connection.execute(
                """
                INSERT INTO review_notices (
                    case_id,status,explanation,evidence_snapshot,preview_kind,
                    preview_content,preview_sha256,render_policy,rendered_at
                ) VALUES ($1,'rendered',$2,$3::jsonb,$4,$5,$6,
                          'sentimail-render-sandbox-v0.2.1:no-network:no-js:qr-masked',now())
                """,
                dossier["case_id"],
                str(dossier["rationale"] or "Verdict indisponible."),
                _json({"clues": [dict(row) for row in clues]}),
                "png" if preview else "text",
                preview,
                hashlib.sha256(preview).hexdigest() if preview else None,
            )
            if hold_original:
                await move(connection, message_id, HELD)
                await connection.execute(
                    """
                    UPDATE delivery_cases SET state='awaiting_reply',
                        original_delivery_allowed=false,binding=true,updated_at=now()
                    WHERE id=$1
                    """,
                    dossier["case_id"],
                )
            return True

    async def record_inbound(self, message_id: str) -> str:
        async with self.pool.acquire() as connection, connection.transaction():
            message = await connection.fetchrow(
                """
                SELECT envelope_from, from_header, subject, body_text, body_html,
                       ARRAY(
                           SELECT value_decoded FROM headers
                           WHERE message_id=messages.id
                             AND name_normalized IN ('in-reply-to','references')
                           ORDER BY ordinal
                       ) AS references
                FROM messages WHERE id=$1::uuid
                """,
                message_id,
            )
            if message is None:
                raise RuntimeError("action message not found")
            sender = aligned_sender(
                str(message["envelope_from"] or ""),
                str(message["from_header"] or ""),
            )
            if sender is None:
                await connection.execute(
                    """
                    INSERT INTO audit_log (actor, action, payload)
                    VALUES ('conversation','smtp_reply.rejected_identity_mismatch',$1::jsonb)
                    """,
                    _json({"message_id": message_id}),
                )
                await self._mark_consumed(connection, message_id)
                return "rejected_sender_alignment"
            joined_references = " ".join(message["references"] or [])
            match = REFERENCE_TOKEN_RE.search(joined_references)
            if match is None:
                match = ACTION_MARKER_RE.search(
                    f"{message['subject'] or ''}\n"
                    + readable_body(message["body_text"], message["body_html"])
                )
            action = None
            if match:
                action = await connection.fetchrow(
                    """
                    SELECT sa.id, sa.case_id, c.id AS conversation_id,
                           c.participant_email, sa.context->>'purpose' AS purpose,
                           sa.context->>'confirm_message_id' AS confirm_message_id,
                           sa.context->>'confirmation_code_hash'
                               AS confirmation_code_hash
                    FROM smtp_actions sa
                    JOIN conversations c
                      ON c.id=NULLIF(sa.context->>'conversation_id','')::uuid
                    WHERE sa.token_hash=$1 AND sa.status='pending'
                      AND sa.expires_at > now()
                    -- Verrou sur l'action : deux traitements concurrents de la
                    -- même réponse (relivraison MX, deux coroutines) sont
                    -- sérialisés, et le second voit l'action déjà consommée
                    -- plutôt que de rejouer la directive.
                    FOR UPDATE OF sa
                    """,
                    token_hash(match.group(1)),
                )
            if action is not None and sender != action["participant_email"].casefold():
                await connection.execute(
                    """
                    INSERT INTO audit_log (actor, action, payload)
                    VALUES ('conversation','smtp_reply.rejected_sender',$1::jsonb)
                    """,
                    _json({"message_id": message_id, "sender": sender}),
                )
                await self._mark_consumed(connection, message_id)
                return "rejected_sender"

            if action is None and not await is_protected(self.pool, sender):
                await connection.execute(
                    """
                    INSERT INTO audit_log (actor, action, payload)
                    VALUES ('conversation','smtp_conversation.rejected_sender',$1::jsonb)
                    """,
                    _json({"message_id": message_id, "sender": sender}),
                )
                await self._mark_consumed(connection, message_id)
                return "rejected_sender"

            if action is None:
                return await self._queue_identity_challenge(
                    connection, message_id, message, sender
                )
            if action["purpose"] == DIGEST_PURPOSE:
                return await self._queue_digest_reply(
                    connection, message_id, message, sender, action
                )
            if action["purpose"] == "authenticate_directive":
                return await self._confirm_directive(
                    connection, message_id, message, sender, action
                )
            conversation_id = str(action["conversation_id"])
            await connection.execute(
                """
                UPDATE smtp_actions SET status='consumed', consumed_at=now(),
                    reply_message_id=$2::uuid, requested_by=$3
                WHERE id=$1 AND status='pending'
                """,
                action["id"],
                message_id,
                sender,
            )
            await connection.execute(
                "UPDATE conversations SET status='processing',updated_at=now() WHERE id=$1",
                action["conversation_id"],
            )

            user_text = strip_quoted_reply(
                readable_body(message["body_text"], message["body_html"])
            )
            await connection.execute(
                """
                INSERT INTO conversation_messages (
                    conversation_id, direction, message_id, subject, body_text,
                    user_text, processing_status
                ) VALUES ($1::uuid,'inbound',$2::uuid,$3,$4,$5,'pending')
                """,
                conversation_id,
                message_id,
                message["subject"],
                readable_body(message["body_text"], message["body_html"])[:50000],
                user_text,
            )
            await self._mark_consumed(connection, message_id)
            return "queued"

    async def _queue_digest_reply(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        message: asyncpg.Record,
        sender: str,
        action: asyncpg.Record,
    ) -> str:
        """Une réponse au récapitulatif porte plusieurs décisions à la fois."""
        await connection.execute(
            """
            UPDATE smtp_actions SET status='consumed', consumed_at=now(),
                reply_message_id=$2::uuid, requested_by=$3
            WHERE id=$1 AND status='pending'
            """,
            action["id"],
            message_id,
            sender,
        )
        await connection.execute(
            "UPDATE conversations SET status='processing',updated_at=now() WHERE id=$1",
            action["conversation_id"],
        )
        await connection.execute(
            """
            INSERT INTO conversation_messages (
                conversation_id, direction, message_id, subject, body_text,
                user_text, processing_status
            ) VALUES ($1::uuid,'inbound',$2::uuid,$3,$4,$5,'pending')
            """,
            str(action["conversation_id"]),
            message_id,
            message["subject"],
            readable_body(message["body_text"], message["body_html"])[:50000],
            strip_quoted_reply(
                readable_body(message["body_text"], message["body_html"])
            ),
        )
        await self._mark_consumed(connection, message_id)
        return "queued_digest"

    async def _queue_identity_challenge(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        message: asyncpg.Record,
        sender: str,
    ) -> str:
        identite = await self._identity()
        # Le quota porte sur l'expéditeur qui déclenche le challenge. Un compteur
        # global laisserait une adresse usurpée bloquer les demandes légitimes,
        # ce qui ferait du garde-fou un moyen de nuire. Le verrou dure ce que
        # dure le code : passé ce délai, une relance légitime doit repartir.
        recent_challenge = await connection.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM smtp_actions
                WHERE status='pending'
                  AND context->>'purpose'='authenticate_directive'
                  AND lower(context->>'challenged_sender')=lower($1)
                  AND issued_at > now() - ($2 * interval '1 minute')
            )
            """,
            sender,
            CONFIRMATION_TTL_MINUTES,
        )
        if recent_challenge:
            await connection.execute(
                """
                INSERT INTO audit_log (actor, action, payload)
                VALUES ('conversation','smtp_challenge.rate_limited',$1::jsonb)
                """,
                _json({"message_id": message_id, "sender": sender}),
            )
            await self._mark_consumed(connection, message_id)
            return "challenge_rate_limited"

        conversation_id = await connection.fetchval(
            """
            INSERT INTO conversations (participant_email, status)
            VALUES ($1,'awaiting_user') RETURNING id::text
            """,
            sender,
        )
        conversation_message_id = await connection.fetchval(
            """
            INSERT INTO conversation_messages (
                conversation_id, direction, message_id, subject, body_text,
                user_text, processing_status
            ) VALUES ($1::uuid,'inbound',$2::uuid,$3,$4,$5,'complete')
            RETURNING id::text
            """,
            conversation_id,
            message_id,
            message["subject"],
            readable_body(message["body_text"], message["body_html"])[:50000],
            strip_quoted_reply(
                readable_body(message["body_text"], message["body_html"])
            ),
        )
        # Le code n'existe qu'ici et dans le courrier envoyé à la boîte
        # challengée : il n'est conservé que haché, et il ne vaut que quelques
        # minutes.
        code = new_code()
        action_id = await connection.fetchval(
            """
            INSERT INTO smtp_actions (
                case_id, action, token_hash, reply_address, expires_at, context
            ) VALUES (
                NULL,'give_directive',NULL,$1,
                now() + ($3 * interval '1 minute'),$2::jsonb
            )
            RETURNING id::text
            """,
            identite.action_address,
            _json(
                {
                    "conversation_id": conversation_id,
                    "purpose": "authenticate_directive",
                    "confirm_message_id": conversation_message_id,
                    "challenged_sender": sender,
                    "confirmation_code_hash": code_hash(code),
                    "binding": False,
                }
            ),
            CONFIRMATION_TTL_MINUTES,
        )
        await connection.execute(
            """
            INSERT INTO assistant_outbox (
                conversation_id, action_id, recipient, sender, reply_to,
                subject, body_text
            ) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7)
            """,
            conversation_id,
            action_id,
            sender,
            identite.assistant_sender,
            identite.action_address,
            "[SentiMail] Confirme ta directive à MAIA",
            "J’ai reçu une nouvelle directive SMTP en ton nom.\n\n"
            "Pour prouver que cette demande vient bien de ta boîte, réponds "
            f"exactement : CONFIRME MAIA {code}\n\n"
            f"Ce code ne vaut que {CONFIRMATION_TTL_MINUTES} minutes et ne sert "
            "qu’une fois. Il n’existe que dans cet email : personne d’autre ne "
            "peut confirmer à ta place.\n\n"
            "Sans cette confirmation, le texte ne sera jamais envoyé au moteur "
            "LLM et aucune information d’apprentissage ne sera enregistrée. Si "
            "tu n’es pas à l’origine du message, ignore simplement cet email.\n\n"
            "— MAIA, SentiMail V3",
        )
        await connection.execute(
            """
            INSERT INTO audit_log (actor, action, payload)
            VALUES ('conversation','smtp_challenge.sent',$1::jsonb)
            """,
            _json({"message_id": message_id, "conversation_id": conversation_id}),
        )
        await self._mark_consumed(connection, message_id)
        return "confirmation_sent"

    async def _confirm_directive(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        message: asyncpg.Record,
        sender: str,
        action: asyncpg.Record,
    ) -> str:
        confirmation = strip_quoted_reply(
            readable_body(message["body_text"], message["body_html"])
        )
        confirmed = confirms(confirmation, action["confirmation_code_hash"])
        rejection = (
            None
            if confirmed
            else ("missing_code" if _CONFIRM_RE.search(confirmation) else "no_match")
        )
        # L'action est consommée que le code soit bon ou non : une tentative,
        # une seule. C'est ce qui interdit d'essayer les codes un par un.
        await connection.execute(
            """
            UPDATE smtp_actions SET status='consumed', consumed_at=now(),
                reply_message_id=$2::uuid, requested_by=$3
            WHERE id=$1 AND status='pending'
            """,
            action["id"],
            message_id,
            sender,
        )
        if confirmed:
            updated = await connection.execute(
                """
                UPDATE conversation_messages SET processing_status='pending'
                WHERE id=$1::uuid AND conversation_id=$2 AND direction='inbound'
                """,
                action["confirm_message_id"],
                action["conversation_id"],
            )
            if not updated.endswith("1"):
                raise RuntimeError("directive awaiting confirmation not found")
            await connection.execute(
                "UPDATE conversations SET status='processing',updated_at=now() WHERE id=$1",
                action["conversation_id"],
            )
            audit_action = "smtp_challenge.confirmed"
            status = "queued_confirmed"
        else:
            await connection.execute(
                "UPDATE conversations SET status='closed',updated_at=now() WHERE id=$1",
                action["conversation_id"],
            )
            audit_action = "smtp_challenge.rejected"
            status = "confirmation_rejected"
        await connection.execute(
            "INSERT INTO audit_log (actor, action, payload) "
            "VALUES ('conversation',$1,$2::jsonb)",
            audit_action,
            _json(
                {
                    "message_id": message_id,
                    "conversation_id": action["conversation_id"],
                    "rejection": rejection,
                }
            ),
        )
        await self._mark_consumed(connection, message_id)
        return status

    @staticmethod
    async def _mark_consumed(connection: asyncpg.Connection, message_id: str) -> None:
        await move(connection, message_id, CONSUMED)
