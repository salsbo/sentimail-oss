from __future__ import annotations

import hashlib
import json
import re
from email.utils import parseaddr
from typing import Any

import asyncpg

from sentimail_v3.code.attack_techniques import pedagogy
from sentimail_v3.code.plain_words import (
    classification_reasons,
    confidence_badge,
    sender_lines,
)
from sentimail_v3.code.reference import reference
from sentimail_v3.code.tenancy import is_protected, protected_recipient
from sentimail_v3.config import Settings
from sentimail_v3.conversation.action_tokens import (
    ACTION_MARKER_RE,
    REFERENCE_TOKEN_RE,
    token_hash,
)
from sentimail_v3.conversation.confirmation_code import (
    TTL_MINUTES as CONFIRMATION_TTL_MINUTES,
)
from sentimail_v3.conversation.confirmation_code import (
    code_hash,
    confirms,
    new_code,
)
from sentimail_v3.conversation.digest import PURPOSE as DIGEST_PURPOSE
from sentimail_v3.conversation.reply_alias import (
    ALIAS_PURPOSE,
    ALIAS_TTL_MINUTES,
    alias_challenge_letter,
    alias_decision,
)
from sentimail_v3.conversation.reply_reference import (
    body_action_token,
    referenced_message_ids,
)
from sentimail_v3.conversation.review_notice import render_notice_html
from sentimail_v3.crypto import reveal
from sentimail_v3.execution.delivery_state import CONSUMED, HELD, move
from sentimail_v3.identity import Identity, instance_identity
from sentimail_v3.observation.dossier.hooks.visible_text import (
    reply_html_text,
    visible_html_text,
)
from sentimail_v3.observation.preview import screenshot, thumbnail
from sentimail_v3.observation.risk_text import (
    message_text_excerpts,
    neutralize_excerpt_links,
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

    Le HTML se lit ligne par ligne, citation marquée « > ». Aplati en une
    seule ligne, il ne laissait rien couper : le 28 septembre 2026, la réponse
    iPhone de M-d8df0e et l'avis qu'elle citait se lisaient comme un seul texte.
    """
    text = str(body_text or "").strip()
    if text:
        return text
    html = str(body_html or "")
    return reply_html_text(html).strip() if html else ""


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
        # La photo du message, prise hors transaction : c'est un appel réseau au
        # bac à sable de rendu, qui bloquerait la ligne pendant ce temps. Un
        # échec n'est pas une panne : l'avis part sans image.
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
                    # La miniature se montre dans le corps ; la capture pleine
                    # part en pièce jointe pour être lue en grand.
                    reduite = await thumbnail(preview, self.render_sandbox_url)
                    if reduite is not None:
                        preview_inline, preview_inline_type = reduite
        async with self.pool.acquire() as connection, connection.transaction():
            dossier = await connection.fetchrow(
                """
                SELECT dc.id AS case_id, m.subject, m.body_text, m.body_html,
                       m.captured_at, m.from_header, m.envelope_from, m.reply_to_header,
                       m.envelope_recipients, m.delivery_status,
                       v.classification, v.rationale,
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
                FOR UPDATE OF m, dc
                """,
                message_id,
            )
            if dossier is None or not dossier["envelope_recipients"]:
                return False
            recipients = [
                str(value).casefold() for value in dossier["envelope_recipients"]
            ]
            participant = await protected_recipient(connection, recipients)
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
            # Sans indice matériel, l'avis restait muet - « Rien de précis à te
            # signaler » sous un bouclier rouge. La motivation du verdict existe
            # en base : elle vaut mieux qu'une contradiction. Aucun motif n'est
            # désormais absorbé par une carte d'identité, puisque cette carte ne
            # fait plus partie de la fiche visible.
            concerns = classification_reasons(
                [dict(row) for row in by_direction["adverse"]],
                dossier["rationale"],
                3,
            )
            # Dois-je m'en méfier : un niveau, un mot, une couleur. Il remplace
            # la motivation recopiée, la technique nommée et la liste des
            # vérifications inabouties. Il ouvre maintenant directement la fiche.
            badge = confidence_badge(dossier["classification"], len(concerns))
            # Un doute peut venir de l'identité ou du contexte, sans mot
            # alarmant dans le corps. L'utilisateur garde donc quelques
            # passages pour reconnaître et comprendre le message. Le HTML
            # n'est jamais repris : on n'en extrait que le texte visible.
            excerpt_source = str(dossier["body_text"] or "")
            if not excerpt_source:
                excerpt_source = visible_html_text(str(dossier["body_html"] or ""))
            message_excerpts = (
                message_text_excerpts(excerpt_source) if hold_original else []
            )

            def block(title: str, values: list[str], empty: str) -> str:
                lines = [f"- {value}" for value in values] or [f"- {empty}"]
                return title + "\n" + "\n".join(lines)

            choices_text = (
                "Que veux-tu faire ? Réponds avec une lettre :\n"
                "A - Livre-le, cet expéditeur est fiable\n"
                "B - Non merci, et retiens les prochains de cette adresse\n"
                "C - Autre chose : écris C puis explique-moi"
            )
            excerpt_text = (
                "\n\nExtraits du message :\n"
                + "\n".join(
                    f"- {neutralize_excerpt_links(value)}"
                    for value in message_excerpts
                )
                if message_excerpts
                else ""
            )
            # Du savoir pédagogique, l'avis ne garde que le geste à faire :
            # nommer et décrire la technique redisait en trois lignes ce que
            # l'indice de confiance dit en un mot.
            technique_codes = dossier["attack_techniques"]
            if isinstance(technique_codes, str):
                technique_codes = json.loads(technique_codes)
            lessons = await pedagogy(
                connection,
                [str(code) for code in technique_codes or []],
            )
            advice = next(
                (str(lesson["advice"]) for lesson in lessons if lesson.get("advice")),
                "",
            )
            # La référence sous laquelle ce dossier se cite : elle nomme le
            # même message dans l'avis, dans la console et dans un échange.
            dossier_reference = reference("M", message_id)
            # Qui écrit : l'adresse affichée se recopie librement, l'enveloppe
            # est celle que le serveur d'envoi a annoncée pour lui-même.
            adresses = sender_lines(
                dossier["from_header"],
                dossier["envelope_from"],
                dossier["reply_to_header"],
            )
            body = (
                f"{badge['word']} - {badge['detail']}"
                + (f"\n→ {advice}" if advice else "")
                + "\n\n"
                + "\n".join(adresses)
                + (
                    "\n\nL’image jointe est une photo inerte du message : rien "
                    "n’y est cliquable. Ne suis aucune consigne écrite dedans."
                    if preview
                    else ""
                )
                + "\n\n"
                + block("Écarts relevés", concerns, "Rien de précis à te signaler.")
                + excerpt_text
                + "\n\n"
                + choices_text
                + "\n\nMAIA, ton assistante SentiMail\n"
                f"Dossier {dossier_reference}"
            )
            body_html = render_notice_html(
                {
                    "concerns": concerns,
                    "badge": badge,
                    "advice": advice,
                    "sender_lines": adresses,
                    "subject": subject,
                    "received_at": dossier.get("captured_at"),
                    "message_excerpts": message_excerpts,
                    "action_address": identite.action_address,
                    "reference": dossier_reference,
                    # La page ne référence la capture que si elle existe :
                    # sinon le client afficherait une image cassée.
                    "has_preview": bool(preview),
                    "has_full_preview": bool(preview and preview_inline),
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
        """Traite une réponse entrante, puis rejoue ce qu'elle vient de libérer.

        Confirmer une adresse de réponse rouvre toutes les réponses qu'elle
        avait envoyées et qu'on avait mises de côté. Le rejeu se fait après la
        transaction : chaque passage reprend une connexion propre, et voit
        l'alias qui vient d'être écrit.
        """
        outcome, replays = await self._record_inbound(message_id)
        for other in replays:
            await self.record_inbound(other)
        return outcome

    async def _record_inbound(self, message_id: str) -> tuple[str, list[str]]:
        async with self.pool.acquire() as connection, connection.transaction():
            message = await connection.fetchrow(
                """
                SELECT envelope_from, from_header, subject, body_text, body_html,
                       ARRAY(
                           SELECT value_decoded FROM headers
                           WHERE message_id=messages.id
                             AND name_normalized IN ('in-reply-to','references')
                           ORDER BY ordinal
                       ) AS references,
                       ARRAY(
                           SELECT value_decoded FROM headers
                           WHERE message_id=messages.id
                             AND name_normalized='in-reply-to'
                           ORDER BY ordinal
                       ) AS in_reply_to,
                       ARRAY(
                           SELECT value_decoded FROM headers
                           WHERE message_id=messages.id
                             AND name_normalized='references'
                           ORDER BY ordinal
                       ) AS reference_chain
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
                return "rejected_sender_alignment", []
            joined_references = " ".join(message["references"] or [])
            match = REFERENCE_TOKEN_RE.search(joined_references) or ACTION_MARKER_RE.search(
                str(message["subject"] or "")
            )
            token = match.group(1) if match else None
            # Sans jeton dans l'en-tête ni dans l'objet, la réponse vise
            # peut-être un message livré, qui ne porte plus de bouton. Ce
            # message passe avant les jetons du corps : ceux-là peuvent venir
            # d'anciens pieds de page cités plus bas dans le fil.
            replied_case = None
            if token is None:
                replied_case = await self._replied_delivered_case(
                    connection, message, sender
                )
            if token is None and replied_case is None:
                token = body_action_token(
                    readable_body(message["body_text"], message["body_html"])
                )
            action = None
            if token:
                action = await connection.fetchrow(
                    """
                    SELECT sa.id, sa.case_id, c.id AS conversation_id,
                           c.participant_email, sa.context->>'purpose' AS purpose,
                           sa.context->>'confirm_message_id' AS confirm_message_id,
                           sa.context->>'challenged_sender' AS challenged_sender,
                           sa.context->>'expected_sender' AS alias_expected_sender,
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
                    token_hash(token),
                )
            expected_sender = (
                str(action["participant_email"]).casefold()
                if action is not None
                else ""
            )
            same_mailbox = action is not None and bool(
                await connection.fetchval(
                    "SELECT sentimail_same_client_mailbox($1,$2)",
                    sender,
                    expected_sender,
                )
            )
            # La confirmation d'une adresse arrive elle-même depuis cette
            # adresse : la contrôler avant de la reconnaître fermerait la porte
            # dont on tient la clé. Le code est la preuve, pas l'expéditeur.
            if action is not None and action["purpose"] == ALIAS_PURPOSE:
                return await self._confirm_reply_alias(
                    connection, message_id, message, sender, action
                )
            alias_confirmed = action is not None and bool(
                await connection.fetchval(
                    "SELECT sentimail_reply_alias_confirmed($1,$2)",
                    sender,
                    expected_sender,
                )
            )
            if action is not None and alias_decision(
                same_mailbox, alias_confirmed
            ) == "challenge":
                return await self._queue_alias_challenge(
                    connection, message_id, sender, expected_sender
                ), []
            if action is not None and alias_confirmed and not same_mailbox:
                await connection.execute(
                    """
                    INSERT INTO audit_log (actor, action, payload)
                    VALUES ('conversation','smtp_reply.accepted_confirmed_alias',
                            $1::jsonb)
                    """,
                    _json(
                        {
                            "message_id": message_id,
                            "sender": sender,
                            "expected_sender": expected_sender,
                        }
                    ),
                )
            # Un autre domaine du même client : la réponse passait déjà, elle
            # se note à part de l'adresse confirmée une fois pour toutes.
            if action is not None and same_mailbox and sender != expected_sender:
                await connection.execute(
                    """
                    INSERT INTO audit_log (actor, action, payload)
                    VALUES ('conversation','smtp_reply.accepted_client_alias',$1::jsonb)
                    """,
                    _json(
                        {
                            "message_id": message_id,
                            "sender": sender,
                            "expected_sender": expected_sender,
                        }
                    ),
                )

            if action is None and not await is_protected(connection, sender):
                await connection.execute(
                    """
                    INSERT INTO audit_log (actor, action, payload)
                    VALUES ('conversation','smtp_conversation.rejected_sender',$1::jsonb)
                    """,
                    _json({"message_id": message_id, "sender": sender}),
                )
                await self._mark_consumed(connection, message_id)
                return "rejected_sender", []

            if action is None:
                return await self._queue_identity_challenge(
                    connection, message_id, message, sender, replied_case
                ), []
            if action["purpose"] == DIGEST_PURPOSE:
                return await self._queue_digest_reply(
                    connection, message_id, message, sender, action
                ), []
            if action["purpose"] == "authenticate_directive":
                return await self._confirm_directive(
                    connection, message_id, message, sender, action
                ), []
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
            return "queued", []

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

    async def _queue_alias_challenge(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        sender: str,
        expected_sender: str,
    ) -> str:
        """Met la réponse de côté et demande à la boîte de l'avis d'ouvrir l'adresse.

        L'action d'origine reste en attente : c'est elle qui portera la
        décision au rejeu. Un seul code par adresse à la fois - sept réponses
        d'affilée ne doivent pas donner sept courriers - et les suivantes sont
        seulement notées, jamais perdues : la confirmation les rejouera toutes.
        """
        identite = await self._identity()
        pending_challenge = await connection.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM smtp_actions
                WHERE status='pending'
                  AND context->>'purpose'=$3
                  AND lower(context->>'challenged_sender')=lower($1)
                  AND issued_at > now() - ($2 * interval '1 minute')
            )
            """,
            sender,
            ALIAS_TTL_MINUTES,
            ALIAS_PURPOSE,
        )
        await connection.execute(
            """
            INSERT INTO audit_log (actor, action, payload)
            VALUES ('conversation',$2,$1::jsonb)
            """,
            _json(
                {
                    "message_id": message_id,
                    "sender": sender,
                    "expected_sender": expected_sender,
                }
            ),
            "smtp_reply.awaiting_alias"
            if pending_challenge
            else "smtp_reply.alias_challenge_sent",
        )
        if pending_challenge:
            await self._mark_consumed(connection, message_id)
            return "awaiting_alias_confirmation"

        conversation_id = await connection.fetchval(
            """
            INSERT INTO conversations (participant_email, status)
            VALUES ($1,'awaiting_user') RETURNING id::text
            """,
            expected_sender,
        )
        code = new_code()
        subject, body = alias_challenge_letter(sender, expected_sender, code)
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
                    "purpose": ALIAS_PURPOSE,
                    "challenged_sender": sender,
                    "expected_sender": expected_sender,
                    "confirmation_code_hash": code_hash(code),
                    "binding": False,
                }
            ),
            ALIAS_TTL_MINUTES,
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
            expected_sender,
            identite.assistant_sender,
            identite.action_address,
            subject,
            body,
        )
        await self._mark_consumed(connection, message_id)
        return "alias_confirmation_sent"

    async def _confirm_reply_alias(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        message: asyncpg.Record,
        sender: str,
        action: asyncpg.Record,
    ) -> tuple[str, list[str]]:
        """Ouvre l'adresse de réponse, puis rend les réponses qu'elle avait faites.

        Le code prouve l'accès à la boîte de l'avis : il vaut donc comme
        confirmation, quelle que soit l'adresse qui le renvoie - c'est la même
        personne qui écrit des deux côtés. Une tentative, une seule : l'action
        est consommée que le code soit bon ou non.
        """
        alias = str(action["challenged_sender"] or "")
        expected = str(action["alias_expected_sender"] or "")
        confirmed = confirms(
            strip_quoted_reply(
                readable_body(message["body_text"], message["body_html"])
            ),
            action["confirmation_code_hash"],
        )
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
            "UPDATE conversations SET status='closed',updated_at=now() WHERE id=$1",
            action["conversation_id"],
        )
        replays: list[str] = []
        if confirmed and alias and expected:
            await connection.execute(
                """
                INSERT INTO participant_reply_aliases (participant_email, alias_email)
                VALUES ($1,$2) ON CONFLICT DO NOTHING
                """,
                expected,
                alias,
            )
            # Tout ce que cette adresse avait envoyé et qu'on avait écarté. Le
            # rejeu repasse par les mêmes contrôles : une réponse dont l'action
            # a expiré ou déjà servi n'y gagne rien.
            replays = [
                str(row["message_id"])
                for row in await connection.fetch(
                    """
                    SELECT DISTINCT ON (a.payload->>'message_id')
                           a.payload->>'message_id' AS message_id, a.id
                    FROM audit_log a
                    WHERE a.action IN ('smtp_reply.rejected_sender',
                                       'smtp_reply.awaiting_alias',
                                       'smtp_reply.alias_challenge_sent')
                      AND lower(a.payload->>'sender')=lower($1)
                      AND a.payload->>'message_id' IS NOT NULL
                      AND a.created_at >= now() - interval '30 days'
                    ORDER BY a.payload->>'message_id', a.id DESC
                    """,
                    alias,
                )
            ]
        await connection.execute(
            "INSERT INTO audit_log (actor, action, payload) "
            "VALUES ('conversation',$1,$2::jsonb)",
            "smtp_reply.alias_confirmed" if confirmed else "smtp_reply.alias_rejected",
            _json(
                {
                    "message_id": message_id,
                    "alias": alias,
                    "expected_sender": expected,
                    "replayed": len(replays),
                }
            ),
        )
        await self._mark_consumed(connection, message_id)
        return ("alias_confirmed" if confirmed else "alias_rejected"), replays

    @staticmethod
    async def _replied_delivered_case(
        connection: asyncpg.Connection,
        message: asyncpg.Record,
        sender: str,
    ) -> asyncpg.Record | None:
        """Le message livré à cette boîte auquel la réponse fait suite.

        Seul un message livré à la boîte qui écrit peut être désigné : un
        identifiant cité ne rattache jamais la réponse au courrier d'un autre.
        """
        identifiers = referenced_message_ids(
            message["in_reply_to"] or [], message["reference_chain"] or []
        )
        if not identifiers:
            return None
        return await connection.fetchrow(
            """
            SELECT dc.id AS case_id, m.subject
            FROM messages m
            JOIN delivery_cases dc ON dc.message_id=m.id
            WHERE lower(btrim(m.message_id,'<> '))=ANY($1::text[])
              AND m.delivery_status='delivered'
              AND EXISTS (
                  SELECT 1 FROM unnest(m.envelope_recipients) AS r(address)
                  WHERE sentimail_same_client_mailbox(r.address,$2)
              )
            ORDER BY array_position($1::text[],lower(btrim(m.message_id,'<> '))),
                     m.captured_at DESC
            LIMIT 1
            """,
            identifiers,
            sender,
        )

    @staticmethod
    async def _case_conversation(
        connection: asyncpg.Connection, case_id: object, sender: str
    ) -> str | None:
        """La conversation du dossier, créée au besoin, si elle est à cette boîte."""
        conversation_id = await connection.fetchval(
            """
            INSERT INTO conversations (case_id,participant_email,status)
            VALUES ($1,$2,'awaiting_user')
            ON CONFLICT (case_id) WHERE case_id IS NOT NULL DO NOTHING
            RETURNING id::text
            """,
            case_id,
            sender,
        )
        if conversation_id is not None:
            return str(conversation_id)
        existing = await connection.fetchrow(
            """
            SELECT id::text AS id,
                   sentimail_same_client_mailbox(participant_email,$2) AS same_mailbox
            FROM conversations WHERE case_id=$1
            """,
            case_id,
            sender,
        )
        if existing is None or not existing["same_mailbox"]:
            return None
        return str(existing["id"])

    async def _queue_identity_challenge(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        message: asyncpg.Record,
        sender: str,
        replied_case: asyncpg.Record | None = None,
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

        # Rattachée au message livré qu'elle cite, la directive saura quel
        # expéditeur bloquer une fois confirmée. Sans rattachement, elle reste
        # une conversation libre.
        conversation_id = (
            await self._case_conversation(connection, replied_case["case_id"], sender)
            if replied_case is not None
            else None
        )
        if conversation_id is None:
            replied_case = None
            conversation_id = await connection.fetchval(
                """
                INSERT INTO conversations (participant_email, status)
                VALUES ($1,'awaiting_user') RETURNING id::text
                """,
                sender,
            )
        # Le courrier nomme le message visé : confirmer, c'est agir sur lui, et
        # la personne doit pouvoir reconnaître une directive qu'elle n'a pas
        # écrite.
        about = ""
        if replied_case is not None:
            objet = " ".join(str(replied_case["subject"] or "(sans objet)").split())
            about = f" à propos du message « {objet[:120]} »"
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
            f"J’ai reçu une nouvelle directive SMTP en ton nom{about}.\n\n"
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
            _json(
                {
                    "message_id": message_id,
                    "conversation_id": conversation_id,
                    "replied_case_id": (
                        str(replied_case["case_id"]) if replied_case is not None else None
                    ),
                }
            ),
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
