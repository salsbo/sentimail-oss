from __future__ import annotations

import json
import logging
import uuid
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formatdate
from typing import Any
from urllib.parse import quote

import aiosmtplib
import asyncpg

from sentimail_v3.code.reference import nommer_dossier, reference
from sentimail_v3.code.tenancy import protected_recipient
from sentimail_v3.config import Settings
from sentimail_v3.conversation.action_tokens import action_token, new_nonce, token_hash
from sentimail_v3.crypto import load_key, reveal
from sentimail_v3.execution.delivery_state import (
    DEFERRED,
    DELIVERED,
    HELD,
    RELEASE_PENDING,
    SUPPRESSED,
    UNDELIVERABLE,
    move,
)
from sentimail_v3.execution.header_text import header_text, une_ligne
from sentimail_v3.execution.smtp_failure import is_permanent_rejection
from sentimail_v3.execution.smtp_sender import require_sender
from sentimail_v3.identity import instance_identity
from sentimail_v3.observation.preview import screenshot, thumbnail
from sentimail_v3.observation.risk_text import (
    message_text_excerpts,
    neutralize_excerpt_links,
)
from sentimail_v3.observation.smtp_utils import extract_queue_id

logger = logging.getLogger("sentimail-v3-delivery")

# Les classements que le Code tient pour dangereux. Le juge écrit « malicious »
# (FILED_AS_JUNK traduit « dangerous ») ; la valeur brute est acceptée aussi,
# au cas où un appelant passerait la classification plutôt que sa traduction.
DANGEROUS_JUNK = frozenset({"malicious", "dangerous"})


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


async def _ensure_feedback_action(
    connection: asyncpg.Connection,
    settings: Settings,
    case_id: object,
    participant: str,
    action_address: str,
) -> tuple[str, str]:
    conversation_id = await connection.fetchval(
        "SELECT id::text FROM conversations WHERE case_id=$1 LIMIT 1",
        case_id,
    )
    if conversation_id is None:
        conversation_id = await connection.fetchval(
            """
            INSERT INTO conversations (case_id,participant_email,status)
            VALUES ($1,$2,'awaiting_user')
            ON CONFLICT (case_id) WHERE case_id IS NOT NULL DO NOTHING
            RETURNING id::text
            """,
            case_id,
            participant.casefold(),
        )
        if conversation_id is None:
            conversation_id = await connection.fetchval(
                "SELECT id::text FROM conversations WHERE case_id=$1 LIMIT 1",
                case_id,
            )
    existing = await connection.fetchrow(
        """
        SELECT id::text AS id, context->>'nonce' AS nonce FROM smtp_actions
        WHERE case_id=$1 AND action='report_spam' AND status='pending'
          AND context->>'purpose'='delivered_feedback'
        ORDER BY issued_at DESC LIMIT 1
        """,
        case_id,
    )
    action_id = existing["id"] if existing is not None else None
    # L'aléa est fixé à la création : régénéré à chaque livraison, il
    # invaliderait le jeton d'un pied de page déjà envoyé.
    nonce = existing["nonce"] if existing is not None else new_nonce()
    if action_id is None:
        action_id = str(uuid.uuid4())
        await connection.execute(
            """
            INSERT INTO smtp_actions (
                id,case_id,action,token_hash,reply_address,expires_at,context
            ) VALUES ($1::uuid,$2,'report_spam',NULL,$3,
                      now()+interval '180 days',$4::jsonb)
            """,
            action_id,
            case_id,
            action_address,
            _json(
                {
                    "conversation_id": conversation_id,
                    "purpose": "delivered_feedback",
                    "nonce": nonce,
                    "binding": True,
                }
            ),
        )
    token = action_token(settings.assistant_token_secret, action_id, nonce)
    await connection.execute(
        "UPDATE smtp_actions SET token_hash=$2 WHERE id=$1::uuid",
        action_id,
        token_hash(token),
    )
    return action_id, token


def _header_line(name: str, value: str) -> bytes:
    """Un en-tête sûr : pas de saut de ligne injecté par une valeur hostile."""
    return f"{name}: {une_ligne(value)}".encode("utf-8", errors="replace")


def classify_header(
    raw: bytes,
    verdict: str,
    *,
    reasons: list[str] | None = None,
    techniques: list[str] | None = None,
) -> bytes:
    """Range un message en indésirables, et dit pourquoi.

    Le tri appartient à la boîte du destinataire, pas au relais : Dovecot range
    en Junk ce qui porte X-Sentimail-Verdict. On y ajoute, sans toucher au corps
    du message, ce qui a motivé le classement et la technique reconnue : un
    message classé sur certitude n'a plus besoin qu'on demande l'avis, mais il
    ne doit pas pour autant rester muet sur la raison.

    Les lignes sont préfixées au bloc d'en-têtes existant, séparées par une
    seule fin de ligne. Un séparateur complet clôturerait le bloc aussitôt
    ouvert : From, Subject et Content-Type basculeraient dans le corps, le
    message perdrait son objet et son expéditeur, et son HTML cesserait d'être
    interprété - il arriverait en texte brut.
    """
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw[:200_000] else b"\n\n"
    end = separator[: len(separator) // 2]
    lines = [_header_line("X-Sentimail-Verdict", verdict)]
    if reasons:
        lines.append(
            _header_line("X-Sentimail-Classification-Reason", " ; ".join(reasons[:5]))
        )
    if techniques:
        lines.append(
            _header_line("X-Sentimail-Attack-Techniques", ", ".join(techniques[:8]))
        )
    return end.join(lines) + end + raw


def annotate_classified(
    raw: bytes,
    verdict: str,
    *,
    reasons: list[str],
    lessons: list[dict[str, str]],
) -> bytes:
    """Ajoute les en-têtes ET un bandeau visible en tête du message classé.

    Le bandeau est préfixé dans les parties texte et HTML, pour qu'en ouvrant
    un indésirable on lise d'abord pourquoi il y est. L'opération peut échouer
    sur un message malformé - un spam l'est souvent : on retombe alors sur les
    seuls en-têtes, la livraison n'est jamais bloquée pour un bandeau.
    """
    codes = [str(lesson.get("name") or "") for lesson in lessons]
    base = classify_header(raw, verdict, reasons=reasons, techniques=codes)
    try:
        from email import policy
        from email.parser import BytesParser

        message = BytesParser(policy=policy.default).parsebytes(base)
        titre = (
            "⚠️ SentiMail a classé ce message en indésirable"
            if verdict != "malicious"
            else "⛔ SentiMail a bloqué ce message : il est dangereux"
        )
        puces = list(reasons[:5]) + [
            f"Technique reconnue : {lesson['name']} — {lesson['description']}"
            for lesson in lessons[:6]
        ]
        texte = titre + "\n" + "\n".join(f"- {p}" for p in puces) + "\n\n" + (
            "———————————————————————————\n\n"
        )
        import html as _html

        html_banner = (
            '<div style="font-family:Arial,sans-serif;border:2px solid #ea580c;'
            'background:#fff7ed;border-radius:8px;padding:12px;margin-bottom:14px">'
            f"<strong>{_html.escape(titre)}</strong><ul style=\"margin:8px 0\">"
            + "".join(f"<li>{_html.escape(str(p))}</li>" for p in puces)
            + "</ul></div>"
        )
        annotated = False
        for part in message.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            try:
                if ctype == "text/plain":
                    part.set_content(
                        texte + str(part.get_content()),
                        subtype="plain",
                        charset="utf-8",
                    )
                    annotated = True
                elif ctype == "text/html":
                    body = str(part.get_content())
                    marker = "<body"
                    if marker in body.lower():
                        idx = body.lower().index(marker)
                        close = body.index(">", idx) + 1
                        body = body[:close] + html_banner + body[close:]
                    else:
                        body = html_banner + body
                    part.set_content(body, subtype="html", charset="utf-8")
                    annotated = True
            except (LookupError, ValueError):
                continue
        if annotated:
            return message.as_bytes()
    except Exception:  # noqa: BLE001 - un bandeau ne bloque jamais la livraison
        pass
    return base


def reasons_or_identity(
    reasons: list[str], identity_card: dict[str, object] | None
) -> list[str]:
    """Les motifs courts, sinon les lignes d'identité gardées pour l'audit.

    L'avis normal n'affiche plus de carte. L'en-tête de classement et le
    bandeau fail-soft restent toutefois lus par une machine ou par un audit :
    ils reprennent les lignes de la carte à défaut de motif, pour qu'un
    classement ne soit jamais muet sur son pourquoi.
    """
    from sentimail_v3.code.plain_words import identity_lines

    return list(reasons) or identity_lines(identity_card)


def build_junk_envelope(
    raw: bytes,
    verdict: str,
    *,
    reasons: list[str],
    lessons: list[dict[str, str]],
    preview: bytes | None,
    preview_content_type: str = "image/png",
    identity_card: dict[str, object] | None = None,
    full_preview: bytes | None = None,
    action_address: str,
    assistant_sender: str,
    recipient: str,
    token: str | None = None,
    message_id: str = "",
    envelope_from: str | None = None,
) -> bytes:
    """Remplace un message classé par l'avis qui explique son classement.

    Le message d'origine n'est pas transmis. Il vient d'être jugé indésirable
    ou dangereux : livrer son texte intact lui laisserait sa force de
    persuasion, et ses liens leur pouvoir de nuire, dans la boîte même de la
    personne qu'on protège. Ce qu'elle reçoit tient à l'identité observée
    (adresse affichée et adresse d'enveloppe), l'objet, une photo inerte du
    message - miniature dans le corps, capture pleine jointe -, trois motifs,
    trois courts extraits inertes et le moyen de faire livrer le message si le
    classement est faux.

    Les en-têtes d'origine sont conservés en X-SentiMail-Original-* : ils
    servent l'audit et permettent de retrouver le dossier, sans rien rendre
    d'actionnable.
    """
    # Un avis sans expéditeur arrive de personne : le client de messagerie
    # n'affiche aucun nom et le bouton « Répondre » ne mène nulle part. Mieux
    # vaut échouer ici - l'appelant se rabat alors sur l'annotation du message
    # d'origine - que produire un courrier sans retour possible.
    for nom, valeur in (
        ("expéditeur de l'avis", assistant_sender),
        ("destinataire", recipient),
    ):
        if not str(valeur or "").strip():
            raise ValueError(f"{nom} manquant : l'avis serait sans retour")
    original: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    # Les en-têtes d'origine se lisent sur une ligne. Un mot encodé peut se
    # décoder en saut de ligne : la bibliothèque refuse alors de reposer
    # l'objet, et refuse même de lire une adresse. L'enveloppe échouait, et
    # le message partait annoté, liens actifs.
    sujet = header_text(original, "subject") or "(sans objet)"
    expediteur = header_text(original, "from") or "(expéditeur inconnu)"
    try:
        from sentimail_v3.observation.dossier.hooks.visible_text import (
            visible_html_text,
        )
        from sentimail_v3.observation.parser import parse_message

        parsed = parse_message(raw).message
        excerpt_source = str(parsed.get("body_text") or "")
        if not excerpt_source:
            excerpt_source = visible_html_text(str(parsed.get("body_html") or ""))
        message_excerpts = message_text_excerpts(excerpt_source)
    except Exception:  # noqa: BLE001 - l'extrait ne bloque jamais le classement
        message_excerpts = []

    # La référence sous laquelle ce dossier se cite, la même que dans la
    # console : un message classé se rappelle comme un message retenu.
    dossier_reference = reference("M", message_id)

    from sentimail_v3.code.plain_words import sender_lines
    from sentimail_v3.conversation.junk_notice import (
        JUNK_TOKEN_PLACEHOLDER,
        render_junk_html,
    )

    # L'adresse affichée se recopie librement ; l'enveloppe est celle que le
    # serveur d'envoi a annoncée. Les deux, l'une sous l'autre, montrent l'écart.
    adresses = sender_lines(expediteur, envelope_from, header_text(original, "reply-to"))

    corps_html = render_junk_html(
        {
            "subject": sujet,
            "sender": expediteur,
            "sender_lines": adresses,
            "verdict": verdict,
            "reasons": reasons,
            "message_excerpts": message_excerpts,
            "action_address": action_address,
            "reference": dossier_reference,
            "has_preview": preview is not None,
            "has_full_preview": preview is not None and full_preview is not None,
        }
    )
    # Le marqueur est ce qui rattache une réponse à son dossier. Sans jeton, on
    # le retire plutôt que de l'afficher : un lien inerte vaut mieux qu'une
    # ligne interne offerte à la lecture du destinataire.
    if token:
        corps_html = corps_html.replace(
            quote(JUNK_TOKEN_PLACEHOLDER), quote(f"S3-ACTION:{token}")
        ).replace(JUNK_TOKEN_PLACEHOLDER, f"S3-ACTION:{token}")
    else:
        # Le marqueur vit dans l'objet du mailto, précédé d'un séparateur
        # « · » : on retire les deux ensemble pour laisser un objet propre.
        corps_html = corps_html.replace(
            quote(" · ") + quote(JUNK_TOKEN_PLACEHOLDER), ""
        ).replace(quote(JUNK_TOKEN_PLACEHOLDER), "").replace(JUNK_TOKEN_PLACEHOLDER, "")

    dangereux = verdict in {"dangerous", "malicious"}
    titre = (
        "Dangereux - classé dans Indésirables"
        if dangereux
        else "Classé dans Indésirables"
    )
    puces = "\n".join(f"- {value.rstrip('. ')}" for value in reasons[:3])
    puces = puces or "- Analyse : plusieurs indices concordants"
    extraits = "\n".join(
        f"- {neutralize_excerpt_links(value)}" for value in message_excerpts
    )
    corps_texte = (
        f"{titre}\n\nObjet : {sujet}\n"
        + "\n".join(adresses)
        + "\n\n"
        + (
            "L’image jointe est une photo inerte du message : rien n’y est "
            "cliquable.\n\n"
            if preview
            else ""
        )
        + f"Pourquoi\n{puces}\n\n"
        + (f"Extraits du message\n{extraits}\n\n" if extraits else "")
        + "Message conservé\nA - Livrer dans ma boîte\n"
        "Bouton indisponible : répondre A\n\n"
        f"{dossier_reference + ' - ' if dossier_reference else ''}MAIA\n"
    )

    enveloppe = EmailMessage()
    # L'avis vient de MAIA, jamais de l'expéditeur classé : reprendre son
    # adresse ferait passer l'avis pour un message de lui. Répondre mène à
    # l'adresse d'action, pour que le bouton du client serve à quelque chose.
    enveloppe["From"] = assistant_sender
    enveloppe["To"] = recipient
    enveloppe["Reply-To"] = action_address
    # L'objet reste reconnaissable : c'est par lui que le destinataire retrouve
    # un message qu'il attendait et qu'on a classé par erreur.
    enveloppe["Subject"] = f"[SentiMail] Indésirable - {sujet}"
    # La date de cet avis, non celle du message classé : celle-ci est reprise
    # plus bas dans les en-têtes X-SentiMail-Original-*. Sans `Date`, un client
    # qui trie range l'avis hors de la liste que l'œil parcourt.
    enveloppe["Date"] = formatdate(localtime=True)
    for nom in ("from", "to", "cc", "date", "message-id", "reply-to"):
        valeur = header_text(original, nom)
        if valeur is not None:
            enveloppe["X-SentiMail-Original-" + nom.title()] = valeur[:400]
    enveloppe["X-SentiMail-Modified"] = "junk-envelope"
    enveloppe.set_content(corps_texte, subtype="plain", charset="utf-8")
    enveloppe.add_alternative(corps_html, subtype="html", charset="utf-8")
    if preview:
        # La miniature se montre dans le corps, pour reconnaître le message.
        from sentimail_v3.conversation.review_notice import PREVIEW_CID

        _, _, sous_type = preview_content_type.partition("/")
        enveloppe.get_payload()[-1].add_related(
            preview,
            maintype="image",
            subtype=sous_type or "png",
            cid=f"<{PREVIEW_CID}>",
            filename=f"capture-email-neutralise.{sous_type or 'png'}",
            disposition="inline",
        )
    if preview and full_preview:
        # La capture pleine, pour lire en grand : une image rattachée au corps
        # ne s'agrandit pas dans tous les clients.
        enveloppe.add_attachment(
            full_preview,
            maintype="image",
            subtype="png",
            filename="message-en-grand.png",
        )
    # Le verdict est apposé par classify_header, et non à la main : c'est cet
    # en-tête, à cette graphie exacte, qui fait ranger le message en
    # indésirables côté serveur de messagerie. Une variante de casse ferait
    # arriver en boîte de réception tout ce qui vient d'être classé.
    # La carte n'est plus dans le corps compact. Elle reste le dernier repli de
    # l'en-tête lu par les règles de tri et par l'audit.
    return classify_header(
        enveloppe.as_bytes(policy=policy.SMTP),
        verdict,
        reasons=reasons_or_identity(reasons, identity_card),
        techniques=[str(lesson.get("name") or "") for lesson in lessons],
    )


async def close_undeliverable_message(
    pool: asyncpg.Pool[Any],
    message_id: str,
    *,
    reason: str,
    error: str | None = None,
) -> str | None:
    """Ferme un dossier dont le relais refuse définitivement le destinataire.

    Le secours habituel livre l'original, ou le retient s'il est dangereux,
    quand l'avis MAIA n'a pas pu partir.
    Ici il n'y a personne à qui livrer : la même adresse serait refusée de la
    même façon, et le dossier resterait « différé » indéfiniment - visible du
    seul superviseur, qui le signalerait sans que personne ne puisse le clore.
    """
    async with pool.acquire() as connection, connection.transaction():
        if not await move(connection, message_id, UNDELIVERABLE, error=error):
            # La transition n'a rien bougé : soit le message est ailleurs et ne
            # nous regarde pas, soit il est déjà clos et il reste peut-être des
            # attaches ouvertes derrière lui. Rejouer la clôture doit alors la
            # terminer, pas s'arrêter à mi-chemin.
            current = await connection.fetchval(
                "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
            )
            if str(current or "") != UNDELIVERABLE:
                return None
        await connection.execute(
            """
            UPDATE smtp_actions SET status='revoked'
            WHERE case_id=(SELECT id FROM delivery_cases WHERE message_id=$1::uuid)
              AND status='pending'
            """,
            message_id,
        )
        # Un avis qu'on ne réémettra jamais n'est plus une erreur en attente : le
        # laisser en « error » ferait signaler indéfiniment un dossier déjà clos.
        await connection.execute(
            """
            UPDATE assistant_outbox SET status=$2
            WHERE status IN ('pending','error')
              AND action_id IN (
                  SELECT sa.id FROM smtp_actions sa
                  JOIN delivery_cases dc ON dc.id=sa.case_id
                  WHERE dc.message_id=$1::uuid
              )
            """,
            message_id,
            UNDELIVERABLE,
        )
        await connection.execute(
            """
            UPDATE delivery_cases SET state='closed',updated_at=now(),
                details=details || $2::jsonb WHERE message_id=$1::uuid
            """,
            message_id,
            _json({"closed_reason": reason, "undeliverable_error": error}),
        )
        await connection.execute(
            """
            INSERT INTO audit_log(actor,action,payload)
            VALUES ('delivery','delivery.undeliverable_closed',$1::jsonb)
            """,
            _json({"message_id": message_id, "reason": reason, "error": error}),
        )
    return UNDELIVERABLE


async def suppress_original(
    pool: asyncpg.Pool[Any], message_id: str, *, reason: str
) -> str:
    """Conclut un message visé par une règle B, sans produire aucun courrier.

    Le silence SMTP n'est pas un silence d'exploitation : message, dossier,
    événement et audit sont écrits dans la même transaction. Une reprise voit
    l'état terminal et ne peut donc ni notifier ni livrer le message.
    """
    async with pool.acquire() as connection, connection.transaction():
        row = await connection.fetchrow(
            """
            SELECT m.delivery_status,dc.id AS case_id
            FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
            WHERE m.id=$1::uuid FOR UPDATE OF m,dc
            """,
            message_id,
        )
        if row is None:
            raise RuntimeError("message or delivery case not found")
        if row["delivery_status"] == SUPPRESSED:
            return "already_suppressed"
        if not await move(connection, message_id, SUPPRESSED):
            return "already_terminal"
        details = {
            "suppression_reason": reason,
            "smtp_attempted": False,
            "source": "authenticated_sender_policy",
        }
        await connection.execute(
            """
            UPDATE delivery_cases SET state='policy_suppressed',
                original_delivery_allowed=false,binding=true,updated_at=now(),
                details=details || $2::jsonb WHERE id=$1
            """,
            row["case_id"],
            _json(details),
        )
        await connection.execute(
            """
            INSERT INTO delivery_events(case_id,event_type,details)
            VALUES ($1,'policy_suppressed',$2::jsonb) ON CONFLICT DO NOTHING
            """,
            row["case_id"],
            _json(details),
        )
        await connection.execute(
            """
            INSERT INTO audit_log(actor,action,payload)
            VALUES ('delivery','delivery.policy_suppressed',$1::jsonb)
            """,
            _json({"message_id": message_id, **details}),
        )
    return "suppressed"


async def release_original(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    message_id: str,
    *,
    reason: str,
    user_requested: bool = False,
    classify_as: str | None = None,
    classify_reasons: list[str] | None = None,
    classify_lessons: list[dict[str, str]] | None = None,
    classify_identity: dict[str, object] | None = None,
    resuming: bool = False,
) -> str:
    """Livre l'original, une fois.

    L'envoi SMTP a lieu hors de la transaction qui l'annonce : deux acteurs
    pourraient donc viser le même message. Le verrou `FOR UPDATE` les sérialise,
    et honorer le retour de `move()` fait abandonner le second - `move` vers
    release_pending échoue quand l'état y est déjà. Une reprise (`resuming`)
    force au contraire l'envoi d'un message resté bloqué, mais seulement après
    le délai de grâce appliqué par `retry_one_release`, pour ne pas doubler un
    envoi encore en cours.
    """
    identite = await instance_identity(pool, settings)
    async with pool.acquire() as connection, connection.transaction():
        row = await connection.fetchrow(
            """
            SELECT m.delivery_status, m.raw_eml, m.envelope_from,
                   m.envelope_recipients, dc.id AS case_id,
                   c.participant_email
            FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
            LEFT JOIN conversations c ON c.case_id=dc.id
            WHERE m.id=$1::uuid FOR UPDATE OF m,dc
            """,
            message_id,
        )
        if row is None:
            raise RuntimeError("message or delivery case not found")
        if row["delivery_status"] == "delivered":
            return "already_delivered"
        if row["raw_eml"] is None:
            # La rétention n'efface jamais un message encore en attente de
            # décision. Si l'original a malgré tout disparu, on refuse sans
            # muter l'état plutôt que de prétendre livrer.
            raise RuntimeError("original content is no longer available")
        moved = await move(connection, message_id, RELEASE_PENDING)
        if not moved and not resuming:
            # Un autre acteur a déjà pris ce message en charge (il est passé en
            # release_pending) : renvoyer maintenant le doublerait.
            return "already_in_flight"
        if not moved and resuming:
            # Reprise d'un release_pending resté bloqué : la transition sur
            # place n'est pas dans ORIGINS, on la force en réhorodatant.
            await connection.execute(
                "UPDATE messages SET delivery_status=$2 WHERE id=$1::uuid",
                message_id,
                RELEASE_PENDING,
            )
        await connection.execute(
            """
            UPDATE delivery_cases SET state='release_requested',
                original_delivery_allowed=true, binding=true, updated_at=now(),
                details=details || $2::jsonb WHERE message_id=$1::uuid
            """,
            message_id,
            _json({"release_reason": reason, "user_requested": user_requested}),
        )
        raw = reveal(row["raw_eml"], load_key(settings.raw_eml_key_file)) or b""
        sender = str(row["envelope_from"])
        recipients = list(row["envelope_recipients"])
        if len(recipients) != 1:
            participant = str(row["participant_email"] or "").casefold()
            matching = [value for value in recipients if value.casefold() == participant]
            if len(matching) != 1:
                raise RuntimeError("multi-recipient delivery case is not isolated")
            recipients = matching
        if any("\r" in value or "\n" in value for value in [sender, *recipients]):
            raise ValueError("invalid newline in SMTP envelope address")
        case_id = row["case_id"]
        feedback_action_id: str | None = None
        token: str | None = None
        # Un message livré part tel quel, sans pied de page. Écrit dans le
        # corps, le pied de page repartait chez l'expéditeur dans chaque
        # réponse citée - boutons et jetons compris - et s'empilait d'un
        # échange à l'autre sous les yeux du correspondant. Pour signaler un
        # message livré, on écrit à MAIA en réponse à ce message.
        #
        # Seul l'avis qui remplace un message classé porte encore un jeton :
        # son bouton A récupère un faux positif, et personne ne répond à un
        # avis en citant l'expéditeur classé.
        if settings.assistant_token_secret and classify_as:
            participant = (
                await protected_recipient(connection, list(recipients)) or recipients[0]
            )
            feedback_action_id, token = await _ensure_feedback_action(
                connection, settings, case_id, participant, identite.action_address
            )
    # Ce qui est parti dans Indésirables : l'enveloppe neutralisée, ou, faute
    # de mieux, l'original annoté. L'événement de livraison le dit.
    junk_envelope: str | None = None
    envelope_error: str | None = None
    if classify_as:
        # Le message classé n'est plus livré tel quel. L'avis porte l'identité
        # (adresse affichée et enveloppe), l'objet, une photo inerte, trois
        # motifs, trois extraits textuels inertes et le moyen de récupérer un
        # faux positif.
        #
        # Hors transaction : la capture est un appel réseau au bac à sable de
        # rendu, et une transaction ouverte pendant ce temps bloquerait la ligne.
        preview: bytes | None = None
        preview_type = "image/png"
        capture_pleine: bytes | None = None
        if settings.render_sandbox_url:
            try:
                preview = await screenshot(raw, settings.render_sandbox_url)
            except Exception:  # noqa: BLE001 - sans photo, l'avis reste utile
                preview = None
            if preview:
                try:
                    reduite = await thumbnail(preview, settings.render_sandbox_url)
                except Exception:  # noqa: BLE001 - l'original fait l'affaire
                    reduite = None
                if reduite:
                    capture_pleine = preview
                    preview, preview_type = reduite
        try:
            raw = build_junk_envelope(
                raw,
                classify_as,
                reasons=classify_reasons or [],
                lessons=classify_lessons or [],
                identity_card=classify_identity,
                preview=preview,
                preview_content_type=preview_type,
                full_preview=capture_pleine,
                action_address=identite.action_address,
                assistant_sender=identite.assistant_sender,
                recipient=recipients[0] if recipients else "",
                token=token,
                message_id=str(message_id),
                envelope_from=row["envelope_from"],
            )
            # Le contrôle ne porte que sur ce que SentiMail compose. Le message
            # d'origine, lui, est relayé tel quel : refuser un courrier entrant
            # mal formé - un rapport de non-remise sans en-tête « From », par
            # exemple - reviendrait à le perdre, ce que la chaîne ne fait jamais.
            raw = require_sender(raw, recipients)
            junk_envelope = "neutralized"
        except Exception as exc:  # noqa: BLE001 - un avis raté ne fait pas perdre le message
            # Le verdict n'est pas retouché ici : classify_as, le jugement en
            # base (dc.details->final_judgment) et la décision 'junk' restent
            # ce qu'ils étaient. Ce qui échoue, c'est la composition de
            # l'enveloppe qui devait exécuter cet ordre - pas l'ordre lui-même.
            # Un message que le Code tient pour dangereux n'est donc pas livré
            # intact : l'exécution est différée, pas annulée ; elle reprend
            # quand un exploitant relance release_original avec le même
            # classify_as. Un indésirable ordinaire part annoté, mais le repli
            # se dit.
            if classify_as in DANGEROUS_JUNK:
                return await _hold_unfiled_dangerous(
                    pool, message_id, case_id, classify_as, exc
                )
            junk_envelope = "annotated_original"
            envelope_error = type(exc).__name__
            # Le repli n'a ni carte ni mise en forme : il reprend en toutes
            # lettres ce que la carte aurait montré, sinon le bandeau
            # annoncerait un classement sans dire lequel.
            raw = annotate_classified(
                raw,
                classify_as,
                reasons=reasons_or_identity(classify_reasons or [], classify_identity),
                lessons=classify_lessons or [],
            )
    try:
        send_result = await aiosmtplib.send(
            raw,
            sender=sender,
            recipients=recipients,
            hostname=settings.relay_host,
            port=settings.relay_port,
            start_tls=False,
            timeout=30,
        )
        smtp_queue_id = extract_queue_id(send_result)
    except Exception as exc:
        # Différer suppose qu'une prochaine tentative puisse aboutir. Quand le
        # relais a refusé l'adresse elle-même, aucune ne le pourra : le dossier
        # se conclut ici, au lieu de rester « différé » à vie.
        if is_permanent_rejection(exc):
            await close_undeliverable_message(
                pool,
                message_id,
                reason="original_recipient_rejected",
                error=str(exc)[:2000],
            )
        else:
            await move(pool, message_id, DEFERRED, error=str(exc)[:2000])
        raise
    event_type = "original_released" if user_requested else "original_delivered"
    state = "original_released" if user_requested else "original_delivered"
    if classify_as:
        event_type = state = "original_filed_as_junk"
    event_details: dict[str, object] = {
        "reason": reason,
        "user_requested": user_requested,
        "feedback_action_id": feedback_action_id,
        # Clé gardée pour l'historique des dossiers : aucun pied de page
        # n'est plus ajouté.
        "feedback_footer_inserted": False,
    }
    if classify_as:
        # Le repli reste une livraison en Indésirables : même événement, mais
        # il se distingue d'une enveloppe neutralisée, et le superviseur le compte.
        event_details["junk_envelope"] = junk_envelope
        if envelope_error is not None:
            event_details["junk_envelope_error"] = envelope_error
    async with pool.acquire() as connection, connection.transaction():
        await move(connection, message_id, DELIVERED)
        await connection.execute(
            """
            UPDATE delivery_cases SET state=$2,original_delivery_allowed=true,
                binding=true,updated_at=now() WHERE id=$1
            """,
            case_id,
            state,
        )
        await connection.execute(
            """
            INSERT INTO delivery_events (case_id,event_type,smtp_queue_id,details)
            VALUES ($1,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING
            """,
            case_id,
            event_type,
            smtp_queue_id,
            _json(event_details),
        )
        if envelope_error is not None:
            await connection.execute(
                """
                INSERT INTO audit_log(actor,action,payload)
                VALUES ('delivery','delivery.junk_envelope_fallback',$1::jsonb)
                """,
                _json(
                    {
                        "message_id": message_id,
                        "classify_as": classify_as,
                        "error_type": envelope_error,
                    }
                ),
            )
    if envelope_error is not None:
        _log(
            "delivery.junk_envelope_fallback",
            message_id=message_id,
            classify_as=classify_as,
            error=envelope_error,
        )
    return "released"


async def _hold_unfiled_dangerous(
    pool: asyncpg.Pool[Any],
    message_id: str,
    case_id: object,
    classify_as: str,
    error: Exception,
) -> str:
    """Remet à la retenue un dangereux dont l'enveloppe n'a pas pu être composée.

    Rien n'est envoyé. L'état du dossier reste 'release_requested', posé par
    la première transaction de release_original, et c'est voulu : ne pas le
    « corriger ». Ainsi la reprise des envois (qui veut release_pending ou
    deferred) et le réconciliateur des avis (qui veut review_notice_pending
    ou awaiting_reply) l'ignorent tous deux ; le rapport d'entretien le
    compte en retenue sans avis, le superviseur en retenue fermée. Après
    correctif, l'exploitant relance release_original avec le même
    classify_as : le message repart de held.
    """
    async with pool.acquire() as connection, connection.transaction():
        moved = await move(connection, message_id, HELD)
        await connection.execute(
            """
            UPDATE delivery_cases SET original_delivery_allowed=false,
                updated_at=now(), details=details || $2::jsonb
            WHERE id=$1
            """,
            case_id,
            _json(
                {
                    "review_guard": "fail_closed",
                    "review_guard_reason": "junk_envelope_failed",
                    "review_guard_error": type(error).__name__,
                    "unfiled_classification": classify_as,
                }
            ),
        )
        await connection.execute(
            """
            INSERT INTO audit_log(actor,action,payload)
            VALUES ('delivery','delivery.junk_envelope_failed_held',$1::jsonb)
            """,
            _json(
                {
                    "message_id": message_id,
                    "classify_as": classify_as,
                    "error_type": type(error).__name__,
                    "moved": moved,
                }
            ),
        )
    _log(
        "delivery.junk_envelope_failed_held",
        message_id=message_id,
        classify_as=classify_as,
        error=type(error).__name__,
        moved=moved,
    )
    return "held_envelope_failed"


async def retry_one_release(
    pool: asyncpg.Pool[Any], settings: Settings
) -> bool:
    # Le verrou SKIP LOCKED empêche deux reprises (worker verdict, caretaker)
    # de prendre la même ligne ; le délai de grâce laisse un envoi en cours -
    # timeout SMTP de 30 s - se conclure avant qu'on ne le considère bloqué.
    #
    # Le secours d'un indésirable n'a pas de filed_as_junk dans le jugement
    # (décision ask_user), et le jugement ne se retouche pas : sans la clé
    # posée par le secours, une reprise différée le renverrait en clair. La
    # route n'est pas réévaluée à la reprise : elle a été décidée au secours.
    async with pool.acquire() as connection, connection.transaction():
        row = await connection.fetchrow(
            """
            SELECT m.id::text, dc.details->>'release_reason' AS reason,
                   coalesce((dc.details->>'user_requested')::boolean,false)
                     AS user_requested,
                   coalesce(
                       dc.details->'final_judgment'->>'filed_as_junk',
                       dc.details->>'fail_open_classify_as'
                   ) AS filed_as_junk,
                   dc.details->'junk_reasons' AS junk_reasons,
                   dc.details->'junk_lessons' AS junk_lessons,
                   dc.details->'junk_identity' AS junk_identity
            FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
            WHERE m.delivery_status IN ('release_pending','deferred')
              AND dc.state='release_requested' AND m.delivery_attempts < 10
              AND dc.updated_at < now() - interval '90 seconds'
            ORDER BY dc.updated_at
            FOR UPDATE OF m SKIP LOCKED
            LIMIT 1
            """
        )
        if row is None:
            return False
        # Réserver la ligne pour cette reprise : réhorodater le dossier sous le
        # verrou empêche une seconde reprise de la resélectionner sitôt le
        # verrou levé (le délai de grâce se calcule sur dc.updated_at).
        await connection.execute(
            "UPDATE delivery_cases SET updated_at=now() WHERE message_id=$1::uuid",
            str(row["id"]),
        )
    await release_original(
        pool,
        settings,
        str(row["id"]),
        reason=str(row["reason"] or "retry"),
        user_requested=bool(row["user_requested"]),
        resuming=True,
        # Sans cela, une reprise transforme un message classé en message
        # ordinaire : il repart sans marque et atterrit en boîte de réception.
        classify_as=str(row["filed_as_junk"]) if row["filed_as_junk"] else None,
        classify_reasons=_json_list(row["junk_reasons"]),
        classify_lessons=_json_dicts(row["junk_lessons"]),
        classify_identity=_json_dict(row["junk_identity"]),
    )
    return True


def _json_dict(value: object) -> dict[str, object] | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    return dict(value) if isinstance(value, dict) and value else None


def _json_list(value: object) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _json_dicts(value: object) -> list[dict[str, str]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return [
        {
            "name": str(item.get("name") or ""),
            "description": str(item.get("description") or ""),
            # Le conseil est ce que l'avis montre d'une leçon : une reprise
            # sans lui renverrait un avis muet sur ce qu'il faut faire.
            "advice": str(item.get("advice") or ""),
        }
        for item in value
        if isinstance(item, dict)
    ] if isinstance(value, list) else []
