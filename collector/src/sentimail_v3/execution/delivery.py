from __future__ import annotations

import html
import json
import re
import uuid
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any
from urllib.parse import quote, urlencode

import aiosmtplib
import asyncpg

from sentimail_v3.conversation.action_tokens import action_token, new_nonce, token_hash
from sentimail_v3.config import Settings
from sentimail_v3.code.reference import reference
from sentimail_v3.crypto import load_key, reveal
from sentimail_v3.identity import instance_identity
from sentimail_v3.execution.delivery_state import (
    DEFERRED,
    DELIVERED,
    RELEASE_PENDING,
    UNDELIVERABLE,
    move,
)
from sentimail_v3.conversation.choice_answers import GRIS, ROUGE, render_choices
from sentimail_v3.conversation.review_notice import corps_redige
from sentimail_v3.execution.smtp_failure import is_permanent_rejection
from sentimail_v3.execution.smtp_sender import require_sender
from sentimail_v3.observation.preview import screenshot, thumbnail
from sentimail_v3.observation.smtp_utils import extract_queue_id
from sentimail_v3.code.tenancy import protected_recipient


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


# Le message est déjà livré : « livre-le-moi » n'a plus de sens ici. Restent le
# geste utile - le signaler - et la porte de sortie. Les lettres et les couleurs
# sont celles des deux autres surfaces, pour qu'un même geste s'apprenne une fois.
_FEEDBACK_CHOICES = (
    ("B", "Non sollicité", "Bloque cet expéditeur", ROUGE),
    ("C", "Autre chose", "J’explique à MAIA", GRIS),
)


def _feedback_links(settings: Settings, token: str) -> dict[str, str]:
    # Fonction synchrone sans accès pool : lit settings.action_address figé au
    # démarrage plutôt que l'identité à chaud (limite assumée, cf. rapport).
    if any(value in settings.action_address for value in ("\r", "\n")):
        raise ValueError("invalid action address")
    corps = {
        # Une phrase lue directement par directive_policy : elle dit « bloque
        # les prochains » sans qu'aucun modèle ait à l'interpréter, et se lit
        # comme une réponse que le destinataire aurait pu écrire. La séquence
        # machine reste dans l'objet, où elle est déjà.
        "B": corps_redige(
            "Ce message ne m'intéresse pas : c'est du spam. Bloque les "
            "prochains de cet expéditeur."
        ),
        # « Autre chose » n'écrit aucune décision : l'amorce invite à écrire.
        "C": corps_redige(""),
    }
    sujets = {
        "B": f"[SentiMail] Déclarer ce message non sollicité · S3-ACTION:{token}",
        "C": f"[SentiMail] Ma réponse · S3-ACTION:{token}",
    }
    # Voir review_notice : « + » n'est pas un espace dans un mailto:.
    return {
        lettre: "mailto:" + settings.action_address + "?" + urlencode(
            {"subject": sujets[lettre], "body": corps[lettre]},
            quote_via=quote,
        )
        for lettre in ("B", "C")
    }


def _feedback_mailto(settings: Settings, token: str) -> str:
    """Le seul lien de signalement, conservé pour la version en texte seul."""
    return _feedback_links(settings, token)["B"]


def append_feedback_footer(raw: bytes, settings: Settings, token: str) -> tuple[bytes, bool]:
    """Ajoute un retour SMTP visible sans modifier Reply-To de l'expéditeur."""
    root: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    if root.get_content_type() in {
        "multipart/signed",
        "application/pkcs7-mime",
        "application/x-pkcs7-mime",
    }:
        return raw, False
    liens = _feedback_links(settings, token)
    plain_footer = (
        "\n\n---\n"
        "SentiMail · Ce message est non sollicité ?\n"
        f"B · Signale-le et bloque cet expéditeur : {liens['B']}\n"
        f"C · Autre chose, tu expliques à MAIA : {liens['C']}\n"
    )
    html_footer = (
        '<div style="margin-top:24px;padding:12px;border-top:1px solid #cbd5e1;'
        'font-family:Arial,sans-serif;font-size:13px;color:#475569">'
        '<strong>SentiMail</strong> · Ce message est non sollicité ?'
        # L'échappement est fait par render_choices : le refaire ici
        # produirait des « &amp;amp; » au milieu des adresses.
        + render_choices(_FEEDBACK_CHOICES, liens)
        + "</div>"
    )
    inserted = False
    for part in root.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            value = part.get_content()
        except Exception:  # noqa: BLE001,S112 - livraison prioritaire au décor
            continue
        if not isinstance(value, str):
            continue
        preserved = {
            name: part.get(name)
            for name in ("Content-ID", "Content-Location", "Content-Language", "Content-Disposition")
            if part.get(name) is not None
        }
        if content_type == "text/html":
            if re.search(r"</body\s*>", value, flags=re.IGNORECASE):
                updated = re.sub(
                    r"</body\s*>", html_footer + "</body>", value,
                    count=1, flags=re.IGNORECASE,
                )
            else:
                updated = value + html_footer
            part.set_content(updated, subtype="html", charset="utf-8")
        else:
            part.set_content(value + plain_footer, subtype="plain", charset="utf-8")
        for name, header_value in preserved.items():
            if part.get(name) is None:
                part[name] = header_value
        inserted = True
    if not inserted:
        return raw, False
    root["X-SentiMail-Feedback"] = "smtp-action-available"
    root["X-SentiMail-Modified"] = "feedback-footer"
    return root.as_bytes(policy=policy.SMTP), True


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
    clean = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
    return f"{name}: {clean}".encode("utf-8", errors="replace")


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


def build_junk_envelope(
    raw: bytes,
    verdict: str,
    *,
    reasons: list[str],
    lessons: list[dict[str, str]],
    preview: bytes | None,
    preview_content_type: str = "image/png",
    action_address: str,
    assistant_sender: str,
    recipient: str,
    token: str | None = None,
    message_id: str = "",
) -> bytes:
    """Remplace un message classé par l'avis qui explique son classement.

    Le message d'origine n'est pas transmis. Il vient d'être jugé indésirable
    ou dangereux : livrer son texte intact lui laisserait sa force de
    persuasion, et ses liens leur pouvoir de nuire, dans la boîte même de la
    personne qu'on protège. Ce qu'elle reçoit est une photo de ce qu'il
    contenait, la raison du classement, et le moyen de le faire livrer si le
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
    sujet = str(original.get("subject") or "(sans objet)")
    expediteur = str(original.get("from") or "(expéditeur inconnu)")

    # La référence sous laquelle ce dossier se cite, la même que dans la
    # console : un message classé se rappelle comme un message retenu.
    dossier_reference = reference("M", message_id)

    from sentimail_v3.conversation.junk_notice import (
        JUNK_TOKEN_PLACEHOLDER,
        render_junk_html,
    )
    from sentimail_v3.conversation.review_notice import PREVIEW_CID

    corps_html = render_junk_html(
        {
            "subject": sujet,
            "sender": expediteur,
            "verdict": verdict,
            "reasons": reasons,
            "lessons": lessons,
            "action_address": action_address,
            "has_preview": preview is not None,
            "reference": dossier_reference,
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
        "Ce message est dangereux, je l’ai mis de côté"
        if dangereux
        else "Ce message est indésirable, je l’ai classé"
    )
    puces = "\n".join(f"- {value}" for value in reasons[:6]) or "- Un faisceau d’indices concordants."
    corps_texte = (
        f"{titre}\n\nObjet : {sujet}\nDe : {expediteur}\n\n"
        f"Pourquoi je l’ai classé :\n{puces}\n\n"
        "Le message lui-même n’est pas reproduit ici. Réponds A pour que je te "
        "le livre, B pour confirmer le classement, C pour m’expliquer autre "
        "chose.\n\n— MAIA, ton assistante SentiMail\n"
        f"Dossier {dossier_reference}\n"
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
    enveloppe["Subject"] = f"[SentiMail] {sujet}"
    for nom in ("from", "to", "cc", "date", "message-id", "reply-to"):
        valeur = original.get(nom)
        if valeur is not None:
            enveloppe["X-SentiMail-Original-" + nom.title()] = str(valeur)[:400]
    enveloppe["X-SentiMail-Modified"] = "junk-envelope"
    enveloppe.set_content(corps_texte, subtype="plain", charset="utf-8")
    enveloppe.add_alternative(corps_html, subtype="html", charset="utf-8")
    if preview:
        # La photo se montre dans le corps, elle ne s'attache pas. En pièce
        # jointe elle doublait le poids de l'avis pour un fichier que personne
        # n'ouvrait, et une photo qu'il faut ouvrir ne dit rien tant qu'on ne
        # l'a pas ouverte. L'avis d'un message retenu procède de même : la même
        # question se pose de la même façon.
        _, _, sous_type = preview_content_type.partition("/")
        enveloppe.get_payload()[-1].add_related(
            preview,
            maintype="image",
            subtype=sous_type or "png",
            cid=f"<{PREVIEW_CID}>",
            filename=f"capture-email-neutralise.{sous_type or 'png'}",
            disposition="inline",
        )
    # Le verdict est apposé par classify_header, et non à la main : c'est cet
    # en-tête, à cette graphie exacte, qui fait ranger le message en
    # indésirables côté serveur de messagerie. Une variante de casse ferait
    # arriver en boîte de réception tout ce qui vient d'être classé.
    return classify_header(
        enveloppe.as_bytes(policy=policy.SMTP),
        verdict,
        reasons=reasons,
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

    Le fail-open habituel livre l'original quand l'avis MAIA n'a pas pu partir.
    Ici il n'y a personne à qui livrer : la même adresse serait refusée de la
    même façon, et le dossier resterait « différé » indéfiniment - visible du
    seul superviseur, qui le signalerait sans que personne ne puisse le clore.
    """
    if not await move(pool, message_id, UNDELIVERABLE, error=error):
        # La transition n'a rien bougé : soit le message est ailleurs et ne
        # nous regarde pas, soit il est déjà clos et il reste peut-être des
        # attaches ouvertes derrière lui. Rejouer la clôture doit alors la
        # terminer, pas s'arrêter à mi-chemin.
        current = await pool.fetchval(
            "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
        )
        if str(current or "") != UNDELIVERABLE:
            return None
    await pool.execute(
        """
        UPDATE smtp_actions SET status='revoked'
        WHERE case_id=(SELECT id FROM delivery_cases WHERE message_id=$1::uuid)
          AND status='pending'
        """,
        message_id,
    )
    # Un avis qu'on ne réémettra jamais n'est plus une erreur en attente : le
    # laisser en « error » ferait signaler indéfiniment un dossier déjà clos.
    await pool.execute(
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
    await pool.execute(
        """
        UPDATE delivery_cases SET state='closed',updated_at=now(),
            details=details || $2::jsonb WHERE message_id=$1::uuid
        """,
        message_id,
        _json({"closed_reason": reason, "undeliverable_error": error}),
    )
    await pool.execute(
        """
        INSERT INTO audit_log(actor,action,payload)
        VALUES ('delivery','delivery.undeliverable_closed',$1::jsonb)
        """,
        _json({"message_id": message_id, "reason": reason, "error": error}),
    )
    return UNDELIVERABLE


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
        footer_inserted = False
        token: str | None = None
        # Le motif d'audit et l'origine de la décision ne doivent pas changer
        # la capacité de corriger ensuite une livraison. Toute livraison de
        # l'original propose donc le même retour SMTP, y compris après une
        # libération demandée par l'utilisateur ou une réconciliation.
        if settings.assistant_token_secret:
            participant = (
                await protected_recipient(pool, list(recipients)) or recipients[0]
            )
            feedback_action_id, token = await _ensure_feedback_action(
                connection, settings, case_id, participant, identite.action_address
            )
            if not classify_as:
                # Un message classé est remplacé par son avis, plus bas : lui
                # ajouter un pied de page serait du travail jeté.
                try:
                    raw, footer_inserted = append_feedback_footer(raw, settings, token)
                except Exception:  # noqa: BLE001 - le pied de page ne bloque jamais la livraison
                    footer_inserted = False
    if classify_as:
        # Le message classé n'est plus livré tel quel : ce qui arrive dans les
        # indésirables est l'avis qui explique le classement, avec une photo du
        # message et le moyen de le faire livrer. Le texte hostile perd ainsi sa
        # force de persuasion et ses liens leur pouvoir de nuire, dans la boîte
        # même de la personne qu'on protège.
        #
        # Hors transaction : la capture est un appel réseau au bac à sable de
        # rendu, et une transaction ouverte pendant ce temps bloquerait la ligne.
        preview: bytes | None = None
        preview_type = "image/png"
        if settings.render_sandbox_url:
            try:
                preview = await screenshot(raw, settings.render_sandbox_url)
            except Exception:  # noqa: BLE001 - sans photo, l'avis reste utile
                preview = None
            # La photo voyage maintenant dans le corps de l'avis : réduite à la
            # largeur qu'un client de messagerie affiche, elle pèse ce qu'elle
            # montre. Un échec du bac à sable laisse partir l'original.
            if preview:
                try:
                    reduite = await thumbnail(preview, settings.render_sandbox_url)
                except Exception:  # noqa: BLE001 - l'original fait l'affaire
                    reduite = None
                if reduite:
                    preview, preview_type = reduite
        try:
            raw = build_junk_envelope(
                raw,
                classify_as,
                reasons=classify_reasons or [],
                lessons=classify_lessons or [],
                preview=preview,
                preview_content_type=preview_type,
                action_address=identite.action_address,
                assistant_sender=identite.assistant_sender,
                recipient=recipients[0] if recipients else "",
                token=token,
                message_id=str(message_id),
            )
            # Le contrôle ne porte que sur ce que SentiMail compose. Le message
            # d'origine, lui, est relayé tel quel : refuser un courrier entrant
            # mal formé - un rapport de non-remise sans en-tête « From », par
            # exemple - reviendrait à le perdre, ce que la chaîne ne fait jamais.
            raw = require_sender(raw, recipients)
        except Exception:  # noqa: BLE001 - un avis raté ne fait pas perdre le message
            raw = annotate_classified(
                raw,
                classify_as,
                reasons=classify_reasons or [],
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
            _json(
                {
                    "reason": reason,
                    "user_requested": user_requested,
                    "feedback_action_id": feedback_action_id,
                    "feedback_footer_inserted": footer_inserted,
                }
            ),
        )
    return "released"


async def retry_one_release(
    pool: asyncpg.Pool[Any], settings: Settings
) -> bool:
    # Le verrou SKIP LOCKED empêche deux reprises (worker verdict, caretaker)
    # de prendre la même ligne ; le délai de grâce laisse un envoi en cours -
    # timeout SMTP de 30 s - se conclure avant qu'on ne le considère bloqué.
    async with pool.acquire() as connection, connection.transaction():
        row = await connection.fetchrow(
            """
            SELECT m.id::text, dc.details->>'release_reason' AS reason,
                   coalesce((dc.details->>'user_requested')::boolean,false)
                     AS user_requested,
                   dc.details->'final_judgment'->>'filed_as_junk' AS filed_as_junk,
                   dc.details->'junk_reasons' AS junk_reasons,
                   dc.details->'junk_lessons' AS junk_lessons
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
    )
    return True


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
        {"name": str(item.get("name") or ""), "description": str(item.get("description") or "")}
        for item in value
        if isinstance(item, dict)
    ] if isinstance(value, list) else []
