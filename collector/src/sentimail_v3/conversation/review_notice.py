"""La fiche de décision que MAIA envoie pour un message retenu (V2).

Un bouton de courrier ne peut qu'ouvrir une réponse. Les choix A et B portent
donc une phrase explicite que les règles locales comprennent sans modèle.

Le jeton d'action n'existe pas encore quand cette page est écrite : il est créé
à l'expédition. Un marqueur en tient la place, remplacé au moment de l'envoi -
ce qui a l'avantage de ne jamais écrire le jeton en base.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from zoneinfo import ZoneInfo

from sentimail_v3.conversation.choice_answers import render_choice_cards
from sentimail_v3.conversation.choice_registry import (
    choice_presentations,
    response_body,
    response_links,
)
from sentimail_v3.conversation.mail_layout import (
    FONT_MONO,
    bullets_block,
    excerpts_block,
    footer,
    headline,
    meta_block,
    status_pill,
    wrap_shell,
)
from sentimail_v3.observation.risk_text import neutralize_excerpt_links  # noqa: F401

ACTION_TOKEN_PLACEHOLDER = "S3-ACTION-TOKEN-PLACEHOLDER"

# L'identifiant sous lequel la miniature du message est rattachée au corps.
PREVIEW_CID = "capture-email-neutralisee"

# L'objet du message de réponse porte la séquence machine.
SUJET_REPONSE = f"Re: [SentiMail] Ma réponse · {ACTION_TOKEN_PLACEHOLDER}"

# Compatibilité pour les autres gabarits : la construction vit dans le registre.
corps_redige = response_body

_PARIS = ZoneInfo("Europe/Paris")

# Pastilles d'état par niveau : (libellé, couleur texte, couleur fond).
_TAGS = {
    "danger": ("DANGEREUX · MESSAGE RETENU", "#991b1b", "#fee2e2"),
    "doute": ("ACTION REQUISE · MESSAGE RETENU", "#9a3412", "#ffedd5"),
    "sain": ("CONFIRMATION · MESSAGE RETENU", "#166534", "#dcfce7"),
}

_HEADLINE_DEFAUT = (
    "J'ai retenu ce message car je ne peux pas trancher seule. "
    "Dis-moi quoi en faire."
)


def choice_links(action_address: str) -> dict[str, str]:
    """Les trois réponses possibles, prêtes à partir."""
    return response_links(action_address, SUJET_REPONSE, "review")


def _boutons(action_address: str) -> str:
    """Les trois réponses V2 sur une ligne."""
    choix = [choice.render_tuple() for choice in choice_presentations("review")]
    return render_choice_cards(choix, choice_links(action_address))


def sender_block(lignes: object) -> str:
    """Nom et adresse affichés, puis adresse réelle, une ligne chacun.

    Une ligne « différente » passe en rouge : c'est l'écart à repérer d'un coup d'œil.
    """
    if not isinstance(lignes, list) or not lignes:
        return ""
    rangs = []
    for ligne in lignes:
        libelle, _, valeur = str(ligne).partition(" : ")
        alerte = "différente" in libelle
        couleur = "#b91c1c" if alerte else "#64748b"
        val_couleur = "#b91c1c" if alerte else "#0f172a"
        rangs.append(
            '<div style="margin:0 0 4px 0;line-height:1.4;font-size:13px">'
            f'<span style="color:{couleur}">{escape(libelle)}</span> : '
            f'<span style="font-family:{FONT_MONO};font-size:13px;'
            f'color:{val_couleur};word-break:break-all">{escape(valeur)}</span></div>'
        )
    return (
        '<div style="margin:8px 0;padding:8px 10px;background:#f8fafc;'
        'border:1px solid #e2e8f0;border-radius:6px">'
        + "".join(rangs)
        + "</div>"
    )


def capture_block(has_preview: object, *, en_grand: bool = False) -> str:
    """Aperçu inerte du message dans un cadre discret 1px solid #cbd5e1."""
    if not has_preview:
        return ""
    legende = "Aperçu inerte du message : rien n'y est cliquable." + (
        " Pour le lire en grand, ouvre la pièce jointe." if en_grand else ""
    )
    return (
        '<div style="margin:0 0 16px 0;border:1px solid #cbd5e1;border-radius:8px;'
        'padding:8px;background:#f8fafc;box-sizing:border-box">'
        f'<img src="cid:{PREVIEW_CID}" alt="Aperçu inerte du message, sans rien de cliquable" '
        'style="display:block;width:100%;max-width:100%;height:auto;'
        'border-radius:4px" />'
        '<div style="margin-top:6px;font-size:11px;color:#64748b;line-height:1.35">'
        f"{legende}</div></div>"
    )


def _heure_de_paris(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_PARIS)


def _niveau(badge: dict[str, object]) -> str:
    niveau = str(badge.get("level") or "doute")
    return niveau if niveau in _TAGS else "doute"


def _meta_rows(
    context: dict[str, object], recu: datetime | None
) -> list[tuple[str, str, bool, bool]]:
    rows: list[tuple[str, str, bool, bool]] = []
    sujet = str(context.get("subject") or "").strip()
    if sujet:
        rows.append(("Objet", sujet, False, False))

    raw_lines = context.get("sender_lines")
    lignes = [str(value) for value in raw_lines] if isinstance(raw_lines, list) else []
    valeurs = dict(ligne.partition(" : ")[::2] for ligne in lignes)

    if valeurs.get("Adresse affichée"):
        rows.append(("Adresse affichée", valeurs["Adresse affichée"], True, False))
    if valeurs.get("Nom affiché"):
        rows.append(("Nom affiché", valeurs["Nom affiché"], True, False))
    for libelle, valeur in valeurs.items():
        if libelle in {"Adresse affichée", "Nom affiché"} or not valeur:
            continue
        different = "différente" in libelle
        label = (
            "Enveloppe"
            if libelle.startswith("Adresse d’enveloppe")
            else libelle.replace(" différente", "")
        )
        rows.append((label, valeur, True, different))

    if recu:
        rows.append(("Reçu", f"{recu:%d/%m/%Y à %H:%M}", False, False))
    return rows


def render_notice_html(context: dict[str, object]) -> str:
    """La fiche de décision V2 : état, accroche, méta, raisons, aperçu, choix."""
    concerns = [str(value) for value in context.get("concerns") or []]
    excerpt_key = (
        "message_excerpts" if "message_excerpts" in context else "risk_excerpts"
    )
    excerpts = [str(value) for value in context.get(excerpt_key) or []][:3]
    badge = context.get("badge")
    badge = (
        badge
        if isinstance(badge, dict) and badge.get("word")
        else {"level": "doute", "word": "DOUTEUX", "detail": "", "color": "#b45309"}
    )
    recu = _heure_de_paris(context.get("received_at"))
    reference = str(context.get("reference") or "")

    tag_label, tag_color, tag_bg = _TAGS[_niveau(badge)]
    conseil = str(context.get("advice") or "").strip()

    apercu_html = (
        capture_block(True, en_grand=bool(context.get("has_full_preview")))
        if context.get("has_preview")
        else excerpts_block("Aperçu inerte", excerpts)
    )

    inner = (
        status_pill(
            tag_label,
            color=tag_color,
            background=tag_bg,
            detail=str(badge.get("detail") or ""),
            hidden_word=str(badge.get("word") or ""),
        )
        + headline(conseil or _HEADLINE_DEFAUT)
        + meta_block(_meta_rows(context, recu))
        + bullets_block(
            "Pourquoi j'hésite",
            concerns,
            empty_text="Rien de précis à te signaler.",
        )
        + apercu_html
        + _boutons(str(context.get("action_address") or ""))
        + footer(
            '<strong style="color:#475569">MAIA</strong>'
            " · Sans boutons, réponds simplement A, B ou C",
            reference=reference,
        )
    )
    return wrap_shell(inner)
