"""La relance d'un dossier retenu, avec les mêmes réponses que son avis (V2)."""

from __future__ import annotations

from html import escape

from sentimail_v3.conversation.choice_answers import render_choice_cards
from sentimail_v3.conversation.choice_registry import choice_presentations
from sentimail_v3.conversation.mail_layout import footer, status_pill, wrap_shell
from sentimail_v3.conversation.review_notice import capture_block, choice_links


def render_reminder_html(
    body: str,
    action_address: str,
    *,
    has_preview: bool = False,
    has_full_preview: bool = False,
) -> str:
    """Garde le texte lisible et les boutons rattachables au dossier SMTP."""
    paragraphes = "".join(
        '<p style="margin:0 0 12px 0;font-size:14px;line-height:1.5;color:#0f172a">'
        + escape(paragraphe).replace("\n", "<br>")
        + "</p>"
        for paragraphe in body.split("\n\n")
        if paragraphe.strip()
    )
    boutons = render_choice_cards(
        [choice.render_tuple() for choice in choice_presentations("review")],
        choice_links(action_address),
    )
    inner = (
        status_pill(
            "RAPPEL · RETENU DEPUIS 3 JOURS",
            color="#9a3412",
            background="#ffedd5",
        )
        + paragraphes
        + capture_block(has_preview, en_grand=has_full_preview)
        + boutons
        + footer(
            '<strong style="color:#475569">MAIA</strong>'
            " · Sans boutons, réponds simplement A, B ou C"
        )
    )
    return wrap_shell(inner, full_document=True)
