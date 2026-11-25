"""L'accusé d'une directive, adressé à celui qui l'a donnée (V2).

A pour livrer à nouveau (si le message n'est pas déjà livré), C pour expliquer
autre chose. Quand la qualification a été enregistrée comme exemple
d'apprentissage, la lettre le dit sobrement.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote, urlencode

from sentimail_v3.conversation.choice_answers import render_choices
from sentimail_v3.conversation.choice_registry import (
    choice_presentations,
    response_links,
)
from sentimail_v3.conversation.mail_layout import (
    footer,
    headline,
    meta_block,
    status_pill,
    wrap_shell,
)
from sentimail_v3.conversation.receipt_preference import (
    receipt_toggle_label,
    receipt_toggle_sentence,
)
from sentimail_v3.conversation.review_notice import (
    ACTION_TOKEN_PLACEHOLDER,
    corps_redige,
)

# Voir review_notice.SUJET_REPONSE : la séquence machine vit dans l'objet.
SUJET_REPONSE = f"Re: [SentiMail] Ma réponse · {ACTION_TOKEN_PLACEHOLDER}"

APPRENTISSAGE = (
    "J’ai aussi gardé ce message comme exemple : il m’aidera à reconnaître "
    "les prochains du même genre, même envoyés d’une autre adresse."
)

# L'accusé ne part que si le réglage est actif : il porte donc l'état et la
# phrase exacte qui le fait taire.
_ETAT_REGLAGE_GABARIT = (
    "L’accusé de réception est activé : réponds « {bascule} » si tu ne veux "
    "plus en recevoir."
)

ETAT_REGLAGE = _ETAT_REGLAGE_GABARIT.format(bascule=receipt_toggle_label(True))


def receipt_toggle_link_html(action_address: str, currently_enabled: bool) -> str:
    """Le lien qui bascule l'accusé vers l'état inverse de currently_enabled."""
    href = "mailto:" + action_address + "?" + urlencode(
        {
            "subject": SUJET_REPONSE,
            "body": corps_redige(receipt_toggle_sentence(currently_enabled)),
        },
        quote_via=quote,
    )
    libelle = escape(receipt_toggle_label(currently_enabled))
    return f'<a href="{escape(href)}">{libelle}</a>'


def _choices(offer_redelivery: bool):
    choices = choice_presentations("receipt")
    return choices if offer_redelivery else choices[1:]


def _links(action_address: str, offer_redelivery: bool) -> dict[str, str]:
    links = response_links(action_address, SUJET_REPONSE, "receipt")
    return links if offer_redelivery else {"C": links["C"]}


def _invitation(offer_redelivery: bool) -> str:
    if offer_redelivery:
        return (
            "Si je me suis trompée : réponds A pour que je te livre ce message "
            "à nouveau, C pour m’expliquer autre chose."
        )
    return "Si tu veux me dire autre chose, réponds C à ce message."


def receipt_text(
    explanation: str,
    subject: object,
    action_status: str,
    *,
    learned: bool,
    offer_redelivery: bool,
) -> str:
    """La version texte de l'accusé, lisible dans tout client."""
    lines = [f"Objet concerné : {subject or '(conversation générale)'}", ""]
    lines.append(str(explanation))
    if action_status:
        lines.extend(["", action_status])
    if learned:
        lines.extend(["", APPRENTISSAGE])
    lines.extend(
        [
            "",
            _invitation(offer_redelivery),
            "",
            ETAT_REGLAGE,
            "",
            "- MAIA, SentiMail V3",
        ]
    )
    return "\n".join(lines)


def receipt_html(
    explanation: str,
    subject: object,
    action_status: str,
    *,
    learned: bool,
    offer_redelivery: bool,
    action_address: str,
) -> str:
    """La même lettre en V2, avec les réponses en boutons."""
    rows: list[tuple[str, str, bool, bool]] = [
        ("Objet", str(subject or "(conversation générale)"), False, False)
    ]
    if action_status:
        rows.append(("Action", str(action_status), False, False))

    learned_html = (
        '<p style="margin:0 0 14px 0;font-size:13px;line-height:1.45;color:#475569">'
        f"{escape(APPRENTISSAGE)}</p>"
        if learned
        else ""
    )

    choix = [choice.render_tuple() for choice in _choices(offer_redelivery)]
    toggle_text = _ETAT_REGLAGE_GABARIT.format(
        bascule=receipt_toggle_link_html(action_address, True)
    )

    inner = (
        status_pill("C'EST NOTÉ", color="#166534", background="#dcfce7")
        + headline(str(explanation))
        + meta_block(rows)
        + learned_html
        + render_choices(choix, _links(action_address, offer_redelivery))
        + footer(
            f'<strong style="color:#475569">MAIA</strong> · {toggle_text}'
        )
    )
    return wrap_shell(inner)
