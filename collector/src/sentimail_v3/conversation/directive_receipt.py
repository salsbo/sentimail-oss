"""L'accusé d'une directive, adressé à celui qui l'a donnée.

L'accusé parlait de l'utilisateur à la troisième personne (« L'utilisateur a
qualifié le message de spam ») en s'adressant à lui, et concluait « réponds à
ce message : il rouvre le dossier » sans dire comment. Les autres surfaces
répondent par des boutons ; celle-ci parle désormais la même langue : A pour
livrer à nouveau, C pour expliquer autre chose. La relivraison n'est proposée
que si le message n'est pas déjà dans la boîte.

Quand la qualification a été enregistrée comme exemple d'apprentissage, la
lettre le dit : le geste de l'utilisateur ne bloque pas qu'une adresse, il
apprend une forme de message.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote, urlencode

from sentimail_v3.conversation.choice_answers import GRIS, VERT, render_choices
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

# (lettre, titre, sous-titre, phrase, couleur). La phrase du choix A porte la
# classification et l'action, lues sans modèle par directive_policy.
_CHOICES = (
    (
        "A",
        "Livrer à nouveau",
        "Je me suis trompée : reçois-le",
        "Tu t'es trompée : c'est un message légitime, livre-le-moi à nouveau.",
        VERT,
    ),
    (
        "C",
        "Autre commentaire",
        "J’explique à MAIA",
        "",
        GRIS,
    ),
)

APPRENTISSAGE = (
    "J’ai aussi gardé ce message comme exemple : il m’aidera à reconnaître "
    "les prochains du même genre, même envoyés d’une autre adresse."
)

# L'accusé ne part que si le réglage est actif : il porte donc l'état et la
# phrase exacte qui le fait taire. Le gabarit est partagé entre la version
# texte (la phrase nue) et la version HTML (la phrase avec la bascule en
# lien) : les deux surfaces ne peuvent alors pas diverger dans leurs mots.
_ETAT_REGLAGE_GABARIT = (
    "L’accusé de réception est activé : réponds « {bascule} » si tu ne veux "
    "plus en recevoir."
)

ETAT_REGLAGE = _ETAT_REGLAGE_GABARIT.format(bascule=receipt_toggle_label(True))


def receipt_toggle_link_html(action_address: str, currently_enabled: bool) -> str:
    """Le lien qui bascule l'accusé vers l'état inverse de currently_enabled.

    Un seul endroit construit ce lien : toute surface qui propose la bascule
    d'un clic (ici, et demain ailleurs) l'appelle plutôt que de réassembler un
    mailto: elle-même. Le corps pré-rempli est la phrase canonique de
    receipt_preference : cliquer envoie exactement ce qu'écrire la phrase à la
    main aurait envoyé, reconnue sans modèle par parse_receipt_toggle.
    """
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
    return _CHOICES if offer_redelivery else _CHOICES[1:]


def _links(action_address: str, offer_redelivery: bool) -> dict[str, str]:
    liens: dict[str, str] = {}
    for lettre, _, _, phrase, _ in _choices(offer_redelivery):
        liens[lettre] = "mailto:" + action_address + "?" + urlencode(
            {"subject": SUJET_REPONSE, "body": corps_redige(phrase)},
            quote_via=quote,
        )
    return liens


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
        ["", _invitation(offer_redelivery), "", ETAT_REGLAGE, "",
         "— MAIA, SentiMail V3"]
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
    """La même lettre, avec les réponses en boutons."""
    sujet = escape(str(subject or "(conversation générale)"))
    blocs = [
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;'
        'margin:0 auto;color:#0f172a">'
        '<div style="font-size:13px;color:#64748b;margin-bottom:8px">'
        f"Objet concerné : {sujet}</div>"
        f'<div style="font-size:14px;line-height:1.45">{escape(str(explanation))}</div>'
    ]
    if action_status:
        blocs.append(
            '<div style="margin-top:10px;padding:9px 11px;background:#f8fafc;'
            'border-left:4px solid #cbd5e1;border-radius:6px;font-size:14px">'
            f"{escape(action_status)}</div>"
        )
    if learned:
        blocs.append(
            '<div style="margin-top:10px;font-size:13px;color:#475569">'
            f"{escape(APPRENTISSAGE)}</div>"
        )
    choix = [
        (lettre, titre, sous_titre, couleur)
        for lettre, titre, sous_titre, _, couleur in _choices(offer_redelivery)
    ]
    blocs.append(
        '<div style="margin-top:12px;font-size:13px;font-weight:bold">'
        "Si je me suis trompée ?</div>"
        + render_choices(choix, _links(action_address, offer_redelivery))
        + '<div style="font-size:11px;color:#64748b;line-height:1.4">'
        "Si les boutons ne fonctionnent pas, réponds simplement "
        + ("A ou C" if offer_redelivery else "C")
        + " à ce message.</div>"
        f'<div style="margin-top:8px;font-size:11px;color:#94a3b8;'
        f'line-height:1.4">'
        f"{_ETAT_REGLAGE_GABARIT.format(bascule=receipt_toggle_link_html(action_address, True))}"
        "</div>"
        '<div style="margin-top:10px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail</div></div>"
    )
    return "".join(blocs)
