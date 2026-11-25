"""Le rendu HTML compact des réponses proposées par SentiMail (V2).

Trois boutons compacts sur une seule ligne :
- A : bouton plein (vert ou sombre) pour l'action principale ;
- B : contour rouge discret pour signaler un indésirable ;
- C : contour neutre pour écrire librement à MAIA.

Le sens des lettres, leurs mots et leurs corps préremplis vivent dans
``choice_registry``. Ce module ne décide rien : il dessine les boutons.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from html import escape

from sentimail_v3.conversation.mail_layout import FONT_SANS

__all__ = ["render_action_button", "render_choice_cards", "render_choices"]

# (lettre, titre, sous-titre, couleur)
Choice = tuple[str, str, str, str]

# Un lien de réponse ne peut mener qu'à un message à envoyer, ou à une page de
# l'application. Tout autre schéma - « javascript: », « data: » - est refusé.
_SCHEMAS_AUTORISES = ("mailto:", "https://")

# Une couleur entre dans un attribut de style, où l'échappement HTML ne
# protège de rien : seule sa forme hexadécimale la garantit.
_COULEUR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def _verifie_couleur(couleur: str) -> str:
    if not _COULEUR.match(couleur or ""):
        raise ValueError(f"couleur refusée : {couleur[:32]!r}")
    return couleur


def _verifie(lien: str) -> str:
    if not lien.startswith(_SCHEMAS_AUTORISES):
        raise ValueError(f"schéma de lien refusé : {lien[:32]!r}")
    return lien


def _style_bouton(lettre: str, couleur: str) -> str:
    """Style V2 unifié : A plein, B contour rouge, C contour neutre."""
    couleur = _verifie_couleur(couleur)
    if lettre == "B":
        return "color:#b91c1c;background:#ffffff;border:1px solid #fecaca;"
    if lettre == "C":
        return "color:#334155;background:#ffffff;border:1px solid #cbd5e1;"
    return f"color:#ffffff;background:{couleur};border:1px solid {couleur};"


def _bouton(choix: Choice, lien: str) -> str:
    lettre, titre, sous_titre, couleur = choix
    palette = _style_bouton(lettre, couleur)
    return (
        f'<a href="{escape(_verifie(lien))}" data-choice="{escape(lettre)}" '
        f'title="{escape(sous_titre)}" '
        f'style="display:inline-block;font-family:{FONT_SANS};font-size:13px;'
        f"line-height:16px;font-weight:600;{palette}"
        "text-decoration:none;padding:7px 12px;border-radius:6px;"
        'margin:0 6px 6px 0">'
        f"<strong>{escape(lettre)}</strong>&nbsp;·&nbsp;{escape(titre)}"
        "</a>"
    )


# Une espace insécable sépare les boutons même dans un client qui ignore les marges.
_ECART = "&nbsp;"


def render_choices(choices: Sequence[Choice], links: dict[str, str]) -> str:
    """Les réponses possibles, côte à côte sur une ligne."""
    boutons = _ECART.join(_bouton(choix, links[choix[0]]) for choix in choices)
    return f'<div style="margin:14px 0 4px 0">{boutons}</div>'


def render_choice_cards(choices: Sequence[Choice], links: dict[str, str]) -> str:
    """Rendu unifié V2 des choix sur une seule ligne."""
    return render_choices(choices, links)


def render_action_button(
    identifiant: str, titre: str, infobulle: str, couleur: str, lien: str
) -> str:
    """Un bouton seul, qui n'est pas un des trois choix."""
    couleur = _verifie_couleur(couleur)
    return (
        '<div style="margin:12px 0 10px 0">'
        f'<a href="{escape(_verifie(lien))}" data-choice="{escape(identifiant)}" '
        f'title="{escape(infobulle)}" '
        f'style="display:inline-block;font-family:{FONT_SANS};font-size:13px;'
        f"line-height:16px;color:#ffffff;background:{couleur};"
        f"border:1px solid {couleur};"
        'text-decoration:none;padding:8px 14px;border-radius:6px;font-weight:600">'
        f"{escape(titre)}</a></div>"
    )
