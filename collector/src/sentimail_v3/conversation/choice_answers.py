"""Les réponses proposées par un avis, écrites une seule fois pour toutes.

Trois endroits demandent une réponse : l'avis sur un message retenu, l'avis qui
remplace un message classé en indésirables, et le pied de page ajouté à un
message livré. Chacun dessinait sa propre version, et le message livré n'avait
qu'un lien noyé dans une phrase. La même question posée de trois façons
s'apprend trois fois.

Ce sont trois petits boutons, sur une seule ligne. Les pavés pleine largeur
qu'on avait d'abord essayés occupaient plus de hauteur que l'explication qu'ils
concluaient : sur un téléphone, il fallait faire défiler pour retrouver ce que
MAIA avait dit. Les liens soulignés qui leur ont succédé tenaient en trois
lignes, mais se lisaient comme du texte - rien ne disait qu'il fallait cliquer.

Un bouton compact tient les deux exigences : la lettre est dedans, sur son fond
de couleur, et les trois tiennent côte à côte sur une ligne. Vert pour recevoir,
rouge pour bloquer, gris pour écrire.

Le gris ne dit pas « désactivé » : c'est la seule des trois réponses qui n'a
aucune alerte à porter. Lui donner du vert ou du rouge lui prêterait un sens
qu'elle n'a pas.

Un lien de courrier ne peut pas exécuter d'action, seulement ouvrir un message
déjà rédigé. Le corps de ce message est construit ailleurs, par la surface qui
sait ce qu'elle propose.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from html import escape

# La couleur d'une lettre ne change jamais de surface : c'est ce qui rend la
# réponse reconnaissable avant même d'avoir lu le libellé.
VERT = "#15803d"
ROUGE = "#b91c1c"
GRIS = "#64748b"

# (lettre, titre, sous-titre, couleur)
Choice = tuple[str, str, str, str]

# Un lien de réponse ne peut mener qu'à un message à envoyer, ou à une page de
# l'application. Tout autre schéma - « javascript: », « data: » - n'a aucune
# raison d'apparaître ici, et en laisser passer un ferait de l'avis lui-même un
# vecteur. La vérification échoue bruyamment plutôt que d'émettre le lien.
_SCHEMAS_AUTORISES = ("mailto:", "https://")


# Une couleur entre dans un attribut de style, où l'échappement HTML ne
# protège de rien : « red;background:url(x) » resterait une déclaration valide.
# Seule sa forme peut la garantir.
_COULEUR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def _verifie_couleur(couleur: str) -> str:
    if not _COULEUR.match(couleur or ""):
        raise ValueError(f"couleur refusée : {couleur[:32]!r}")
    return couleur


def _verifie(lien: str) -> str:
    if not lien.startswith(_SCHEMAS_AUTORISES):
        raise ValueError(f"schéma de lien refusé : {lien[:32]!r}")
    return lien


def _bouton(choix: Choice, lien: str) -> str:
    lettre, titre, sous_titre, couleur = choix
    # Tout ce qui entre dans le gabarit est échappé ici, attributs compris.
    # L'échappement appartient au module : un appelant qui l'oublie ne doit pas
    # pouvoir produire un avis mal formé, et un appelant qui le fait deux fois
    # afficherait des « &amp;amp; » à la place des liens.
    #
    # Le sous-titre passe en infobulle : il redisait le titre en deux fois plus
    # de place, et c'est cette place qu'on cherche à rendre.
    return (
        f'<a href="{escape(_verifie(lien))}" data-choice="{escape(lettre)}" '
        f'title="{escape(sous_titre)}" '
        'style="display:inline-block;font-family:Arial,sans-serif;font-size:13px;'
        f"line-height:16px;color:#ffffff;background:{_verifie_couleur(couleur)};"
        'text-decoration:none;padding:6px 11px;border-radius:5px;'
        'margin:0 6px 6px 0">'
        f"<strong>{escape(lettre)}</strong>&nbsp;·&nbsp;{escape(titre)}"
        "</a>"
    )


def render_choices(choices: Sequence[Choice], links: dict[str, str]) -> str:
    """Les réponses possibles, côte à côte, dans l'ordre où on les propose."""
    boutons = "".join(_bouton(choix, links[choix[0]]) for choix in choices)
    return f'<div style="margin:10px 0 8px 0">{boutons}</div>'


def render_action_button(
    identifiant: str, titre: str, infobulle: str, couleur: str, lien: str
) -> str:
    """Un bouton seul, qui n'est pas un des trois choix.

    Le récapitulatif ne propose pas A, B ou C : il propose d'ouvrir le bulletin
    où toutes les réponses seront cochées d'un coup. C'est un autre geste, donc
    un autre bouton - mais il passe par les mêmes vérifications, parce qu'un
    lien mal formé reste un lien mal formé quel que soit ce qu'il ouvre.
    """
    return (
        '<div style="margin:10px 0 12px 0">'
        f'<a href="{escape(_verifie(lien))}" data-choice="{escape(identifiant)}" '
        f'title="{escape(infobulle)}" '
        'style="display:inline-block;font-family:Arial,sans-serif;font-size:14px;'
        f"line-height:18px;color:#ffffff;background:{_verifie_couleur(couleur)};"
        'text-decoration:none;padding:9px 15px;border-radius:6px;font-weight:bold">'
        f"{escape(titre)}</a></div>"
    )
