"""L'avis qui accompagne un message classé en indésirable.

Jusqu'ici, un message classé partait dans les indésirables tel quel, précédé
d'un bandeau et suivi d'un lien de signalement. Trois choses n'allaient pas.

Le message hostile arrivait intact : son texte gardait toute sa force de
persuasion, et ses liens restaient cliquables. Or il vient précisément d'être
jugé indésirable ou dangereux - le laisser opérationnel dans la boîte du
destinataire est une décision qu'on ne prend pas.

La raison du classement était une liste à puces au milieu du message : le
lecteur devait la distinguer du discours de l'attaquant, écrit juste en
dessous et souvent plus soigné.

Et rien ne permettait de récupérer un message classé par erreur, sinon écrire à
MAIA en formulant soi-même sa demande.

Le message est donc remplacé par cet avis : une capture de ce qu'il contenait,
la raison du classement mise en forme, et deux réponses d'un clic - dont
celle qui le fait livrer pour de bon.
"""

from __future__ import annotations

from html import escape

from sentimail_v3.conversation.choice_answers import (
    GRIS,
    VERT,
    render_choices,
)
from sentimail_v3.conversation.review_notice import capture_block, corps_redige
from urllib.parse import quote, urlencode

JUNK_TOKEN_PLACEHOLDER = "S3-JUNK-TOKEN-PLACEHOLDER"

# Voir review_notice.SUJET_REPONSE : la séquence machine vit dans l'objet, la
# zone de saisie reste au destinataire.
SUJET_REPONSE = f"Re: [SentiMail] Ma réponse · {JUNK_TOKEN_PLACEHOLDER}"

# Des phrases lues sans modèle : voir review_notice._CHOICES. Le jeu suit la
# situation : le classement est déjà acquis, le confirmer (B) n'apporterait
# rien - seuls le désaccord (A) et la parole libre (C) ont un geste.
_CHOICES = (
    (
        "A",
        "Livre-le-moi",
        "C’était une erreur",
        "Merci pour ton avis, mais c'était une erreur : ce message est "
        "légitime, livre-le-moi.",
        VERT,
    ),
    (
        "C",
        "Autre chose",
        "J’explique à MAIA",
        "",
        GRIS,
    ),
)


def junk_choice_links(action_address: str) -> dict[str, str]:
    """Les réponses possibles, prêtes à partir."""
    liens: dict[str, str] = {}
    for lettre, _, _, phrase, _ in _CHOICES:
        # quote_via=quote impose le pourcentage-encodage. Par defaut urlencode
        # encode l'espace en « + », convention des formulaires web qu'un client
        # de messagerie n'applique PAS a un mailto: - la consigne arrivait donc
        # avec des « + » a la place des espaces, et « Ne+le+livre+pas » etait lu
        # comme une demande de livraison.
        liens[lettre] = "mailto:" + action_address + "?" + urlencode(
            {"subject": SUJET_REPONSE, "body": corps_redige(phrase)},
            quote_via=quote,
        )
    return liens


def _boutons(action_address: str) -> str:
    """Les réponses, en boutons colorés."""
    choix = [(lettre, titre, sous_titre, couleur)
             for lettre, titre, sous_titre, _, couleur in _CHOICES]
    return render_choices(choix, junk_choice_links(action_address))


def render_junk_html(context: dict[str, object]) -> str:
    """L'avis qui remplace le message dans le dossier des indésirables.

    Le texte du message d'origine n'est jamais recopié ici : il est dans la
    capture, où il ne peut plus ni tromper par un lien, ni charger d'image.
    """
    dangereux = str(context.get("verdict") or "") in {"dangerous", "malicious"}
    sujet = escape(str(context.get("subject") or "(sans objet)"))
    expediteur = escape(str(context.get("sender") or "(expéditeur inconnu)"))
    raisons = [str(value) for value in context.get("reasons") or []]
    lecons = [v for v in context.get("lessons") or [] if isinstance(v, dict)]

    titre = (
        "Ce message est dangereux, je l’ai mis de côté"
        if dangereux
        else "Ce message est indésirable, je l’ai classé"
    )
    bandeau = "#b91c1c" if dangereux else "#b45309"

    raisons_html = "".join(
        '<li style="margin:0 0 6px 0;line-height:1.35">' + escape(value) + "</li>"
        for value in raisons[:6]
    ) or '<li style="margin:0;color:#64748b">Un faisceau d’indices concordants.</li>'

    techniques_html = "".join(
        '<div style="margin-top:8px;padding:9px 11px;background:#fff7ed;'
        'border-left:4px solid #ea580c;border-radius:6px;font-size:13px">'
        f'<strong>{escape(str(value.get("name") or ""))}</strong> — '
        f'{escape(str(value.get("description") or ""))}'
        + (
            '<div style="margin-top:5px;color:#7c2d12">→ '
            + escape(str(value.get("advice") or ""))
            + "</div>"
            if value.get("advice")
            else ""
        )
        + "</div>"
        for value in lecons[:4]
    )

    # Le même bloc que l'avis d'un message retenu, au même endroit : après
    # l'en-tête, avant l'explication. Deux mises en page différentes
    # obligeraient à réapprendre où regarder pour une question identique.
    capture_html = capture_block(context.get("has_preview")) or (
        '<div style="margin-top:12px;padding:10px 12px;background:#f1f5f9;'
        'border-radius:8px;font-size:12px;color:#475569">'
        "Je n’ai pas pu photographier ce message. Son contenu n’est pas "
        "reproduit ici, pour ne pas te le remettre sous les yeux.</div>"
    )
    avertissement = (
        '<div style="margin-top:10px;font-size:11px;color:#64748b;line-height:1.4">'
        "L’image ci-dessus est une photo du message : rien n’y est cliquable, "
        "et son texte peut rester trompeur.</div>"
        if context.get("has_preview")
        else ""
    )

    return (
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;'
        'margin:0 auto;color:#0f172a">'
        '<h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.5px;'
        'color:#64748b;margin:0 0 6px 0">Aperçu de l’email</h2>'
        f'<div style="background:{bandeau};color:#ffffff;padding:12px 14px;'
        'border-radius:10px 10px 0 0;font-size:14px;font-weight:bold">'
        f"{escape(titre)}</div>"
        '<div style="border:1px solid #e2e8f0;border-top:0;'
        'border-radius:0 0 10px 10px;padding:11px 14px;font-size:14px">'
        f'<div style="font-weight:bold">{sujet}</div>'
        f'<div style="color:#475569;font-size:13px">De : {expediteur}</div>'
        "</div>"
        # La photo vient avant l'explication, comme dans l'avis d'un message
        # retenu : on reconnaît d'abord ce dont on parle, on lit ensuite
        # pourquoi il a été écarté.
        f"{capture_html}"
        # La raison, mise en forme et seule à cet endroit : le discours de
        # l'expéditeur ne vient plus concurrencer l'explication.
        '<div style="margin-top:14px;padding:11px 13px;background:#fef2f2;'
        'border-left:4px solid #dc2626;border-radius:8px">'
        '<div style="font-size:13px;font-weight:bold;color:#991b1b;'
        'margin-bottom:6px">Pourquoi je l’ai classé</div>'
        f'<ul style="margin:0;padding-left:18px;color:#7f1d1d;font-size:14px">'
        f"{raisons_html}</ul>{techniques_html}</div>"
        f"{avertissement}"
        '<div style="margin-top:14px;font-size:13px;font-weight:bold">'
        "Que veux-tu faire ?</div>"
        + _boutons(str(context.get("action_address") or ""))
        + '<div style="font-size:11px;color:#64748b;line-height:1.4">'
        "Si les boutons ne fonctionnent pas, réponds simplement A ou C à ce "
        "message.</div>"
        '<div style="margin-top:10px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail"
        # La référence du dossier : de quoi en reparler sans le retrouver.
        + (
            '<span style="float:right;font-family:ui-monospace,Menlo,monospace">'
            + escape(str(context.get("reference") or ""))
            + "</span>"
            if context.get("reference")
            else ""
        )
        + "</div>"
        "</div>"
    )
