"""La mise en forme de l'avis que MAIA envoie, et rien d'autre.

Un avis se lit sur un téléphone, entre deux choses. L'ancienne mise en page
empilait six sections sur toute la hauteur de l'écran : il fallait faire défiler
pour savoir s'il fallait s'inquiéter. Ce qui inquiète et ce qui rassure tiennent
désormais côte à côte, la conclusion vient dessous, et la réponse se donne d'un
geste.

Deux contraintes propres au courrier, qui dictent les choix techniques :

- les clients de messagerie ignorent la plupart des mises en page modernes, et
  l'avis est un fragment sans <head> : pas de media query possible. Les colonnes
  sont donc deux blocs inline-block à largeur plafonnée, côte à côte quand la
  place existe, empilés d'eux-mêmes sur un téléphone (un tableau figé 50/50
  broyait le texte sur iPhone) ;
- un bouton ne peut pas exécuter d'action, seulement ouvrir un message. Les
  choix A et B ouvrent donc une réponse déjà rédigée, en toutes lettres plutôt
  qu'en initiales : « A » seul ne veut rien dire pour l'interprétation, alors
  qu'une phrase explicite est reconnue sans avoir à consulter un modèle.

Le jeton d'action n'existe pas encore quand cette page est écrite : il est créé
à l'expédition. Un marqueur en tient la place, remplacé au moment de l'envoi -
ce qui a l'avantage de ne jamais écrire le jeton en base.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote, urlencode

from sentimail_v3.conversation.choice_answers import (
    GRIS,
    ROUGE,
    VERT,
    render_choices,
)

ACTION_TOKEN_PLACEHOLDER = "S3-ACTION-TOKEN-PLACEHOLDER"

# L'identifiant sous lequel la capture est rattachée au corps HTML. Il est
# fixe : la page est écrite en base bien avant que le message MIME existe.
PREVIEW_CID = "capture-email-neutralisee"

# Ce que chaque choix fait écrire. La réponse part au nom du destinataire :
# elle doit se lire comme un message qu'il aurait pu écrire. La trame
# précédente - le jeton en première ligne, puis une lettre nue - faisait
# croire à un envoi défectueux : personne ne comprenait ce qui partait.
# Les phrases sont calées sur les règles de lecture (directive_policy) :
# elles restent comprises sans modèle, exactement comme la lettre l'était.
_CHOICES = (
    (
        "A",
        "Je le veux",
        "Cet expéditeur est fiable, livre-le-moi",
        "Merci pour ton avis. Je connais cet expéditeur et ce message est "
        "légitime : livre-le-moi.",
        VERT,
    ),
    (
        "B",
        "Non merci",
        "C’est indésirable, bloque cet expéditeur",
        "Merci pour ton avis. C'est du spam : ne le livre pas et bloque les "
        "prochains.",
        ROUGE,
    ),
    (
        "C",
        "Autre chose",
        "J’explique à MAIA",
        "",
        GRIS,
    ),
)


# L'objet du message de réponse porte la séquence machine. Un mailto: ne
# transporte que du texte brut : impossible d'y cacher quoi que ce soit par la
# mise en forme. L'objet est le seul champ que le destinataire n'édite jamais,
# et le serveur y cherche déjà le marqueur (conversation.record_inbound lit
# objet + corps) - la zone de saisie reste ainsi entièrement à lui.
SUJET_REPONSE = f"Re: [SentiMail] Ma réponse · {ACTION_TOKEN_PLACEHOLDER}"

# Ce que « Autre chose » ouvre : une amorce à compléter. Le propos est libre ;
# laissée telle quelle, l'invite ne déclenche aucune action.
OUVERTURE_LIBRE = "Voici ma demande à propos de ce message :"
INVITE_LIBRE = "Tapez ici vos demandes ou remarques"


def corps_redige(phrase: str) -> str:
    """Une réponse rédigée : salutation, propos, remerciement.

    Le propos vide est celui du choix libre : l'amorce invite à écrire, sans
    rien décider tant que rien n'est écrit.
    """
    propos = phrase or f"{OUVERTURE_LIBRE}\n\n{INVITE_LIBRE}"
    return f"Bonjour MAIA,\n\n{propos}\n\nMerci !\n"


def choice_links(action_address: str) -> dict[str, str]:
    """Les trois réponses possibles, prêtes à partir."""
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


def capture_block(has_preview: object) -> str:
    """La photo du message, dessinée une seule fois pour les deux avis.

    Un message retenu et un message classé posent la même question à la même
    personne : deux mises en page différentes obligeraient à réapprendre où
    regarder, alors que seule la décision change.

    La photo est une miniature, à mi-largeur. En pleine page elle repoussait
    l'explication hors de l'écran, alors qu'elle sert seulement à reconnaître
    le message - le lire n'est pas le sujet, et son texte peut de toute façon
    rester trompeur.

    Le cadre rouge la désigne. Sans lui, la miniature se lisait comme une
    illustration de l'avis ; entourée, elle se lit comme ce dont l'avis parle.
    C'est la même convention que sur une capture annotée : ce qui est cerclé
    est le sujet, pas le décor.
    """
    if not has_preview:
        return ""
    return (
        '<div style="margin-top:12px;border:2px solid #dc2626;border-radius:10px;'
        'padding:6px;background:#fef2f2;width:50%;max-width:50%;'
        'box-sizing:border-box">'
        f'<img src="cid:{PREVIEW_CID}" alt="Photo du message, sans rien de cliquable" '
        'style="display:block;width:100%;max-width:100%;height:auto;'
        'border-radius:6px" />'
        '<div style="margin-top:5px;font-size:11px;color:#991b1b;'
        'font-family:Arial,sans-serif;line-height:1.3">'
        "Le message dont je te parle</div></div>"
    )


def _liste(valeurs: list[str], vide: str, couleur: str) -> str:
    elements = "".join(
        f'<li style="margin:0 0 6px 0;line-height:1.35">{escape(value)}</li>'
        for value in valeurs
    ) or f'<li style="margin:0;color:#64748b">{escape(vide)}</li>'
    return (
        f'<ul style="margin:0;padding-left:18px;color:{couleur};font-size:14px">'
        f"{elements}</ul>"
    )


def _boutons(action_address: str) -> str:
    """Les trois réponses, en trois lignes de texte coloré."""
    choix = [(lettre, titre, sous_titre, couleur)
             for lettre, titre, sous_titre, _, couleur in _CHOICES]
    return render_choices(choix, choice_links(action_address))


def render_notice_html(context: dict[str, object]) -> str:
    """L'avis complet : compact, en deux colonnes, avec ses trois réponses."""
    sujet = escape(str(context.get("subject") or "(sans objet)"))
    expediteur = escape(str(context.get("sender") or "(expéditeur inconnu)"))
    statut = escape(str(context.get("status_text") or ""))
    concerns = [str(value) for value in context.get("concerns") or []]
    reassurances = [str(value) for value in context.get("reassurances") or []]
    limits = [str(value) for value in context.get("limits") or []]
    risques = [str(value) for value in context.get("risk_excerpts") or []]
    techniques = [
        value for value in context.get("techniques") or [] if isinstance(value, dict)
    ]
    bandeau = "#b45309" if "n’a pas été livré" in str(context.get("status_text") or "") else "#15803d"

    # La capture montre le message dont il est question. Sans elle, l'avis
    # demande un avis sur quelque chose que le destinataire n'a pas vu. Elle est
    # rattachée au corps à l'expédition, sous cet identifiant.
    apercu_html = capture_block(context.get("has_preview"))

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
        for value in techniques
    )
    limites_html = (
        '<div style="margin-top:10px;font-size:12px;color:#64748b">'
        "<strong>Ce que je n’ai pas pu vérifier :</strong> "
        + escape(" ".join(limits))
        + " Cela ne veut pas dire que le message est dangereux.</div>"
        if limits
        else ""
    )
    risques_html = (
        '<div style="margin-top:10px">'
        + "".join(
            '<div style="margin:4px 0;padding:8px;background:#fee2e2;color:#991b1b;'
            f'border-left:4px solid #dc2626;border-radius:6px;font-size:13px">'
            f"{escape(value)}</div>"
            for value in risques
        )
        + "</div>"
        if risques
        else ""
    )

    return (
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;'
        'margin:0 auto;color:#0f172a">'
        # Aperçu du message concerné
        '<h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.5px;'
        'color:#64748b;margin:0 0 6px 0">Aperçu de l’email</h2>'
        # C'est la première ligne lue : elle porte la taille la plus grande de
        # l'avis, pour dire d'emblée ce qui s'est passé et ce qu'on attend.
        f'<div style="background:{bandeau};color:#ffffff;padding:14px 16px;'
        'border-radius:10px 10px 0 0;font-size:19px;font-weight:bold;'
        'line-height:1.3">'
        f"{statut}</div>"
        '<div style="border:1px solid #e2e8f0;border-top:0;border-radius:0 0 10px 10px;'
        'padding:11px 14px;font-size:14px">'
        f'<div style="font-weight:bold">{sujet}</div>'
        f'<div style="color:#475569;font-size:13px">De : {expediteur}</div>'
        "</div>"
        # La photo du message, avant tout commentaire sur celui-ci
        + apercu_html
        # Les deux colonnes : deux blocs fluides à largeur plafonnée. Le
        # tableau figé 50/50 broyait le texte sur iPhone (deux colonnes de
        # 180 px, un mot par ligne) ; des blocs inline-block se rangent côte à
        # côte quand la place existe et s'empilent d'eux-mêmes sur un écran
        # étroit. Sans media query : l'avis est un fragment sans <head>, et
        # tous les clients n'en respectent pas. Le font-size:0 du conteneur
        # évite qu'un espace entre les blocs ne les fasse passer à la ligne.
        +
        '<div style="margin-top:14px;font-size:0">'
        '<div style="display:inline-block;width:100%;max-width:320px;'
        'vertical-align:top;font-size:14px">'
        '<div style="padding:0 14px 12px 0">'
        '<div style="font-size:13px;font-weight:bold;color:#991b1b;margin-bottom:5px">'
        "Ce qui me gêne</div>"
        + _liste(concerns, "Rien de précis à te signaler.", "#7f1d1d")
        + "</div></div>"
        '<div style="display:inline-block;width:100%;max-width:320px;'
        'vertical-align:top;font-size:14px">'
        '<div style="padding:0 0 12px 0">'
        '<div style="font-size:13px;font-weight:bold;color:#166534;margin-bottom:5px">'
        "Ce qui me rassure</div>"
        + _liste(reassurances, "Rien de particulier.", "#14532d")
        + "</div></div></div>"
        # Le verdict, sous les deux colonnes, avec la technique employée
        '<div style="margin-top:14px;padding:11px 13px;background:#eff6ff;'
        'border-left:4px solid #2563eb;border-radius:8px">'
        '<div style="font-size:13px;font-weight:bold;color:#1e3a8a;margin-bottom:4px">'
        "Ce que j’en conclus</div>"
        f'<div style="font-size:14px;line-height:1.4">'
        f'{escape(str(context.get("decision") or ""))}</div>'
        f"{techniques_html}{limites_html}{risques_html}</div>"
        # Les trois réponses
        '<div style="margin-top:14px;font-size:13px;font-weight:bold">'
        "Que veux-tu faire ?</div>"
        + _boutons(str(context.get("action_address") or ""))
        + '<div style="font-size:11px;color:#64748b;line-height:1.4">'
        + (
            "L’image ci-dessus est une photo du message : rien n’y est cliquable, "
            "et son texte peut rester trompeur. "
            if apercu_html
            else ""
        )
        + "Si les boutons ne fonctionnent pas, réponds "
        "simplement A, B ou C à ce message.</div>"
        '<div style="margin-top:10px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail"
        # La référence du dossier. Elle ne demande rien et ne dit rien du
        # message : elle sert à en parler - à la console, à quelqu'un d'autre,
        # à soi-même dans trois semaines - sans avoir à le retrouver de tête.
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
