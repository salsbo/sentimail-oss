"""La mise en forme du récapitulatif, et le bulletin qu'on lui renvoie.

Le récapitulatif posait sa question en texte nu quand les avis avaient déjà une
charte : un bandeau, des cartes, trois lettres colorées. La même question posée
de deux façons s'apprend deux fois, et celle qui ressemble le moins à un avis
est celle à laquelle on répond le moins.

Répondre demandait d'écrire « 1 A, 2 B » de mémoire. La liste est sous les yeux,
mais la réponse, elle, s'écrit à l'aveugle. D'où les cases : elles sont là où
l'œil est déjà, et cocher est le seul geste que le courrier autorise.

Trois contraintes propres au courrier dictent la forme retenue :

- une vraie case de formulaire n'existe pas en messagerie ; les clients la
  suppriment, et rien ne partirait avec la réponse. La case est donc faite de
  deux crochets, en toutes lettres, qu'on remplit d'une croix comme sur un
  bulletin de vote ;
- un bouton n'exécute rien : il ouvre un message déjà rédigé. Le bouton du
  récapitulatif ouvre donc le bulletin entier, cases vides, prêt à cocher - ce
  qui met la réponse dans le texte saisi, là où elle est lue sans réserve ;
- ce corps prérempli voyage dans une URL, et plusieurs clients tronquent au-delà
  de deux mille caractères. Le bulletin cliquable s'arrête donc à ``MAX_BULLETIN``
  dossiers, puis se rétrécit tant qu'il dépasse - un bulletin amputé se
  cocherait dans le vide.

La référence en tête (« D-3f9c1a ») dit de quel envoi ces cases proviennent.
Sans elle, une réponse d'hier recitée dans un fil appliquerait ses croix aux
dossiers d'aujourd'hui, qui portent les mêmes numéros.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote, urlencode

from sentimail_v3.conversation.choice_answers import (
    GRIS,
    ROUGE,
    VERT,
    render_action_button,
)
from sentimail_v3.conversation.review_notice import ACTION_TOKEN_PLACEHOLDER

__all__ = [
    "ACTION_TOKEN_PLACEHOLDER",
    "MAX_BULLETIN",
    "ballot_mailto",
    "build_text",
    "render_digest_html",
]

# Au-delà, l'URL du bulletin dépasse ce que les clients transportent.
MAX_BULLETIN = 12
# Marge sous la limite basse observée (2000), pour l'objet et le schéma.
LONGUEUR_MAX_LIEN = 1900
# Un objet long ne rend pas le dossier plus reconnaissable, il rend le
# bulletin intransportable.
OBJET_MAX = 46
OBJET_MAX_BULLETIN = 38

SUJET_REPONSE = f"Re: [SentiMail] Mon bulletin · {ACTION_TOKEN_PLACEHOLDER}"

BLEU = "#2563eb"

# Ce que chaque lettre décide. Écrit une seule fois : la page, le texte et le
# bulletin disent la même chose, sinon la réponse ne veut plus dire la même
# chose selon l'endroit où on l'a lue.
LETTRES = (
    ("A", "livrer", "livre-le, cet expéditeur est fiable", VERT),
    ("B", "bloquer", "ne le livre pas, retiens les prochains", ROUGE),
    ("C", "autre", "autre chose, explique après les deux-points", GRIS),
)


def _objet(valeur: object, taille: int = OBJET_MAX) -> str:
    texte = str(valeur or "(sans objet)").strip() or "(sans objet)"
    return texte[:taille]


def ballot_lines(items: list[dict[str, object]]) -> list[str]:
    """Un dossier, deux lignes : ce dont il s'agit, puis les cases."""
    lignes: list[str] = []
    for item in items:
        lignes.append(f"{item['number']}. {_objet(item.get('subject'), OBJET_MAX_BULLETIN)}")
        lignes.append("   [ ] A   [ ] B   [ ] C : ")
        lignes.append("")
    return lignes


def ballot_body(
    items: list[dict[str, object]], reference: str, total: int | None = None
) -> str:
    """Le bulletin prérempli : ce que le bouton ouvre, cases vides.

    Quand il ne porte pas tout, il le dit et nomme le premier dossier absent.
    Un bulletin tronqué en silence se referme sur douze lignes alors que vingt
    attendent : on le renvoie en croyant avoir tout traité, et le reste dort
    jusqu'au prochain envoi.
    """
    entete = [
        "Bonjour MAIA,",
        "",
        f"Voici mes réponses. Récapitulatif {reference}",
        "Je mets une croix dans une seule case par message.",
        "",
        "A = livre-le, cet expéditeur est fiable",
        "B = ne le livre pas, retiens les prochains",
        "C = autre chose, à écrire après les deux-points",
        "",
    ]
    reste = (total or len(items)) - len(items)
    pied: list[str] = []
    if reste > 0 and items:
        suivant = int(items[-1]["number"]) + 1
        pied = [
            f"(mes {reste} autre(s) message(s) restent à cocher dans ton",
            f"récapitulatif, ou à écrire ici : « {suivant} A », « {suivant + 1} B »)",
            "",
        ]
    return "\n".join([*entete, *ballot_lines(items), *pied, "Merci !", ""])


def ballot_mailto(
    action_address: str, items: list[dict[str, object]], reference: str
) -> str:
    """Le lien qui ouvre le bulletin, raccourci tant qu'il ne passe pas.

    Un client qui tronque une URL ne prévient pas : le bulletin arriverait
    amputé de ses derniers dossiers, cochés dans le vide. Mieux vaut en
    proposer moins et redemander le reste au prochain envoi.
    """
    total = len(items)
    retenus = list(items)[:MAX_BULLETIN]
    while retenus:
        # quote_via=quote impose le pourcentage-encodage : par défaut urlencode
        # écrit l'espace « + », convention des formulaires web qu'un client de
        # messagerie n'applique pas à un mailto:.
        lien = "mailto:" + action_address + "?" + urlencode(
            {
                "subject": SUJET_REPONSE,
                "body": ballot_body(retenus, reference, total),
            },
            quote_via=quote,
        )
        if len(lien) <= LONGUEUR_MAX_LIEN or len(retenus) == 1:
            return lien
        retenus = retenus[:-1]
    return "mailto:" + action_address + "?" + urlencode(
        {"subject": SUJET_REPONSE, "body": ballot_body([], reference)},
        quote_via=quote,
    )


def _phrase_abandons(nombre: int) -> str:
    """Ce que MAIA a cessé de suivre, dit une fois, sans courrier de plus.

    Un dossier abandonné quitte la file en silence : rien ne distinguerait
    alors « tu as tout traité » de « j'ai renoncé à te le demander ». La
    précision qu'aucun n'a été livré est le fond du sujet : ne pas répondre
    n'a rien autorisé.
    """
    if nombre <= 0:
        return ""
    return (
        f"J’ai cessé de suivre {nombre} message"
        + ("s" if nombre > 1 else "")
        + " resté"
        + ("s" if nombre > 1 else "")
        + " sans réponse : aucun n’a été livré."
    )


def build_text(
    items: list[dict[str, object]],
    total: int,
    reference: str,
    action_address: str,
    abandoned: int = 0,
) -> str:
    """Le récapitulatif en texte : la même chose, sans mise en forme.

    C'est ce que lisent les clients qui refusent le HTML, et c'est ce qui est
    cité quand on clique simplement sur « Répondre ». Les cases y sont donc
    aussi : cocher dans la citation doit rester possible.
    """
    lignes = [
        f"{total} message{'s' if total > 1 else ''} attendent ton avis.",
        f"Récapitulatif {reference}",
        "",
        "Coche une seule case par message, puis renvoie-moi ce message.",
        "Tu peux aussi écrire « 1 A », « 2 B » : les deux se valent.",
        "",
        "A = livre-le, cet expéditeur est fiable",
        "B = ne le livre pas, retiens les prochains",
        "C = autre chose, à écrire après les deux-points",
        "",
        f"Pour répondre sans citer, écris à {action_address}.",
        "",
        "─────────────────────────────",
        "",
    ]
    for item in items:
        lignes.extend(
            [
                f"{item['number']}. {_objet(item.get('subject'))}",
                f"   de {str(item.get('sender') or '(expéditeur inconnu)')[:70]}",
                f"   reçu le {item.get('received') or ''}".rstrip(),
                "   [ ] A   [ ] B   [ ] C : ",
                "",
            ]
        )
    if total > len(items):
        lignes.append(f"(et {total - len(items)} autre(s) que je te montrerai ensuite)")
        lignes.append("")
    lignes.append("Tu peux n’en traiter que quelques-uns : je te redemanderai le reste.")
    abandons = _phrase_abandons(abandoned)
    if abandons:
        lignes.extend(["", abandons])
    lignes.append("")
    lignes.append("— MAIA, ton assistante SentiMail")
    return "\n".join(lignes)


def _cases_html() -> str:
    """Les trois cases d'un dossier, à chasse fixe pour qu'on puisse y écrire.

    Les crochets sont du texte, pas une image ni une case de formulaire : c'est
    ce qui permet d'y poser une croix dans la citation, sur n'importe quel
    client, sans que rien n'ait été prévu pour lui.
    """
    cases = "".join(
        '<span style="white-space:nowrap;margin-right:14px">'
        '<span style="font-family:Menlo,Consolas,monospace;font-size:14px">[&nbsp;]</span> '
        f'<strong style="color:{couleur}">{lettre}</strong> '
        f'<span style="color:#475569">{escape(libelle)}</span>'
        "</span>"
        for lettre, libelle, _, couleur in LETTRES
    )
    return (
        '<div style="margin-top:6px;font-size:13px;line-height:1.9">'
        f"{cases}</div>"
    )


def _carte(item: dict[str, object]) -> str:
    numero = escape(str(item.get("number") or ""))
    sujet = escape(_objet(item.get("subject")))
    expediteur = escape(str(item.get("sender") or "(expéditeur inconnu)")[:70])
    recu = escape(str(item.get("received") or ""))
    return (
        '<div style="border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;'
        'margin-bottom:8px">'
        f'<div style="font-size:14px;font-weight:bold">{numero}. {sujet}</div>'
        f'<div style="color:#475569;font-size:13px">De : {expediteur}'
        + (f" · reçu le {recu}" if recu else "")
        + "</div>"
        + _cases_html()
        + "</div>"
    )


def render_digest_html(context: dict[str, object]) -> str:
    """La page du récapitulatif : le bandeau, les dossiers, le bulletin."""
    items = [value for value in context.get("items") or [] if isinstance(value, dict)]
    total = int(context.get("total") or len(items))
    reference = str(context.get("reference") or "")
    action_address = str(context.get("action_address") or "")
    abandons = int(context.get("abandoned") or 0)
    reste = total - len(items)
    legende = "".join(
        f'<div style="margin:2px 0"><strong style="color:{couleur}">{lettre}</strong> '
        f"— {escape(sens)}</div>"
        for lettre, _, sens, couleur in LETTRES
    )
    return (
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;'
        'margin:0 auto;color:#0f172a">'
        # Le bandeau dit d'emblée ce qui est attendu, comme sur un avis.
        '<div style="background:#b45309;color:#ffffff;padding:14px 16px;'
        'border-radius:10px 10px 0 0;font-size:19px;font-weight:bold;line-height:1.3">'
        f"{total} message{'s' if total > 1 else ''} attendent ton avis</div>"
        '<div style="border:1px solid #e2e8f0;border-top:0;'
        'border-radius:0 0 10px 10px;padding:11px 14px;font-size:13px">'
        '<div style="margin-bottom:6px">Coche une case par message, puis renvoie-moi '
        "ce message. Une seule croix par ligne.</div>"
        f"{legende}"
        f'<div style="margin-top:6px;color:#64748b;font-size:11px">Récapitulatif '
        f"{escape(reference)}</div>"
        "</div>"
        # Le bouton ouvre le bulletin entier : la réponse est alors du texte
        # saisi, et non une citation modifiée.
        + render_action_button(
            "bulletin",
            "Répondre en cochant",
            "Ouvre une réponse déjà rédigée, il ne reste qu’à cocher",
            BLEU,
            ballot_mailto(action_address, items, reference),
        )
        + "".join(_carte(item) for item in items)
        + (
            '<div style="font-size:12px;color:#64748b;margin-bottom:8px">'
            f"(et {reste} autre(s) que je te montrerai ensuite)</div>"
            if reste > 0
            else ""
        )
        + (
            '<div style="margin:10px 0;padding:8px 11px;background:#f1f5f9;'
            'border-left:4px solid #94a3b8;border-radius:6px;font-size:12px;'
            'color:#475569">' + escape(_phrase_abandons(abandons)) + "</div>"
            if abandons > 0
            else ""
        )
        + '<div style="font-size:11px;color:#64748b;line-height:1.4">'
        "Si le bouton ne fonctionne pas, réponds à ce message et coche "
        "directement dans le texte cité, ou écris « 1 A », « 2 B ». "
        "Tu peux n’en traiter que quelques-uns : je te redemanderai le reste."
        "</div>"
        '<div style="margin-top:10px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail</div>"
        "</div>"
    )
