"""La mise en forme du récapitulatif, et le bulletin qu'on lui renvoie.

Le récapitulatif posait sa question en texte nu quand les avis avaient déjà une
charte : un bandeau, des cartes, trois lettres colorées. La même question posée
de deux façons s'apprend deux fois, et celle qui ressemble le moins à un avis
est celle à laquelle on répond le moins.

Répondre demandait d'écrire « 1 A, 2 B » de mémoire. La liste est sous les yeux,
mais la réponse, elle, s'écrit à l'aveugle. D'où les cases : elles sont là où
l'œil est déjà, et cocher est le seul geste que le courrier autorise.

Le récapitulatif conserve uniquement les blocs des messages et leurs cases.
La réponse se fait avec la fonction « Répondre » de la messagerie, en cochant
le texte cité ou en écrivant les numéros et les lettres.

La référence en tête (« D-3f9c1a ») dit de quel envoi ces cases proviennent.
Sans elle, une réponse d'hier recitée dans un fil appliquerait ses croix aux
dossiers d'aujourd'hui, qui portent les mêmes numéros.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote, urlencode

from sentimail_v3.conversation.choice_registry import choice_presentations
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
# Marge sous la limite basse observée (2000), jeton final compris.
LONGUEUR_MAX_LIEN = 1900
BALLOT_TOKEN_PREFIX = "S3-BALLOT-"
# Un objet long ne rend pas le dossier plus reconnaissable, il rend le
# bulletin intransportable.
OBJET_MAX = 46
OBJET_MAX_BULLETIN = 38

SUJET_REPONSE = f"Re: [SentiMail] Mon bulletin · {ACTION_TOKEN_PLACEHOLDER}"

# Ce que chaque lettre décide. Écrit une seule fois : la page, le texte et le
# bulletin disent la même chose, sinon la réponse ne veut plus dire la même
# chose selon l'endroit où on l'a lue.
LETTRES = tuple(choice.render_tuple() for choice in choice_presentations("digest"))


def _objet(valeur: object, taille: int = OBJET_MAX) -> str:
    texte = str(valeur or "(sans objet)").strip() or "(sans objet)"
    return texte[:taille]


def ballot_lines(items: list[dict[str, object]]) -> list[str]:
    """Chaque choix emporte les identités et motifs qui permettent de décider."""
    lignes: list[str] = []
    for item in items:
        lignes.append(f"{item['number']}. {_objet(item.get('subject'), OBJET_MAX_BULLETIN)}")
        lignes.extend(_decision_context(item))
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
        f"Récapitulatif {reference}. Une croix par message.",
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
            f"({reste} autre(s) message(s) : boutons suivants, à partir du n°{suivant},",
            f"ou réponse écrite : « {suivant} A ».)",
            "",
        ]
    return "\n".join([*entete, *ballot_lines(items), *pied, "Merci !", ""])


def ballot_mailto(
    action_address: str, items: list[dict[str, object]], reference: str
) -> str:
    """Le lien qui ouvre le bulletin, raccourci tant qu'il ne passe pas.

    Un client qui tronque une URL ne prévient pas : le bulletin arriverait
    amputé de ses derniers dossiers, cochés dans le vide. Les dossiers suivants
    sont proposés par les autres boutons du récapitulatif.
    """
    return _select_ballot(action_address, items, reference)[1]


def _select_ballot(
    action_address: str, items: list[dict[str, object]], reference: str
) -> tuple[list[dict[str, object]], str]:
    """Un lot de dossiers complets ; jamais d'adresse ni de motif amputé."""
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
        if len(lien.replace(ACTION_TOKEN_PLACEHOLDER, "S3-ACTION:" + "x" * 43)) <= LONGUEUR_MAX_LIEN:
            return retenus, lien
        retenus = retenus[:-1]
    return [], ""


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


def sequence_hint(nombre: int) -> str:
    """La consigne « une suite de lettres », avec un exemple à la taille de la liste.

    Sur téléphone, cocher est pénible ; « ABA » ne l'est pas. L'exemple a la
    longueur de la liste envoyée, pour que l'ordre se voie. Un seul dossier
    n'en a pas besoin : une lettre seule suffit déjà.
    """
    if nombre < 2:
        return ""
    lettres = "".join("AB"[index % 2] for index in range(nombre))
    detail = ", ".join(f"{index + 1} {lettre}" for index, lettre in enumerate(lettres))
    return (
        f"Sur téléphone, réponds par la suite des lettres dans l’ordre de la liste "
        f"(A ou B seulement) : « {lettres} » vaut {detail}."
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
        *([sequence_hint(len(items))] if len(items) >= 2 else []),
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
                f"   reçu le {item.get('received') or ''}".rstrip(),
                *_decision_context(item),
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


def _sender_lines(item: dict[str, object]) -> list[str]:
    """Séparer le nom annoncé de l'adresse complète, y compris en texte brut."""
    return item.get("identities") or [f"De : {item.get('sender') or '(expéditeur inconnu)'}"]


def _decision_context(item: dict[str, object]) -> list[str]:
    """Le même contexte dans le courrier et dans la réponse préremplie."""
    return [
        *[f"   {value}" for value in _sender_lines(item)],
        *[f"   {value}" for value in item.get("addresses") or []],
        "   Pourquoi je te demande :",
        *[
            f"   - {value}"
            for value in item.get("concerns") or ["Aucun point défavorable précis disponible."]
        ],
        *[f"   Limite d’analyse : {value}" for value in item.get("limits") or []],
    ]


def _carte(item: dict[str, object]) -> str:
    numero = escape(str(item.get("number") or ""))
    sujet = escape(_objet(item.get("subject")))
    expediteur = "".join(
        f'<div style="color:#475569;font-size:13px">{escape(str(value))}</div>'
        for value in _sender_lines(item)
    )
    recu = escape(str(item.get("received") or ""))
    addresses = "".join(
        f'<div style="color:#475569;font-size:12px">{escape(str(value))}</div>'
        for value in item.get("addresses") or []
    )
    concerns = "".join(
        f'<li style="margin:3px 0">{escape(str(value))}</li>'
        for value in item.get("concerns") or ["Aucun point défavorable précis disponible."]
    )
    limits = "".join(
        '<div style="margin-top:5px;color:#64748b;font-size:12px">'
        f'Limite d’analyse : {escape(str(value))}</div>'
        for value in item.get("limits") or []
    )
    return (
        '<div style="border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;'
        'margin-bottom:8px;overflow-wrap:anywhere;word-break:break-word">'
        f'<div style="font-size:14px;font-weight:bold">{numero}. {sujet}</div>'
        + expediteur
        + (f'<div style="color:#64748b;font-size:12px">Reçu le {recu}</div>' if recu else "")
        + addresses
        + '<div style="margin-top:8px;font-size:12px;line-height:1.45">'
        '<strong>Pourquoi je te demande :</strong>'
        '<ul style="margin:4px 0 0;padding-left:18px">'
        + concerns
        + "</ul></div>"
        + limits
        + _cases_html()
        + "</div>"
    )


def render_digest_html(context: dict[str, object]) -> str:
    """La page du récapitulatif : le bandeau et les blocs des messages."""
    items = [value for value in context.get("items") or [] if isinstance(value, dict)]
    total = int(context.get("total") or len(items))
    reference = str(context.get("reference") or "")
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
        "Réponds à ce message et coche "
        "directement dans le texte cité, ou écris « 1 A », « 2 B ». "
        + escape(sequence_hint(len(items)))
        + " Tu peux n’en traiter que quelques-uns : je te redemanderai le reste."
        "</div>"
        '<div style="margin-top:10px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail</div>"
        "</div>"
    )
