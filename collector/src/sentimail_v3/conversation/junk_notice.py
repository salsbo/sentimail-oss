"""L'avis télégraphique qui remplace un message classé indésirable (V2).

Le message hostile ne voyage pas en entier : ni lien actif, ni contenu actif.
L'avis tient à l'identité observée (adresse affichée et adresse réelle),
l'objet, trois motifs courts, une photo inerte du message, quelques extraits
textuels inertes et un seul geste utile - livrer le message si le classement
est faux.
"""

from __future__ import annotations

from sentimail_v3.conversation.choice_answers import render_choices
from sentimail_v3.conversation.choice_registry import (
    choice_presentations,
    response_links,
)
from sentimail_v3.conversation.mail_layout import (
    bullets_block,
    excerpts_block,
    footer,
    headline,
    meta_block,
    status_pill,
    wrap_shell,
)
from sentimail_v3.conversation.review_notice import capture_block
from sentimail_v3.observation.risk_text import neutralize_excerpt_links  # noqa: F401

JUNK_TOKEN_PLACEHOLDER = "S3-JUNK-TOKEN-PLACEHOLDER"

# Voir review_notice.SUJET_REPONSE : la séquence machine vit dans l'objet.
SUJET_REPONSE = f"Re: [SentiMail] Ma réponse · {JUNK_TOKEN_PLACEHOLDER}"

_HEADLINE = (
    "Message écarté automatiquement. Tu n'as rien à faire, "
    "sauf s'il s'agit d'une erreur."
)


def junk_choice_links(action_address: str) -> dict[str, str]:
    """Les réponses possibles, prêtes à partir."""
    return response_links(action_address, SUJET_REPONSE, "junk")


def _boutons(action_address: str) -> str:
    """Le seul geste utile : récupérer un classement erroné."""
    choix = [choice.render_tuple() for choice in choice_presentations("junk")]
    return render_choices(choix, junk_choice_links(action_address))


def _meta_rows(context: dict[str, object]) -> list[tuple[str, str, bool, bool]]:
    sujet = str(context.get("subject") or "(sans objet)")
    rows: list[tuple[str, str, bool, bool]] = [("Objet", sujet, False, False)]

    sender_lines = context.get("sender_lines")
    if isinstance(sender_lines, list) and sender_lines:
        for ligne in sender_lines:
            libelle, _, valeur = str(ligne).partition(" : ")
            if not valeur:
                continue
            rows.append((libelle, valeur, True, "différente" in libelle))
    else:
        expediteur = str(context.get("sender") or "(expéditeur inconnu)")
        rows.append(("De", expediteur, True, False))
    return rows


def render_junk_html(context: dict[str, object]) -> str:
    """L'avis compact V2 ; le contenu original n'y est jamais recopié en entier."""
    dangereux = str(context.get("verdict") or "") in {"dangerous", "malicious"}
    raisons = [str(value).rstrip(". ") for value in context.get("reasons") or []][:3]
    excerpts = [str(value) for value in context.get("message_excerpts") or []][:3]
    reference = str(context.get("reference") or "")

    if dangereux:
        pill = status_pill(
            "DANGEREUX · CLASSÉ EN INDÉSIRABLES",
            color="#991b1b",
            background="#fee2e2",
        )
    else:
        pill = status_pill(
            "CLASSÉ EN INDÉSIRABLES · AUCUNE ACTION REQUISE",
            color="#475569",
            background="#f1f5f9",
        )

    inner = (
        pill
        + headline(_HEADLINE)
        + meta_block(_meta_rows(context))
        + bullets_block(
            "Motifs",
            raisons or ["Analyse : plusieurs indices concordants"],
        )
        + capture_block(
            context.get("has_preview"),
            en_grand=bool(context.get("has_full_preview")),
        )
        + excerpts_block("Aperçu inerte", excerpts)
        + _boutons(str(context.get("action_address") or ""))
        + footer(
            '<strong style="color:#475569">MAIA</strong> · Aucune action requise',
            reference=reference,
        )
    )
    return wrap_shell(inner)
