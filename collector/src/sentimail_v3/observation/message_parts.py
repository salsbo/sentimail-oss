"""Sépare les paroles actuelles des citations, sans retirer de contenu.

Cette séparation décrit une présentation, jamais un échange authentifié :
un expéditeur peut fabriquer les en-têtes d'un fil qu'il cite.
"""

from __future__ import annotations

import re

from sentimail_v3.observation.dossier.hooks.visible_text import reply_html_text

_INTRO = re.compile(
    r"^(?:On .+ wrote:|Le .+ a écrit\s*:|"
    r"-{2,}\s*(?:Original Message|Forwarded message|Message d.origine)\s*-{2,}|"
    r"Début du message réexpédié\s*:)$",
    re.IGNORECASE,
)
_FROM = re.compile(r"^(?:De|From)\s*:", re.IGNORECASE)
_HEADER = re.compile(r"^(?:Envoyé|Sent|Date|À|To|Objet|Subject)\s*:", re.IGNORECASE)


def split_message_text(text: str) -> tuple[str, str]:
    """Garde les réponses intercalées ; reconnaît les en-têtes groupés.

    « De : » seul peut appartenir au message courant. Il ne commence un fil
    que si deux autres champs d'en-tête suivent dans les huit lignes.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    current: list[str] = []
    quoted: list[str] = []
    in_thread = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        grouped_headers = bool(_FROM.match(stripped)) and sum(
            bool(_HEADER.match(next_line.strip()))
            for next_line in lines[index + 1 : index + 9]
        ) >= 2
        if _INTRO.match(stripped) or grouped_headers:
            in_thread = True
        if in_thread or stripped.startswith(">"):
            quoted.append(line)
        else:
            current.append(line)
    return "\n".join(current).strip(), "\n".join(quoted).strip()


def message_parts(body_text: str | None, body_html: str | None) -> tuple[str, str]:
    """Privilégie le texte brut, sinon le HTML dont les citations sont marquées."""
    text = str(body_text or "").strip()
    return split_message_text(text or reply_html_text(str(body_html or "")))
