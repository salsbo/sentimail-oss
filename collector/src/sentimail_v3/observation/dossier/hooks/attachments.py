from __future__ import annotations

import re
from pathlib import PurePath
from typing import ClassVar

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_DANGEROUS = {"exe", "scr", "bat", "vbs", "js", "jar", "msi", "hta", "ps1", "lnk", "cmd", "com", "cpl", "dll"}
_MACRO = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam"}
_ARCHIVE = {"zip", "rar", "7z", "ace", "iso", "img"}
_LURE = re.compile(r"facture|invoice|paiement|colis|livraison|relev[ée]|contrat", re.IGNORECASE)

# Le markup actif d'une pièce jointe qui se présente comme image ou document.
# Un vrai SVG graphique n'a ni script, ni formulaire, ni décodage base64.
_ACTIVE_MARKUP = {
    "script": re.compile(r"<script\b", re.IGNORECASE),
    "foreign_object": re.compile(r"<foreignObject\b", re.IGNORECASE),
    "iframe": re.compile(r"<iframe\b", re.IGNORECASE),
    "form": re.compile(r"<form\b", re.IGNORECASE),
    "password_field": re.compile(r'type\s*=\s*["\']?password', re.IGNORECASE),
    "event_handler": re.compile(r"\bon(?:load|click|error|mouseover)\s*=", re.IGNORECASE),
    "base64_decode": re.compile(r"\batob\s*\(|\beval\s*\(|createObjectURL", re.IGNORECASE),
    "navigation": re.compile(r"(?:window\.)?location\s*=|location\.href", re.IGNORECASE),
}


class AttachmentHook(EvidenceHook):
    name: ClassVar[str] = "attachments"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        attachments = [part for part in context.parsed.parts if part["is_attachment"]]
        clues: list[Clue] = []
        total_bytes = 0
        dangerous = 0
        archives = 0
        for part in attachments[:50]:
            filename = str(part.get("filename") or "")
            suffixes = [value.lstrip(".").casefold() for value in PurePath(filename).suffixes]
            final = suffixes[-1] if suffixes else ""
            size = int(part.get("decoded_size_bytes") or 0)
            total_bytes += size
            if final in _DANGEROUS:
                dangerous += 1
                double = len(suffixes) >= 2 and suffixes[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}
                clues.append(
                    Clue(
                        "ATT-002" if double else "ATT-001",
                        "ATTACHMENT_DOUBLE_EXTENSION" if double else "ATTACHMENT_EXECUTABLE",
                        "adverse",
                        98 if double else 92,
                        0.99,
                        "Une pièce jointe exécutable utilise une double extension trompeuse."
                        if double
                        else "Une pièce jointe utilise une extension exécutable dangereuse.",
                        {"extension": final, "lure_name": bool(_LURE.search(filename))},
                        {"source": "mime:filename"},
                    )
                )
            elif final in _MACRO:
                clues.append(
                    Clue(
                        "ATT-003",
                        "ATTACHMENT_MACRO_FORMAT",
                        "adverse",
                        65,
                        0.92,
                        "Une pièce jointe Office peut contenir des macros.",
                        {"extension": final},
                        {"source": "mime:filename"},
                    )
                )
            elif final in _ARCHIVE:
                archives += 1
                clues.append(
                    Clue(
                        "ATT-004",
                        "ATTACHMENT_ARCHIVE_REQUIRES_SANDBOX",
                        "neutral",
                        0,
                        1.0,
                        "Une archive doit être inspectée dans le sandbox fichier.",
                        {"extension": final},
                        {"source": "mime:filename"},
                    )
                )
            declared = str(part.get("content_type") or "")
            if final == "pdf" and declared != "application/pdf":
                clues.append(
                    Clue(
                        "ATT-005",
                        "ATTACHMENT_MIME_EXTENSION_MISMATCH",
                        "adverse",
                        45,
                        0.9,
                        "L’extension de la pièce jointe ne correspond pas au type MIME déclaré.",
                        {"extension": final, "declared_type": declared},
                        {"source": "mime"},
                    )
                )
            if size > 25 * 1024 * 1024:
                clues.append(
                    Clue(
                        "ATT-006",
                        "ATTACHMENT_TOO_LARGE_FOR_SANDBOX",
                        "adverse",
                        55,
                        1.0,
                        "Une pièce jointe dépasse la limite d’analyse profonde.",
                        {"size_bytes": size},
                        {"source": "analysis-budget"},
                    )
                )
            # Une pièce jointe SVG, XML ou HTML qui porte du markup actif -
            # script, formulaire, décodage base64 côté navigateur - est une
            # page web déguisée en image ou en document : le vecteur de
            # phishing en plus forte croissance, sans lien scannable dans le
            # mail. Le texte de la part est exposé par le parseur.
            markup = str(part.get("text_content") or "")
            if markup and part.get("maintype") in {"image", "text", "application"}:
                found = [
                    label
                    for label, pattern in _ACTIVE_MARKUP.items()
                    if pattern.search(markup)
                ]
                if found:
                    clues.append(
                        Clue(
                            "ATT-007",
                            "ATTACHMENT_ACTIVE_MARKUP",
                            "adverse",
                            min(90, 55 + 12 * len(found)),
                            0.9,
                            "Une pièce jointe qui devrait être une image ou un "
                            "document contient du code actif (script, "
                            "formulaire, décodage) : page web déguisée.",
                            {
                                "content_type": part.get("content_type"),
                                "filename": filename,
                                "markers": found,
                            },
                            {"source": "attachment:markup"},
                        )
                    )
        if len(attachments) > 50:
            clues.append(
                Clue(
                    "ATT-006",
                    "ATTACHMENT_ANALYSIS_INCOMPLETE",
                    "adverse",
                    60,
                    1.0,
                    "Toutes les pièces jointes n’ont pas pu être inventoriées.",
                    {"total": len(attachments), "analyzed": 50},
                    {"source": "analysis-budget"},
                )
            )
        return clues, {
            "count": len(attachments),
            "analyzed_count": min(50, len(attachments)),
            "total_bytes": total_bytes,
            "dangerous_count": dangerous,
            "archive_count": archives,
            "complete": len(attachments) <= 50,
        }
