from __future__ import annotations

from typing import ClassVar

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext


class StructureHook(EvidenceHook):
    name: ClassVar[str] = "structure"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        message = context.parsed.message
        defects = list(message["parser_defects"])
        clues: list[Clue] = []
        if defects:
            clues.append(
                Clue(
                    "STRUCT-002",
                    "STRUCT_PARSER_DEFECTS",
                    "adverse",
                    10,
                    0.9,
                    f"Le parseur a signalé {len(defects)} défaut(s) structurel(s).",
                    {"defects": defects},
                    {"source": "python.email.parser"},
                )
            )
        else:
            clues.append(
                Clue(
                    "STRUCT-001",
                    "STRUCT_PARSEABLE",
                    "favorable",
                    5,
                    1.0,
                    "Le message est analysable sans défaut structurel signalé.",
                    provenance={"source": "python.email.parser"},
                )
            )

        message_id = message.get("message_id")
        clues.append(
            Clue(
                "STRUCT-003" if message_id else "STRUCT-004",
                "STRUCT_MESSAGE_ID_PRESENT"
                if message_id
                else "STRUCT_MESSAGE_ID_MISSING",
                "favorable" if message_id else "adverse",
                3,
                1.0,
                "Un Message-ID est présent."
                if message_id
                else "Le Message-ID est absent.",
                {"present": bool(message_id)},
                {"source": "header:message-id"},
            )
        )

        date_valid = bool(message.get("header_date"))
        clues.append(
            Clue(
                "DATE-001" if date_valid else "DATE-002",
                "DATE_PARSEABLE" if date_valid else "DATE_MISSING_OR_INVALID",
                "favorable" if date_valid else "adverse",
                2 if date_valid else 4,
                1.0,
                "La date déclarée est analysable."
                if date_valid
                else "La date déclarée est absente ou invalide.",
                {
                    "raw": message.get("header_date_raw"),
                    "parse_error": message.get("header_date_parse_error"),
                },
                {"source": "header:date"},
            )
        )
        return clues, {
            "header_count": len(context.parsed.headers),
            "mime_part_count": len(context.parsed.parts),
            "parser_defect_count": len(defects),
        }
