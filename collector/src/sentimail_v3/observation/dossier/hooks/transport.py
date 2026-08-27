from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from itertools import pairwise
from typing import ClassVar

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_IP = re.compile(r"\[([0-9a-f:.]+)\]", re.IGNORECASE)


class TransportHook(EvidenceHook):
    name: ClassVar[str] = "transport"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        received = [
            str(row["value_decoded"])
            for row in context.parsed.headers
            if row["name_normalized"] == "received"
        ]
        public_ips: set[str] = set()
        dates: list[datetime] = []
        for value in received[:50]:
            for candidate in _IP.findall(value):
                try:
                    parsed = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if parsed.is_global:
                    public_ips.add(parsed.compressed)
            if ";" in value:
                try:
                    parsed_date = parsedate_to_datetime(value.rsplit(";", 1)[1].strip())
                    dates.append(parsed_date.astimezone(UTC))
                except (TypeError, ValueError, OverflowError):
                    pass
        clues: list[Clue] = []
        if len(received) > 50:
            clues.append(
                Clue(
                    "CHAIN-001",
                    "RECEIVED_CHAIN_TOO_LONG",
                    "adverse",
                    30,
                    1.0,
                    "La chaîne de transport dépasse le budget d’analyse.",
                    {"hop_count": len(received)},
                    {"source": "header:received"},
                )
            )
        chronology_errors = sum(newer < older for newer, older in pairwise(dates))
        if chronology_errors:
            clues.append(
                Clue(
                    "CHAIN-002",
                    "RECEIVED_CHRONOLOGY_INCONSISTENT",
                    "adverse",
                    min(60, 25 + chronology_errors * 10),
                    0.85,
                    "Les dates de la chaîne Received ne sont pas chronologiquement cohérentes.",
                    {"inconsistencies": chronology_errors},
                    {"source": "header:received"},
                )
            )
        header_date = context.parsed.message.get("header_date")
        skew_hours: float | None = None
        if isinstance(header_date, datetime) and dates:
            skew_hours = abs((dates[0] - header_date.astimezone(UTC)).total_seconds()) / 3600
            if skew_hours > 48:
                clues.append(
                    Clue(
                        "CHAIN-003",
                        "HEADER_DATE_LARGE_SKEW",
                        "adverse",
                        min(55, int(20 + skew_hours / 24)),
                        0.82,
                        "La date déclarée diffère fortement de la date de transport.",
                        {"skew_hours": round(skew_hours, 2)},
                        {"source": "date+received"},
                    )
                )
        return clues, {
            "hop_count": len(received),
            "parsed_date_count": len(dates),
            "public_ips": sorted(public_ips),
            "chronology_inconsistencies": chronology_errors,
            "header_transport_skew_hours": round(skew_hours, 3) if skew_hours is not None else None,
            "observed_at": datetime.now(UTC).isoformat(),
        }
