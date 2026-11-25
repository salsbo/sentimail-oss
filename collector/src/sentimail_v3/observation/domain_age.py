"""Âge d'un domaine à la réception, indépendant de la date du cache ou du rejeu."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def domain_age(data: dict[str, Any], captured_at: datetime | None) -> int | None:
    """Dérive l'âge sans modifier la preuve RDAP ; garde l'ancien âge en repli."""
    creation = data.get("creation_date")
    if isinstance(creation, str) and isinstance(captured_at, datetime):
        try:
            created = datetime.fromisoformat(creation.replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            received = captured_at
            if received.tzinfo is None:
                received = received.replace(tzinfo=timezone.utc)
            return (received - created).days
        except (ValueError, OverflowError):
            pass
    observed = data.get("age_days")
    if isinstance(observed, int) and not isinstance(observed, bool):
        return observed
    if isinstance(observed, str):
        try:
            return int(observed)
        except ValueError:
            pass
    return None
