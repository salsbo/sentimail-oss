from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from sentimail_v3.observation.dossier.models import Clue, InvestigationContext


class EvidenceHook(ABC):
    """Contrat minimal d'un enquêteur indépendant et non décisionnaire."""

    name: ClassVar[str]
    version: ClassVar[str]
    timeout_seconds: ClassVar[float] = 1.0

    @abstractmethod
    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        """Retourne des indices et les faits de travail du hook."""
