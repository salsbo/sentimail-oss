"""Dossier probatoire et hooks d'observation de SentiMail V3."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentimail_v3.observation.dossier.hook import EvidenceHook
    from sentimail_v3.observation.dossier.models import HookResult, InvestigationContext


def build_hooks() -> list["EvidenceHook"]:
    """Charge le pipeline lorsque demandé, sans cycle avec ses propres hooks."""
    from sentimail_v3.observation.dossier.pipeline import build_hooks as build
    return build()


async def run_hooks(context: "InvestigationContext") -> list["HookResult"]:
    """Le simple import d'un modèle de dossier ne charge pas tous les hooks."""
    from sentimail_v3.observation.dossier.pipeline import run_hooks as run
    return await run(context)

__all__ = ["build_hooks", "run_hooks"]
