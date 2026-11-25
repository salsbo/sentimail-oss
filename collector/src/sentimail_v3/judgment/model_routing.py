"""Choisir le coût du juge à partir du dossier, jamais du correspondant.

Le modèle économique ne peut rendre une décision contraignante que sur un
dossier simple, complet et univoque. Le mode ``shadow`` lui pose la question
mais conserve toujours la réponse premium comme verdict : c'est l'échantillon
qui permet d'établir la qualité avant de basculer vers ``enforced``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import asyncpg

JUDGMENT_RULES_VERSION = "verdict-final-v6-real-doubt"


@dataclass(frozen=True)
class ModelRouting:
    mode: str
    economy_model: str
    premium_model: str
    confidence_margin: float

    @property
    def enabled(self) -> bool:
        return self.mode in {"shadow", "enforced"}


async def load_model_routing(
    pool: asyncpg.Pool[Any], fallback_model: str
) -> ModelRouting:
    row = await pool.fetchrow(
        "SELECT mode,economy_model_name,premium_model_name,confidence_margin "
        "FROM verdict_model_routing WHERE singleton=true"
    )
    if row is None:
        return ModelRouting("off", fallback_model, fallback_model, 0.0)
    return ModelRouting(
        str(row["mode"]),
        str(row["economy_model_name"]),
        str(row["premium_model_name"]),
        float(row["confidence_margin"]),
    )


def _clue_directions(dossier: dict[str, object]) -> tuple[bool, bool]:
    clues = dossier.get("clues")
    values = clues if isinstance(clues, list) else []
    favorable = any(
        isinstance(clue, dict) and clue.get("direction") == "favorable"
        for clue in values
    )
    adverse = any(
        isinstance(clue, dict) and clue.get("direction") == "adverse"
        for clue in values
    )
    return favorable, adverse


def initial_route(dossier: dict[str, object]) -> tuple[str, str]:
    """Retourne le palier initial et son motif, sur les seuls faits du dossier."""
    rules = dossier.get("judgment_rules")
    rules = rules if isinstance(rules, dict) else {}
    favorable, adverse = _clue_directions(dossier)
    if rules.get("identity_destination_conflict"):
        return "premium", "identity_destination_conflict"
    if rules.get("material_danger_evidence"):
        return "premium", "material_danger"
    if rules.get("authenticated_sender_policy") == "hold":
        return "premium", "authenticated_hold"
    if not rules.get("static_investigation_complete"):
        return "premium", "static_analysis_incomplete"
    if (
        rules.get("incomplete_analysis_is_decisive", True)
        and not rules.get("deep_execution_complete")
    ):
        return "premium", "deep_analysis_incomplete"
    if favorable and adverse:
        return "premium", "mixed_evidence"
    if adverse:
        # Ce palier ne peut autoriser qu'une livraison sans charge : commencer
        # par lui sur une charge seule imposait toujours un second appel.
        return "premium", "adverse_only_evidence"
    if not favorable and not adverse:
        return "premium", "no_directional_evidence"
    return "economy", "simple_univocal_dossier"


def escalation_reasons(
    result: dict[str, object],
    dossier: dict[str, object],
    confidence_margin: float,
) -> list[str]:
    """Ce qui interdit au candidat économique de devenir contraignant."""
    rules = dossier.get("judgment_rules")
    rules = rules if isinstance(rules, dict) else {}
    favorable, adverse = _clue_directions(dossier)
    decision = str(result.get("delivery_decision") or "")
    confidence = float(result.get("confidence") or 0.0)
    threshold = float(rules.get("confidence_required") or 1.0)
    reasons: list[str] = []
    # Le palier économique ne peut conclure seul qu'à une livraison simple.
    # Junk reste récupérable, mais une différence de classement est précisément
    # ce que la phase de comparaison doit mesurer avant de lui faire confiance.
    if decision != "deliver":
        reasons.append("non_delivery_decision")
    if bool(result.get("verdict_doubt", result.get("judge_doubt"))):
        reasons.append("verdict_doubt")
    required_confidence = round(min(1.0, threshold + confidence_margin), 6)
    if confidence + 1e-9 < required_confidence:
        reasons.append("confidence_margin")
    if decision == "deliver" and adverse:
        reasons.append("adverse_evidence_on_delivery")
    if decision == "junk" and favorable:
        reasons.append("favorable_evidence_on_junk")
    return reasons


def same_outcome(economy: dict[str, object], premium: dict[str, object]) -> bool:
    return (
        economy.get("classification") == premium.get("classification")
        and economy.get("delivery_decision") == premium.get("delivery_decision")
    )


def unsafe_delivery_divergence(
    economy: dict[str, object], premium: dict[str, object]
) -> bool:
    """Le cas bloquant : Flash livrerait là où Pro ne livre pas en réception."""
    return (
        economy.get("delivery_decision") == "deliver"
        and premium.get("delivery_decision") != "deliver"
    )
