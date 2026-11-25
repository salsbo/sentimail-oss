"""Plan lisible des étapes : une préférence, un OTP qualifié, ou une enquête."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisPlan:
    path: str
    stages: tuple[str, ...]
    version: str = "sentimail-analysis-plan-1"


def plan_for(*, authenticated_hold: bool = False, qualified_otp: bool = False) -> AnalysisPlan:
    """Une décision terminale évite les seules étapes devenues inutiles."""
    if authenticated_hold:
        return AnalysisPlan("policy_b", ("proven_identity", "sender_policy", "accept", "suppress"))
    if qualified_otp:
        return AnalysisPlan("otp", ("static_evidence", "otp_qualification", "accept", "deliver"))
    return AnalysisPlan("full", (
        "static_evidence", "cached_observations", "bounded_inspections", "full_dossier",
        "delivery_barriers", "model_view", "candidate", "compare", "accept", "execute",
    ))
