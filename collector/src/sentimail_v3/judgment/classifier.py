"""Classifieur sélectif : coefficients JSON, indices seuls, abstention explicite."""

from __future__ import annotations

import math
import re
from typing import Any

from sentimail_v3.judgment.model_routing import initial_route
from sentimail_v3.supervision.training import fingerprint

SCHEMA = "sentimail-logistic-clues-1"
POLICY = "legitimate-only-1"
MAX_CLUES = 60
LLM_QUALIFICATION = "llm-holdout-ab-1"
MIN_SHADOW = 300
MIN_EXPERT_ACCEPTED = 300
MIN_EXPERT_ADVERSE = 50
TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def number(value: object, low: float, high: float) -> float:
    """NaN, booléens et valeurs hors contrat ne deviennent pas une certitude."""
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("valeur numérique invalide")
    result = float(value)
    if not math.isfinite(result) or not low <= result <= high:
        raise ValueError("valeur numérique hors limites")
    return result


def features(dossier: dict[str, Any]) -> dict[str, float]:
    """Aucune identité, aucun texte libre, aucune cible dans les variables."""
    clues = dossier.get("clues")
    if not isinstance(clues, list) or not 1 <= len(clues) <= MAX_CLUES:
        raise ValueError("indices absents ou dossier tronqué")
    result: dict[str, float] = {}
    for clue in clues:
        code, article = clue["clue_code"], clue["article_code"]
        direction = clue["direction"]
        if not TOKEN.fullmatch(code) or not TOKEN.fullmatch(article):
            raise ValueError("référence d'indice invalide")
        if direction not in {"favorable", "adverse", "neutral"}:
            raise ValueError("direction inconnue")
        prefix = f"{code}|{article}|{direction}"
        values = {
            "present": 1.0,
            "strength": number(clue["strength"], 0, 100) / 100,
            "confidence": number(clue["confidence"], 0, 1),
        }
        for name, value in values.items():
            key = f"{prefix}|{name}"
            result[key] = max(result.get(key, 0.0), value)
    return result


def validate_artifact(artifact: dict[str, Any]) -> None:
    if artifact.get("schema") != SCHEMA or artifact.get("policy") != POLICY:
        raise ValueError("version de classifieur incompatible")
    weights = artifact.get("weights")
    if not isinstance(weights, dict) or not 1 <= len(weights) <= 6000:
        raise ValueError("coefficients absents ou trop nombreux")
    for key, weight in weights.items():
        parts = key.split("|")
        if (len(parts) != 4 or not all(TOKEN.fullmatch(p) for p in parts[:2])
                or parts[2] not in {"favorable", "adverse", "neutral"}
                or parts[3] not in {"present", "strength", "confidence"}):
            raise ValueError("variable extérieure aux indices")
        number(weight, -10000, 10000)
    number(artifact.get("intercept"), -10000, 10000)
    number(artifact.get("threshold"), 0.95, 0.99999)
    if not isinstance(artifact.get("rules_versions"), list):
        raise ValueError("versions du Code absentes")


def model_id(artifact: dict[str, Any]) -> str:
    return fingerprint(artifact)


def group_id(dossier: dict[str, Any]) -> str:
    """Même ensemble d'indices, même groupe, même si un indice est répété."""
    return fingerprint(sorted({str(c["clue_code"]) for c in dossier["clues"]}))


def probability(artifact: dict[str, Any], values: dict[str, float]) -> float:
    z = artifact["intercept"] + sum(
        artifact["weights"].get(key, 0.0) * value for key, value in values.items()
    )
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def predict(artifact: dict[str, Any], dossier: dict[str, Any]) -> dict[str, Any]:
    """Le score ne peut autoriser que les livraisons simples, jamais une retenue."""
    validate_artifact(artifact)
    clues = dossier.get("clues")
    if isinstance(clues, list) and not 1 <= len(clues) <= MAX_CLUES:
        return {"probability": 0.0, "eligible": False, "reason": "clue_count_outside_scope"}
    values = features(dossier)
    score = probability(artifact, values)
    rules = dossier.get("judgment_rules") or {}
    reason = "eligible"
    if (dossier.get("llm_budget") or {}).get("truncated_for_llm"):
        reason = "truncated_dossier"
    elif set(values) - artifact["weights"].keys():
        reason = "unknown_clue"
    elif str(rules.get("version") or "") not in artifact["rules_versions"]:
        reason = "unknown_rules"
    elif initial_route(dossier)[0] != "economy":
        reason = initial_route(dossier)[1]
    elif any(c["direction"] == "adverse" for c in dossier["clues"]):
        reason = "adverse_evidence"
    elif not rules.get("deep_execution_complete"):
        reason = "deep_analysis_incomplete"
    elif score < max(artifact["threshold"], number(rules.get("confidence_required"), 0, 1)):
        reason = "low_probability"
    return {"probability": score, "eligible": reason == "eligible", "reason": reason}


def candidate(dossier: dict[str, Any], prediction: dict[str, Any]) -> dict[str, Any]:
    """La motivation décrit le périmètre constaté, sans inventer d'explication."""
    if not prediction["eligible"]:
        raise ValueError("le classifieur s'est abstenu")
    return {
        "favorable": {"clue_codes": [c["clue_code"] for c in dossier["clues"]
                                        if c["direction"] == "favorable"],
                      "arguments": []},
        "unfavorable": {"clue_codes": [], "arguments": []},
        "final_verdict": {
            "classification": "legitimate", "delivery_decision": "deliver",
            "confidence": prediction["probability"], "doubt": False,
            "doubt_reasons": [],
            "rationale": "Le classifieur local reconnaît un dossier complet avec "
                         "des indices favorables et aucun indice défavorable.",
        },
    }


def offline_blockers(artifact: dict[str, Any]) -> list[str]:
    """Deux contrats explicites : expertise historique ou distillation corrigée."""
    report = artifact.get("evaluation", {}).get("expert_test", {})
    validation = artifact.get("evaluation", {}).get("expert_valid", {})
    reasons = []
    quality = artifact.get("corpus_quality", {})
    if quality.get("unmaterialized_labels", 0) or quality.get("conflicting_samples", 0):
        reasons.append("annotations manquantes ou contradictoires dans l'export")
    if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("corpus_sha256") or "")):
        reasons.append("empreinte du corpus normatif absente")
    qualification = artifact.get("qualification", "expert")
    if qualification == LLM_QUALIFICATION:
        if artifact.get("split_strategy") != "sha256-unique-clue-codes-70-15-15-v1":
            reasons.append("découpage indépendant non identifié")
        for part in ("valid", "test"):
            measured = artifact.get("evaluation", {}).get(f"teacher_{part}", {})
            if (measured.get("total", 0) < 200 or measured.get("accepted", 0) < 1
                    or measured.get("adverse", 0) < 50):
                reasons.append(f"évaluation LLM {part} insuffisante (200 groupes, un candidat, 50 adverses)")
            if measured.get("unsafe", 0) or measured.get("invalid", 0):
                reasons.append(f"divergence de livraison ou dossier invalide dans le jeu LLM {part}")
            for source in ("expert", "correction"):
                if artifact.get("evaluation", {}).get(f"{source}_{part}", {}).get("unsafe", 0):
                    reasons.append(f"livraison contredite par {source} dans le jeu {part}")
        return reasons
    if qualification != "expert":
        reasons.append("contrat de qualification inconnu")
    if validation.get("accepted", 0) < 30 or validation.get("unsafe", 0):
        reasons.append("validation expertisée insuffisante ou erronée")
    if report.get("accepted", 0) < MIN_EXPERT_ACCEPTED:
        reasons.append(f"moins de {MIN_EXPERT_ACCEPTED} livraisons expertisées au test")
    if report.get("adverse", 0) < MIN_EXPERT_ADVERSE:
        reasons.append(f"moins de {MIN_EXPERT_ADVERSE} dossiers adverses expertisés au test")
    if report.get("unsafe", 0):
        reasons.append("livraison erronée sur le test expertisé")
    return reasons
