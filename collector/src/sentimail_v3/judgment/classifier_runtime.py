"""Branchement fail-soft du candidat local avant tout verdict contraignant."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sentimail_v3.judgment.classifier import candidate, group_id, model_id, offline_blockers, predict
from sentimail_v3.supervision.training import fingerprint

logger = logging.getLogger("sentimail-v3-classifier")
MAX_MODEL_AGE = timedelta(days=90)


async def corpus_fingerprint(pool: Any) -> str:
    """Une évolution du Code exige une nouvelle qualification du modèle."""
    value = await pool.fetchval("""SELECT jsonb_agg(jsonb_build_object(
        'edition',edition_id,'article',article_code,'principle',principle,
        'limitations',limitations,'direction',default_direction,
        'strength',default_strength,'parameters',parameters,'enabled',enabled
        ) ORDER BY edition_id,article_code) FROM code_articles""")
    return fingerprint(json.loads(value) if isinstance(value, str) else value)


async def error(pool: Any, stage: str, exc: Exception) -> None:
    logger.error("classifier.error stage=%s type=%s", stage, type(exc).__name__)
    try:
        await asyncio.wait_for(pool.execute(
            "INSERT INTO audit_log(actor,action,payload) "
            "VALUES ('classifier','classifier.error',$1::jsonb)",
            json.dumps({"stage": stage, "error_type": type(exc).__name__}),
        ), timeout=2)
    except Exception:
        logger.error("classifier.audit_unavailable")


async def attempt(pool: Any, run: Any, dossier: dict[str, Any],
                  parse: Callable) -> dict[str, Any] | None:
    try:
        row = await asyncio.wait_for(pool.fetchrow(
            "SELECT c.mode,c.model_id,m.artifact FROM classifier_config c "
            "LEFT JOIN classifier_models m USING(model_id) WHERE c.singleton=true"
        ), timeout=2)
        if not row or row["mode"] == "off":
            return None
        artifact = json.loads(row["artifact"]) if isinstance(row["artifact"], str) else row["artifact"]
        if model_id(artifact) != row["model_id"]:
            raise ValueError("empreinte du modèle incorrecte")
        trained_at = datetime.fromisoformat(artifact["trained_at"])
        age = datetime.now(timezone.utc) - trained_at
        if age < timedelta(0) or age > MAX_MODEL_AGE:
            raise ValueError("modèle périmé : réentraîner et réévaluer")
        prediction = predict(artifact, dossier)
        result = None
        if prediction["eligible"]:
            # Même validateur que le juge distant, avant toute acceptation.
            result = parse(json.dumps(candidate(dossier, prediction)), dossier)
        enforced = row["mode"] == "enforced"
        if enforced and offline_blockers(artifact):
            raise ValueError("modèle non qualifié pour décider")
        if artifact.get("corpus_sha256"):
            current = await asyncio.wait_for(corpus_fingerprint(pool), timeout=2)
            if current != artifact["corpus_sha256"]:
                raise ValueError("le Code a changé : réentraîner et réévaluer")
        # Un dossier sur vingt reste jugé à distance pour détecter les dérives.
        audit_sample = int(str(run["id"]).replace("-", "")[:8], 16) % 20 == 0
        use_local = enforced and result is not None and not audit_sample
        return {"model_id": row["model_id"], "prediction": prediction,
                "result": result, "use_local": use_local,
                "metadata": {"provider": "local_classifier", "model": "logistic-clues-" + row["model_id"][:16],
                             "system_fingerprint": row["model_id"], "usage": {},
                             "classifier_policy": artifact["policy"]}}
    except Exception as exc:
        await error(pool, "predict", exc)
        return None


async def observe(pool: Any, run: Any, dossier: dict[str, Any], context: dict[str, Any] | None,
                  result: dict[str, Any], metadata: dict[str, Any], prompt_version: str) -> None:
    if context is None or context["use_local"]:
        return
    prediction = context["prediction"]
    unsafe = prediction["eligible"] and (result["delivery_decision"] != "deliver"
                                         or result["classification"] != "legitimate")
    try:
        await asyncio.wait_for(pool.execute(
            """INSERT INTO classifier_observations
            (model_id,verdict_run_id,split_group_hash,probability,eligible,reason,
             reference_classification,reference_decision,reference_model,reference_prompt,unsafe)
            VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            ON CONFLICT (model_id,verdict_run_id) DO NOTHING""",
            context["model_id"], run["id"], group_id(dossier),
            prediction["probability"], prediction["eligible"], prediction["reason"],
            result["classification"], result["delivery_decision"],
            str(metadata.get("model") or run["model_name"]), prompt_version, unsafe,
        ), timeout=2)
        if unsafe:
            # On désactive seulement les décisions futures, jamais le verdict accepté.
            await asyncio.wait_for(pool.execute(
                "WITH changed AS (UPDATE classifier_config SET mode='shadow',updated_at=now() "
                "WHERE model_id=$1 AND mode='enforced' RETURNING model_id) "
                "INSERT INTO audit_log(actor,action,payload) SELECT 'classifier',"
                "'classifier.disabled_after_divergence',jsonb_build_object('model_id',model_id) FROM changed",
                context["model_id"],
            ), timeout=2)
    except Exception as exc:
        await error(pool, "observe", exc)
