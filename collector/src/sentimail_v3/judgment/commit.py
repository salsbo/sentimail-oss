"""Persiste un jugement validé et ses échéances de reprise."""

from __future__ import annotations

import hashlib
from typing import Any
import asyncpg
from sentimail_v3.postgres_values import pg_text
from sentimail_v3.judgment.verdict_retry import RetryPlan, plan_retry
from sentimail_v3.supervision.training import SCHEMA as TRAINING_SCHEMA
from sentimail_v3.supervision.training import compact_dossier, safe_teacher_target, split_group_hash
from sentimail_v3.supervision.training import fingerprint as view_fingerprint
from sentimail_v3.judgment.dossier_view import _json
from sentimail_v3.judgment.prompt import PROMPT_VERSION
from sentimail_v3.judgment.events import _log

async def _complete(
    pool: asyncpg.Pool[Any],
    run: asyncpg.Record,
    dossier: dict[str, object],
    result: dict[str, object],
    metadata: dict[str, Any],
    duration_ms: float,
    *,
    binding: bool,
    original_delivery_allowed: bool,
    judgment: dict[str, object],
    training_eligible: bool = True,
) -> str:
    fingerprint = hashlib.sha256(_json(dossier).encode()).hexdigest()
    actual_model = str(metadata.get("model") or run["model_name"])
    clues = {
        str(clue["clue_code"]): int(clue["id"])
        for clue in dossier["clues"]  # type: ignore[index]
    }
    evidence_for = [clues[code] for code in result["supporting_clue_codes"]]
    evidence_against = [clues[code] for code in result["contradicting_clue_codes"]]
    investigation_id = str(run["investigation_id"])
    view = compact_dossier(dossier)
    if metadata.get("provider") == "authenticated_sender_policy" and dossier.get("analysis_not_requested_reason"):
        view.update({"schema": dossier["schema"],
                     "analysis_not_requested_reason": dossier["analysis_not_requested_reason"]})
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute(
            """
            INSERT INTO verdicts (
                investigation_id, classification, source, confidence, rationale,
                evidence_for, evidence_against, model_name, model_version,
                prompt_version, is_binding
            ) VALUES ($1::uuid,$2,$10,$3,$4,$5,$6,$7,$8,$9,$11)
            """,
            investigation_id,
            result["classification"],
            result["confidence"],
            pg_text(result["rationale"]),
            evidence_for,
            evidence_against,
            actual_model,
            metadata.get("system_fingerprint"),
            PROMPT_VERSION,
            str(metadata.get("provider") or "llm"),
            binding,
        )
        message_id = await connection.fetchval(
            """
            UPDATE delivery_cases dc SET assessed_classification=$2,
                binding=$4, original_delivery_allowed=$5, updated_at=now(),
                details=details || $3::jsonb
            FROM investigations i
            WHERE dc.investigation_id=i.id AND i.id=$1::uuid
            RETURNING dc.message_id::text
            """,
            investigation_id,
            result["classification"],
            _json(
                {
                    "latest_verdict_source": str(metadata.get("provider") or "llm"),
                    "latest_verdict_confidence": result["confidence"],
                    "verdict_binding": binding,
                    "final_judgment": judgment,
                    "original_delivery_allowed": original_delivery_allowed,
                }
            ),
            binding,
            original_delivery_allowed,
        )
        await connection.execute(
            """
            UPDATE verdict_runs SET status='complete', model_name=$6,
                input_fingerprint=$2,
                input_snapshot=$3::jsonb, response=$4::jsonb, duration_ms=$5,
                completed_at=now(), error_type=NULL, error_detail=NULL
            WHERE id=$1
            """,
            run["id"],
            fingerprint,
            # Le dossier complet a servi au jugement ; ce qui se conserve est
            # sa forme, sans le contenu du message qui, lui, s'efface.
            _json(view),
            _json({"verdict": result, "api": metadata}),
            duration_ms,
            actual_model,
        )
        if training_eligible:
            await connection.execute(
                """
            INSERT INTO training_samples (
                message_id, kind, dossier, dossier_sha256, model_classification,
                model_decision, prompt_version, schema_version,
                teacher_model_name, teacher_model_version, teacher_provider,
                teacher_target, split_group_hash
            ) VALUES (
                $1::uuid,'form_example',$2::jsonb,$3,$4,$5,$6,$7,
                $8,$9,$10,$11::jsonb,$12
            )
            ON CONFLICT (kind, dossier_sha256) DO NOTHING
                """,
                run["message_id"],
                _json(view),
                view_fingerprint(view),
                result["classification"],
                result["delivery_decision"],
                PROMPT_VERSION,
                TRAINING_SCHEMA,
                actual_model,
                metadata.get("system_fingerprint"),
                metadata.get("provider"),
                _json(safe_teacher_target(result)),
                split_group_hash(view),
            )
        policy_source = metadata.get("provider") == "authenticated_sender_policy"
        await connection.execute(
            """
            INSERT INTO audit_log (actor, action, payload)
            VALUES ($2,$3,$1::jsonb)
            """,
            _json(
                {
                    "investigation_id": investigation_id,
                    "classification": result["classification"],
                    "confidence": result["confidence"],
                    "delivery_decision": result["delivery_decision"],
                    "verdict_binding": binding,
                }
            ),
            "policy-execution" if policy_source else "llm-verdict",
            (
                "policy.authenticated_sender_suppression"
                if policy_source
                else "verdict.final_judgment"
            ),
        )
    if message_id is None:
        raise RuntimeError("delivery case not found")
    return str(message_id)

async def _mark_error(
    pool: asyncpg.Pool[Any], run: asyncpg.Record, exc: Exception
) -> RetryPlan:
    """Enregistre l'échec et ce qui le suit ; l'appelant escalade sur ce plan.

    `completed_at` marque l'épuisement, `next_attempt_at` l'échéance d'un
    essai planifié. Les deux vivent en base : un redémarrage ne perd ni
    l'abandon ni l'attente.
    """
    plan = plan_retry(int(run["attempts"]), exc)
    updated = await pool.execute(
        """
        UPDATE verdict_runs SET status='error', error_type=$2, error_detail=$3,
            completed_at=CASE WHEN $4 THEN now() ELSE NULL END,
            next_attempt_at=CASE WHEN $5::double precision IS NULL THEN NULL
                ELSE now() + $5::double precision * interval '1 second' END
        WHERE id=$1 AND status<>'complete'
          AND NOT EXISTS (
            SELECT 1 FROM verdicts v
            WHERE v.investigation_id=verdict_runs.investigation_id AND v.is_binding
          )
        """,
        run["id"],
        type(exc).__name__,
        pg_text(str(exc)[:1000]),
        plan.exhausted,
        plan.delay.total_seconds() if plan.delay is not None else None,
    )
    if isinstance(updated, str) and updated.rsplit(" ", 1)[-1] == "0":
        # Le jugement est durable : l'échec concerne son exécution. La reprise
        # SMTP et le contrôle des écarts gardent leur rôle, sans repayer le juge
        # ni remplacer un ordre déjà accepté par une nouvelle décision.
        _log("verdict.execution.error", run_id=run["id"], message_id=run.get("message_id"),
             error=type(exc).__name__, verdict_preserved=True)
        return RetryPlan("accepted")
    return plan
