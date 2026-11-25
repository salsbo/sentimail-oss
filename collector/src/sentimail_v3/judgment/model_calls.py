"""Appels du juge, paliers et comparaison économique avant acceptation."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Any
import asyncpg
import httpx
from sentimail_v3.config import Settings
from sentimail_v3.judgment.model_routing import ModelRouting, same_outcome, unsafe_delivery_divergence
from sentimail_v3.llm import provider_chat_json
from sentimail_v3.judgment.claims import VerdictQuotaExceeded, _reserve_verdict_call
from sentimail_v3.judgment.dossier_view import _json
from sentimail_v3.judgment.events import _log
from sentimail_v3.judgment.prompt import PROVIDER_ADDENDA, _prompt

async def _record_model_route(
    pool: asyncpg.Pool[Any],
    run: asyncpg.Record,
    tier: str,
    reason: str,
) -> None:
    """Conserve chaque changement de palier sans conserver le courrier."""
    trace = {
        "attempt": int(run["attempts"]),
        "tier": tier,
        "reason": reason,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    await pool.execute(
        """
        UPDATE verdict_runs SET model_tier=$2,routing_reason=$3,
            routing_trace=routing_trace || $4::jsonb
        WHERE id=$1
        """,
        run["id"],
        tier,
        reason,
        _json([trace]),
    )

async def _call_verdict_model(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    run: asyncpg.Record,
    dossier: dict[str, object],
    *,
    model_name: str,
    stage: str,
    allow_local: bool = False,
) -> tuple[str, dict[str, Any], float]:
    """Un appel, une réservation de quota et un événement d'audit complet."""
    event_id, quota = await _reserve_verdict_call(
        pool, settings, run, model_name=model_name, stage=stage
    )
    if quota:
        raise VerdictQuotaExceeded(quota)
    assert event_id is not None
    started = time.perf_counter()
    try:
        content, metadata = await provider_chat_json(
            pool,
            client,
            settings,
            messages=_prompt(dossier),
            provider_addenda=PROVIDER_ADDENDA,
            max_tokens=2400,
            role="verdict",
            model_override=model_name,
            # Les paliers Flash/Pro restent distants. ``allow_local`` n'est
            # vrai qu'en mode off, pour préserver un éventuel routage historique.
            allow_local=allow_local,
            # Flash répond en 7 s au 95e centile : suspendu, il ne doit pas
            # coûter le budget de Pro avant le repli. Pro garde le budget commun.
            deadline_seconds=(
                settings.economy_llm_deadline_seconds if stage == "economy" else None
            ),
        )
    except Exception as exc:  # noqa: BLE001 - tout échec clôt l'événement réservé
        # Le 14 septembre 2026, un appel Flash suspendu 901 s n'a laissé aucune
        # ligne de journal : seule la colonne routing_reason en base le portait.
        _log(
            "verdict.model_call.error",
            run_id=str(run["id"]),
            message_id=str(run["message_id"]),
            stage=stage,
            model=model_name,
            error_type=type(exc).__name__,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        await pool.execute(
            """
            UPDATE verdict_llm_call_events SET status='error',error_type=$2,
                completed_at=now() WHERE id=$1
            """,
            event_id,
            type(exc).__name__,
        )
        raise
    duration_ms = (time.perf_counter() - started) * 1000
    await pool.execute(
        """
        UPDATE verdict_llm_call_events SET status='complete',provider=$2,
            model_name=$3,completed_at=now() WHERE id=$1
        """,
        event_id,
        metadata.get("provider"),
        metadata.get("model") or model_name,
    )
    return content, metadata, duration_ms

async def _record_shadow_evaluation(
    pool: asyncpg.Pool[Any],
    run: asyncpg.Record,
    routing: ModelRouting,
    economy: dict[str, object] | None,
    premium: dict[str, object],
    reasons: list[str],
    *, context: dict[str, str] | None = None,
) -> None:
    context = context or {}
    agreement = economy is not None and same_outcome(economy, premium)
    unsafe = economy is not None and unsafe_delivery_divergence(economy, premium)
    await pool.execute(
        """
        INSERT INTO verdict_model_routing_evaluations (
            verdict_run_id,attempt,economy_model_name,premium_model_name,
            economy_valid,economy_classification,economy_decision,
            economy_confidence,premium_classification,premium_decision,
            premium_confidence,agreement,unsafe_delivery_divergence,
            escalation_reasons,prompt_version,corpus_sha256,rules_version,confidence_margin
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        ON CONFLICT (verdict_run_id,attempt) DO NOTHING
        """,
        run["id"],
        run["attempts"],
        routing.economy_model,
        routing.premium_model,
        economy is not None,
        economy.get("classification") if economy else None,
        economy.get("delivery_decision") if economy else None,
        float(economy.get("confidence") or 0.0) if economy else None,
        premium["classification"],
        premium["delivery_decision"],
        float(premium.get("confidence") or 0.0),
        agreement,
        unsafe,
        reasons,
        context.get("prompt_version"), context.get("corpus_sha256"),
        context.get("rules_version"), routing.confidence_margin,
    )

def _routing_audit_sample(run_id: object) -> bool:
    """Un vingtième des runs, stable au rejeu et indépendant du correspondant."""
    return int.from_bytes(hashlib.sha256(str(run_id).encode()).digest()[:8], "big") % 20 == 0

async def _shadow_after_unsafe_audit(pool: Any, run: Any, routing: ModelRouting) -> None:
    """Le contrôle ne remplace pas une configuration modifiée depuis son départ."""
    await pool.execute(
        """WITH changed AS (
            UPDATE verdict_model_routing SET mode='shadow',configured_by='runtime_audit',updated_at=now()
            WHERE singleton=true AND mode='enforced'
              AND economy_model_name=$1 AND premium_model_name=$2 AND confidence_margin=$3
            RETURNING economy_model_name,premium_model_name,confidence_margin
        ) INSERT INTO audit_log(actor,action,payload)
          SELECT 'verdict-audit','llm.model_routing_disabled_after_divergence',
            to_jsonb(changed) || jsonb_build_object('verdict_run_id',$4::text)
          FROM changed""",
        routing.economy_model, routing.premium_model, routing.confidence_margin, str(run["id"]),
    )

