"""Choisit le candidat, sans accepter de verdict ni exécuter de courrier."""
from __future__ import annotations

from sentimail_v3.judgment.model_calls import _call_verdict_model, _record_model_route, _record_shadow_evaluation, _shadow_after_unsafe_audit
from sentimail_v3.judgment.prompt import PROMPT_VERSION
from sentimail_v3.judgment.response import _parse_final_response, _parse_verdict
from sentimail_v3.judgment.events import _log
from typing import Any
from sentimail_v3.config import Settings
from sentimail_v3.judgment.model_routing import ModelRouting, escalation_reasons, initial_route, unsafe_delivery_divergence
from sentimail_v3.judgment import classifier_runtime
from sentimail_v3.llm import LlmError
from sentimail_v3.llm_accounting import llm_scope
from sentimail_v3.supervision.model_routing import qualification_context

async def choose_candidate(pool, client, settings, run, dossier, routing, audit_sample, comparison_context):
    """Un seul candidat : classifieur, modèle unique ou cascade qualifiée."""
    api_duration_ms = 0.0
    structural_contradiction: list[str] = []
    economy_result: dict[str, object] | None = None
    comparison_reasons: list[str] = []
    local = await classifier_runtime.attempt(pool, run, dossier, _parse_verdict)

    if local is not None and local["use_local"]:
        result = local["result"]
        metadata = local["metadata"]
    elif not routing.enabled:
        await _record_model_route(pool, run, "single", "routing_off")
        content, metadata, duration = await _call_verdict_model(
            pool,
            client,
            settings,
            run,
            dossier,
            model_name=str(run["model_name"]),
            stage="single",
            # Mode off = comportement historique, y compris si
            # l'opérateur a explicitement qualifié un verdict Ollama.
            allow_local=True,
        )
        api_duration_ms += duration
        result, structural_contradiction = _parse_final_response(content, dossier)
    else:
        # Si une tentative a déjà payé Flash puis échoué en passant à Pro,
        # la reprise ne repaie pas Flash : le palier premium est durable.
        if local is not None and local["prediction"]["eligible"]:
            tier, route_reason = "premium", "classifier_reference"
        elif run.get("model_tier") == "premium":
            tier, route_reason = "premium", "resume_premium"
        else:
            tier, route_reason = initial_route(dossier)
        shadow_eligible = route_reason == "simple_univocal_dossier"

        if tier == "economy":
            await _record_model_route(pool, run, "economy", route_reason)
            try:
                economy_content, economy_metadata, duration = (
                    await _call_verdict_model(
                        pool,
                        client,
                        settings,
                        run,
                        dossier,
                        model_name=routing.economy_model,
                        stage="economy",
                    )
                )
                api_duration_ms += duration
                economy_result = _parse_verdict(economy_content, dossier)
                comparison_reasons = escalation_reasons(
                    economy_result, dossier, routing.confidence_margin
                )
            except LlmError as exc:
                # Un compte sans crédit affecte les deux modèles du même
                # fournisseur : doubler immédiatement l'échec ne prouve rien.
                if "HTTP 402" in str(exc):
                    raise
                comparison_reasons = [f"economy_error:{type(exc).__name__}"]
            except (ValueError, TypeError, KeyError) as exc:
                # Réponse reçue mais inexploitable : aucune décision n'a
                # encore été rendue, le juge premium reprend le dossier.
                comparison_reasons = [f"economy_invalid:{type(exc).__name__}"]

            use_economy = (
                routing.mode == "enforced"
                and economy_result is not None
                and not comparison_reasons
            )
            if use_economy:
                result = economy_result
                metadata = economy_metadata
                if audit_sample:
                    result, metadata, duration, structural_contradiction = await _audit_economy_reference(
                        pool, client, settings, run, routing, dossier,
                        economy_result, economy_metadata, comparison_context,
                    )
                    api_duration_ms += duration
            else:
                route_reason = (
                    ",".join(comparison_reasons) or "shadow_reference"
                )
                tier = "premium"

        if tier == "premium":
            await _record_model_route(pool, run, "premium", route_reason)
            content, metadata, duration = await _call_verdict_model(
                pool,
                client,
                settings,
                run,
                dossier,
                model_name=routing.premium_model,
                stage="premium",
            )
            api_duration_ms += duration
            result, structural_contradiction = _parse_final_response(content, dossier)
            if routing.mode == "shadow" and shadow_eligible:
                await _record_shadow_evaluation(
                    pool,
                    run,
                    routing,
                    economy_result,
                    result,
                    comparison_reasons,
                    context=comparison_context,
                )
    await classifier_runtime.observe(pool, run, dossier, local, result, metadata, PROMPT_VERSION)
    return result, metadata, api_duration_ms, structural_contradiction


async def _audit_economy_reference(
    pool: Any, client: Any, settings: Settings, run: Any, routing: ModelRouting,
    dossier: dict[str, object], economy: dict[str, object], metadata: dict[str, Any],
    context: dict[str, str] | None,
) -> tuple[dict[str, object], dict[str, Any], float, list[str]]:
    """Compare avant acceptation ; une référence absente ne crée pas de retenue."""
    try:
        with llm_scope(purpose="verdict_reference_audit"):
            content, reference_metadata, duration = await _call_verdict_model(
                pool, client, settings, run, dossier,
                model_name=routing.premium_model, stage="premium",
            )
        reference, contradictions = _parse_final_response(content, dossier)
    except Exception as exc:
        _log("verdict.audit_reference_unavailable", run_id=run["id"],
             error_type=type(exc).__name__)
        return economy, metadata, 0.0, []
    unsafe = unsafe_delivery_divergence(economy, reference)
    if context is not None:
        try:
            if context != await qualification_context(pool):
                # Le dossier était figé avant les appels. La comparaison garde
                # sa version d'origine et ne qualifie pas le nouveau contexte.
                _log("verdict.audit_context_changed", run_id=run["id"])
        except Exception as exc:
            _log("verdict.audit_context_check_unavailable", run_id=run["id"], error_type=type(exc).__name__)
    try:
        await _record_shadow_evaluation(pool, run, routing, economy, reference,
            ["enforced_audit_sample"], context=context)
    except Exception as exc:
        _log("verdict.audit_recording_error", run_id=run["id"], error_type=type(exc).__name__)
    if unsafe:
        # La référence est appliquée à ce jugement encore non accepté. Seules
        # les décisions futures passent en comparaison, sous condition de cible.
        try:
            await _shadow_after_unsafe_audit(pool, run, routing)
        except Exception as exc:
            _log("verdict.audit_downgrade_error", run_id=run["id"], error_type=type(exc).__name__)
        await _record_model_route(pool, run, "premium", "enforced_audit_unsafe_divergence")
        return reference, reference_metadata, duration, contradictions
    return economy, metadata, duration, []
