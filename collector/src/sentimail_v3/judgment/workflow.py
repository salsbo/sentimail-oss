"""Planifie l’observation puis accepte et exécute un seul jugement."""
from __future__ import annotations

from sentimail_v3.judgment.model_selection import choose_candidate
from sentimail_v3.judgment import classifier_runtime
from sentimail_v3.judgment.decisions_shadow import evaluate_shadow

from sentimail_v3.judgment.claims import ENGINE, VerdictQuotaExceeded, _claim, _reserve_verdict_call, _verdict_domain, resume_interrupted_runs
from sentimail_v3.judgment.commit import _complete as _persist_complete, _mark_error
from sentimail_v3.judgment.core_compare import before_commit, before_model, run_legacy
from sentimail_v3.judgment.plan import AnalysisPlan, plan_for
from sentimail_v3.judgment.dossier import _build_dossier, _express_dossier, _prepare_for_judgment
from sentimail_v3.judgment.dossier_view import MAX_ENTITY_VALUE_CHARS, MAX_LLM_DOSSIER_CHARS, MAX_URLS_PER_HOST, _DOSSIER_PREFIX_KEYS, _URL_ATTRIBUTES_IN_VALUE, _bounded, _cited_code_articles, _code_index, _compact_attributes, _compact_enrichment, _compact_entities, _deduplicate_clues, _fit_dossier, _json, _json_default, _ordered_dossier, _short
from sentimail_v3.judgment.fast_paths import _apex_of, _express_judgment, _facts_of, _sender_established, _visible_code
from sentimail_v3.judgment.model_calls import _call_verdict_model, _record_model_route, _record_shadow_evaluation, _routing_audit_sample, _shadow_after_unsafe_audit
from sentimail_v3.judgment.prompt import PROMPT_VERSION, _prompt
from sentimail_v3.judgment.response import CLASSIFICATIONS, FILED_AS_JUNK, JudgmentContradiction, _EVIDENCE_CODE_REF, _authenticated_suppression, _judgment_execution, _parse_final_response, _parse_verdict, _validate_final_judgment, _without_real_doubt, delivery_without_question, waiting_judgment
from sentimail_v3.judgment.rules import _ATTACHMENT_INCOMPLETE_CLUES, _IMPERSONATION_ACTIONS, _MATERIAL_SPAM_SOLICITATION, _MECHANICAL_REFUTATION, _attachment_analysis_complete, _clue_facts, _judgment_rules, _learning_adjustments, _material_danger_evidence, _material_impersonation_profile, _material_spam_profile
from sentimail_v3.judgment.events import _log

import logging
import time
from typing import Any

import asyncpg
import httpx
import tldextract

from sentimail_v3.code.attack_techniques import pedagogy as technique_pedagogy
from sentimail_v3.code.attack_techniques import record_observations
from sentimail_v3.code.plain_words import classification_reasons, identity_card
from sentimail_v3.code.sender_identity import read_proven_identity
from sentimail_v3.code.sender_policy import authenticated_hold
from sentimail_v3.config import Settings
from sentimail_v3.conversation.conversation import ConversationStore
from sentimail_v3.execution.campaign_memory import remember_campaign
from sentimail_v3.execution.delivery import release_original, suppress_original
from sentimail_v3.execution.delivery_state import ANALYZING, move
from sentimail_v3.execution.hostile_sources import record_hostile_source
from sentimail_v3.execution.review_guard import hold_with_review_or_fail_open
from sentimail_v3.judgment.model_routing import ModelRouting, JUDGMENT_RULES_VERSION, escalation_reasons, initial_route, load_model_routing, same_outcome, unsafe_delivery_divergence
from sentimail_v3.judgment.verdict_retry import ATTEMPTS_CEILING, MAX_ATTEMPTS, TRANSIENT_RETRY_DELAYS, RetryPlan, plan_retry
from sentimail_v3.llm_accounting import llm_scope
from sentimail_v3.supervision.model_routing import qualification_context
from sentimail_v3.observation.deep_analysis import analyze_message, persist_signals

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-verdict")
# Les indices de démarchage non sollicité qui, joints à une forge et à une
# première observation, achèvent le profil de spam matériel (cf _parse_verdict).


# Ce qu'un message demande quand il se fait passer pour quelqu'un d'autre :
# cliquer, saisir, payer, rappeler. Sans demande, une identité empruntée peut
# encore être une maladresse ; avec, c'est le hameçonnage lui-même.


# Le seul démenti d'identité qui condamne sans question : le domaine émetteur
# accole le nom d'un domaine officiel rendu par la recherche. Constat posé sans
# modèle (deep_analysis.MECHANICAL_APPENDED). La lecture des deux recherches
# par le modèle produit le même code, mais elle s'est déjà trompée (Groupe
# Banque Populaire depuis son routeur d'emailing) : elle converge et informe
# le juge, elle ne classe pas seule.


# Ce qui part en indésirables plutôt que d'attendre un avis.


# Ces attributs recopient l'URL elle-même : le juge les lit déjà dans la valeur.


# Ce qui ne change pas d'un message à l'autre ouvre le dossier : le cache de
# préfixe du fournisseur ne s'applique qu'à un début identique, et il ne
# couvrait que le prompt système tant que le Code fermait la marche.


# Les deux indices qui disent qu'une pièce jointe n'a pas été entièrement
# inspectée : ATT-019, lu dans le rapport du bac à sable, et DEEP-005, posé
# quand l'analyse elle-même s'arrête.


_extract_apex = tldextract.TLDExtract(suffix_list_urls=())


async def _complete(*args: Any, **kwargs: Any) -> str:
    await before_commit(args[0], args[1], args[2], args[3])
    return await _persist_complete(*args, **kwargs)


async def _record_plan(pool: Any, run: Any, plan: AnalysisPlan) -> None:
    if run.get("engine_generation") is not None:
        await pool.execute(
            "UPDATE verdict_runs SET analysis_plan=$2::jsonb WHERE id=$1",
            run["id"], _json({"version": plan.version, "path": plan.path,
                              "stages": plan.stages, "generation": run["engine_generation"]}),
        )


async def _execute_suppression(pool: Any, run: Any, dossier: dict[str, object], settings: Settings) -> None:
    """Une suppression B est terminale et auditée, sans inventer de qualification."""
    result = _authenticated_suppression(dossier)
    if result is None:
        raise ValueError("préférence de suppression non prouvée")
    judgment = _judgment_execution(result)
    message_id = await _complete(
        pool, run, dossier, result,
        {"provider": "authenticated_sender_policy", "model": "none"}, 0.0,
        binding=settings.decision_mode, original_delivery_allowed=False,
        judgment=judgment, training_eligible=False,
    )
    delivery = await suppress_original(pool, message_id, reason="authenticated_sender_policy_hold")
    if delivery not in {"suppressed", "already_suppressed"}:
        raise RuntimeError("authenticated suppression was not applied: " + str(delivery))
    _log("verdict.policy_suppressed", run_id=run["id"], message_id=message_id,
         delivery_result=delivery, final_judgment=judgment)


async def _process_one(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    conversations: ConversationStore,
) -> bool:
    run = await _claim(pool, settings)
    if run is None:
        return False
    with llm_scope(message_id=str(run["message_id"]), verdict_run_id=str(run["id"]), purpose="message_analysis"):
        if run.get("engine_generation") == "legacy":
            return await run_legacy(pool, client, settings, conversations, run)
        return await _process_run(pool, client, settings, conversations, run)


async def _process_run(
    pool: asyncpg.Pool[Any], client: httpx.AsyncClient, settings: Settings,
    conversations: ConversationStore, run: asyncpg.Record,
) -> bool:
    processing_started = time.perf_counter()
    _log(
        "verdict.processing_started",
        run_id=run["id"],
        investigation_id=run["investigation_id"],
        message_id=run["message_id"],
        model=run["model_name"],
        prompt_version=PROMPT_VERSION,
        attempt=run["attempts"],
    )
    try:
        if settings.decision_mode:
            await move(pool, str(run["message_id"]), ANALYZING)
        if settings.decision_mode:
            try:
                identity = await read_proven_identity(pool, str(run["message_id"]))
                suppress = await authenticated_hold(pool, str(run["message_id"]), identity)
            except Exception as exc:
                # Une preuve indisponible ne justifie aucune suppression. Le
                # chemin complet conserve son traitement de panne habituel.
                _log("policy.early_lookup_failed", error=type(exc).__name__)
                suppress = False
            if suppress:
                await _record_plan(pool, run, plan_for(authenticated_hold=True))
                dossier = await _express_dossier(pool, str(run["message_id"]))
                dossier.update({
                    "schema": "sentimail-authenticated-sender-policy-v1",
                    "analysis_not_requested_reason": "authenticated_sender_policy",
                    "judgment_rules": {"version": JUDGMENT_RULES_VERSION,
                                       "authenticated_sender_policy": "hold"},
                })
                await _execute_suppression(pool, run, dossier, settings)
                return True
        # Voie rapide : un code à usage unique attend derrière un écran. Les
        # indices statiques suffisent à conclure sur un courrier aussi
        # contraint, et l'inspection profonde le rendrait périmé. Le jugement
        # rendu ici emprunte ensuite exactement le même chemin d'exécution.
        express = await _express_judgment(pool, str(run["message_id"]))
        if express is not None:
            await _record_plan(pool, run, plan_for(qualified_otp=True))
            _log(
                "verdict.express_path",
                run_id=run["id"],
                message_id=run["message_id"],
                path="one_time_code",
            )
            judgment = _judgment_execution(express)
            express_delivery_allowed = bool(judgment["original_delivery_allowed"])
            message_id = await _complete(
                pool,
                run,
                await _express_dossier(pool, str(run["message_id"])),
                express,
                {"provider": "express_path", "model": "none"},
                0.0,
                binding=settings.decision_mode,
                original_delivery_allowed=express_delivery_allowed,
                judgment=judgment,
            )
            # La promesse de la voie rapide est la livraison, pas le seul
            # verdict : sans cette exécution, le code restait « analyzing »
            # avec un ordre deliver jamais appliqué - constaté le 20/08 sur
            # le tout premier verdict express, resté bloqué après _complete.
            if settings.decision_mode and express_delivery_allowed:
                await release_original(
                    pool,
                    settings,
                    message_id,
                    reason="final_judgment_deliver",
                )
            return True
        await _record_plan(pool, run, plan_for())
        deep = await analyze_message(
            pool, client, settings, str(run["message_id"])
        )
        await persist_signals(pool, str(run["investigation_id"]), deep)
        routing = await load_model_routing(pool, str(run["model_name"]))
        audit_sample = routing.mode == "enforced" and _routing_audit_sample(run["id"])
        comparison_context = None
        if routing.mode == "shadow" or audit_sample:
            try:
                comparison_context = await qualification_context(pool)
            except Exception as exc:
                if not audit_sample:
                    raise
                _log("verdict.audit_context_unavailable", run_id=run["id"], error_type=type(exc).__name__)
        dossier = await _build_dossier(
            pool,
            str(run["investigation_id"]),
            deep,
            client=client,
            settings=settings,
        )
        # L'ancien commentaire affirmait déjà cet ordre, alors que
        # _build_dossier avait tronqué avant : material_danger_evidence,
        # strong_adverse, family_coverage et converging_families se
        # calculaient sur 40 à 60 indices et sur des paramètres d'article
        # coupés à 300 caractères. Désormais les règles voient tout, puis la
        # vue est ajustée une seule fois. L'ajustement reste avant le
        # classifieur local : il lit llm_budget.truncated_for_llm.
        await before_model(pool, run, dossier, deep, settings)
        dossier = _prepare_for_judgment(dossier, deep, settings)
        suppression = (
            _authenticated_suppression(dossier) if settings.decision_mode else None
        )
        if suppression is not None:
            await _execute_suppression(pool, run, dossier, settings)
            return True
        if comparison_context is not None:
            try:
                if comparison_context != await qualification_context(pool):
                    comparison_context = None
            except Exception:
                if not audit_sample:
                    raise
                comparison_context = None
        result, metadata, api_duration_ms, structural_contradiction = await choose_candidate(
            pool, client, settings, run, dossier, routing, audit_sample, comparison_context
        )
        recognized_codes = [
            str(code) for code in (result.get("attack") or {}).get("techniques") or []
        ]
        if recognized_codes:
            await record_observations(pool, recognized_codes)
        judgment = _judgment_execution(result)
        binding = settings.decision_mode
        original_delivery_allowed = bool(judgment["original_delivery_allowed"])
        message_id = await _complete(
            pool,
            run,
            dossier,
            result,
            metadata,
            api_duration_ms,
            binding=binding,
            original_delivery_allowed=original_delivery_allowed,
            judgment=judgment,
            training_eligible=metadata.get("provider") != "local_classifier",
        )
        queued = False
        delivery_result = "observation"
        filed_as_junk = judgment.get("filed_as_junk")
        classify_reasons: list[str] = []
        classify_lessons: list[dict[str, str]] = []
        classify_identity: dict[str, object] | None = None
        if filed_as_junk:
            # Un indésirable livré sur certitude ne demande rien, mais dit
            # pourquoi : les points à charge en clair, et la technique reconnue.
            adverse_rows = await pool.fetch(
                """
                SELECT DISTINCT c.clue_code, c.statement, c.facts
                FROM clues c JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid AND c.direction='adverse'
                ORDER BY c.clue_code
                """,
                message_id,
            )
            # La carte reste dans le dossier pour l'audit et le bandeau de
            # repli. L'avis normal, lui, ne dessine plus une seconde enquête :
            # il donne trois motifs télégraphiques et le geste de récupération.
            classify_identity = identity_card([dict(row) for row in adverse_rows])
            classify_reasons = classification_reasons(
                [dict(row) for row in adverse_rows],
                result["rationale"],
                telegraphique=True,
            )
            classify_lessons = await technique_pedagogy(
                pool,
                [str(code) for code in (result.get("attack") or {}).get("techniques") or []],
            )
            # Persisté dans le dossier : la reprise doit pouvoir reconstruire la
            # même annotation sans rejouer le verdict.
            await pool.execute(
                "UPDATE delivery_cases SET details=details || $2::jsonb "
                "WHERE message_id=$1::uuid",
                message_id,
                _json({"junk_reasons": classify_reasons,
                       "junk_lessons": classify_lessons,
                       "junk_identity": classify_identity}),
            )
            # Un indésirable confirmé laisse l'adresse de son serveur au
            # registre des sources hostiles. En échec, le registre attendra -
            # jamais la livraison.
            try:
                await record_hostile_source(
                    pool, message_id, "verdict_" + str(filed_as_junk)
                )
            except Exception as exc:  # noqa: BLE001 - registre en bonus
                _log("hostile_source.record_error", error=type(exc).__name__)
            # Le gabarit de l'indésirable entre en mémoire de campagne : la
            # récidive sera reconnue même par un autre compte d'envoi.
            try:
                await remember_campaign(pool, message_id, str(filed_as_junk))
            except Exception as exc:  # noqa: BLE001 - mémoire en bonus
                _log("campaign_memory.record_error", error=type(exc).__name__)
        if settings.decision_mode and original_delivery_allowed:
            delivery_result = await release_original(
                pool,
                settings,
                message_id,
                reason="final_judgment_junk" if filed_as_junk else "final_judgment_deliver",
                classify_as=str(filed_as_junk) if filed_as_junk else None,
                classify_reasons=classify_reasons,
                classify_lessons=classify_lessons,
                classify_identity=classify_identity,
            )
        elif settings.decision_mode:
            await pool.execute(
                """
                UPDATE delivery_cases SET details=details || $2::jsonb
                WHERE message_id=$1::uuid
                """,
                message_id,
                _json({"final_judgment": judgment}),
            )
            delivery_result = await hold_with_review_or_fail_open(
                pool, settings, conversations, message_id
            )
            queued = delivery_result == "review_notice_queued"
        elif result["classification"] != "legitimate":
            queued = await conversations.queue_invitation(message_id)
        _log(
            "verdict.complete",
            run_id=run["id"],
            investigation_id=run["investigation_id"],
            message_id=message_id,
            model=metadata.get("model") or run["model_name"],
            prompt_version=PROMPT_VERSION,
            attempt=run["attempts"],
            classification=result["classification"],
            confidence=result["confidence"],
            final_judgment=judgment,
            delivery_result=delivery_result,
            invitation_queued=queued,
            structural_contradiction=structural_contradiction,
            api_request_id=metadata.get("id"),
            finish_reason=metadata.get("finish_reason"),
            usage=metadata.get("usage") or {},
            api_duration_ms=round(api_duration_ms, 2),
            duration_ms=round((time.perf_counter() - processing_started) * 1000, 2),
            binding=binding,
        )
        await evaluate_shadow(
            pool,
            client,
            settings,
            message_id=message_id,
            verdict_run_id=str(run["id"]),
            dossier=dossier,
            binding_result=result,
            binding_judgment=judgment,
        )
    except Exception as exc:  # noqa: BLE001 - retries bornees et fail-open
        plan = await _mark_error(pool, run, exc)
        if plan.kind == "accepted":
            return True
        # Tant qu'un essai reste à venir, le message reste en analyse : ni
        # livré, ni remis à l'humain. L'escalade attend l'épuisement.
        if plan.exhausted:
            message_id = await pool.fetchval(
                "SELECT message_id::text FROM investigations WHERE id=$1",
                run["investigation_id"],
            )
            if message_id:
                if settings.decision_mode:
                    await hold_with_review_or_fail_open(
                        pool, settings, conversations, str(message_id)
                    )
                else:
                    await conversations.queue_invitation(str(message_id))
        _log(
            "verdict.error",
            run_id=run["id"],
            investigation_id=run["investigation_id"],
            message_id=run["message_id"],
            model=run["model_name"],
            prompt_version=PROMPT_VERSION,
            attempt=run["attempts"],
            error=type(exc).__name__,
            detail=str(exc)[:300],
            duration_ms=round((time.perf_counter() - processing_started) * 1000, 2),
            retry=plan.kind,
            retry_in_seconds=(
                int(plan.delay.total_seconds()) if plan.delay is not None else None
            ),
        )
    return True


