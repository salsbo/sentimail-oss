from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from typing import Any

import aiosmtplib
import asyncpg

from sentimail_v3.code.reference import nommer_dossier
from sentimail_v3.config import Settings, load_settings
from sentimail_v3.execution.hostile_export import export_hostile_cidr
from sentimail_v3.execution.retention import OPEN_STATUSES as RETENTION_OPEN_STATUSES
from sentimail_v3.execution.retention import RETENTION_ELIGIBLE_SQL
from sentimail_v3.identity import instance_identity
from sentimail_v3.judgment.verdict_retry import (
    MAX_ATTEMPTS as VERDICT_MAX_ATTEMPTS,
    retry_on_schedule_sql,
    retry_overdue_sql,
)
from sentimail_v3.observation.smtp_utils import extract_queue_id
from sentimail_v3.supervision.health import pulse, set_status
from sentimail_v3.supervision.classifier import report as classifier_report
from sentimail_v3.supervision.core_health import snapshot as core_health_snapshot
from sentimail_v3.supervision.probe import run_probe
from sentimail_v3.supervision.watchdog_letter import lettre as watchdog_lettre

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-watchdog")
BACKUP_HEARTBEAT = Path("/backups/.last-success")
# Les enquêteurs profonds dont le passage doit rester constatable. Un nom
# absent d'ici ne serait plus surveillé - c'est ce qui rend la liste utile.
REQUIRED_DEEP_HOOKS = (
    "requested_action",
    "sender_relation",
    "cousin_domain",
    "sender_activity",
    "action_destination",
)
REQUIRED_STATIC_HOOKS = (
    "structure",
    "headers",
    "identity",
    "authentication",
    "rspamd",
    "transport",
    "content",
    "nature",
    "urls",
    "attachments",
)
# En dessous de ce délai, une dégradation identique à la précédente ne renvoie
# pas d'email : la nuit du 14 au 15 août en a produit douze pour une seule
# cause, chaque spam relançant le même compteur puis sa rémission. L'alerte
# doit réveiller, pas bercer. L'état reste visible en continu dans la console
# et dans operational_status ; seul l'email est espacé, et une raison nouvelle
# ou une panne franche (down) alertent toujours immédiatement.
ALERT_COOLDOWN = timedelta(hours=6)

# Nombre d'occurrences à partir duquel un compteur dégrade.
#
# Les compteurs d'intégrité du flux valent 1 : un seul message accepté sans
# issue, une seule retenue sans avis, un seul verdict non exécuté sont déjà des
# anomalies, et rien ne les résorbera tout seul.
#
# Les compteurs d'échecs fail-soft valent davantage : le pipeline continue par
# conception quand un sous-module échoue, et une occurrence isolée sur une heure
# est son fonctionnement nominal, pas une panne. La traiter comme une
# dégradation a produit, du 14 au 15 août, cinq alertes pour des incidents que
# personne n'avait à traiter. Le seuil dit à partir de quand cela devient un
# motif ; le compteur reste visible dans le détail, alerte ou pas.
DEGRADED_THRESHOLDS = {
    "core_qualification_lost": 1,
    "core_comparison_mismatches": 1,
    "core_comparison_errors": 1,
    "core_health_unavailable": 1,
    "classifier_errors_last_hour": 3,
    "classifier_unsafe_divergences": 1,
    "analysis_backlog": 1,
    "delivery_backlog": 1,
    "outbox_errors": 1,
    "unprotected_holds": 1,
    "silent_holds": 1,
    # Un seul message dangereux retenu sans avis est déjà une anomalie, et
    # rien ne la résorbe seul : même famille que les deux compteurs du dessus.
    "fail_closed_holds": 1,
    "delivered_without_smtp_event": 1,
    "smtp_events_without_queue_id": 1,
    "accepted_without_terminal_outcome": 1,
    "suppressed_without_event": 1,
    "junk_not_filed": 1,
    "missing_deep_hook_runs": 1,
    # L'enquêteur sender_relation rend toujours un constat : un passage sans
    # indice ou en erreur est un contournement, pas une question sans objet.
    "sender_relation_silent": 1,
    "coherence_hook_failures": 1,
    "verdict_execution_mismatches": 1,
    "feedback_application_mismatches": 1,
    # Un 402 n'est pas un échec passager du modèle : le fournisseur refuse
    # tout nouvel appel tant que son compte n'est pas recrédité.
    "verdict_provider_credit_exhausted": 1,
    # Un essai planifié qui ne démarre pas à son échéance est un juge arrêté
    # ou saturé : rien ne le résorbe seul. Et un dossier dont les quatre
    # essais espacés ont échoué a vu le fournisseur muet plus de cinq heures :
    # un seul cas mérite qu'on le sache, contrairement aux échecs ordinaires
    # de verdict_errors_last_hour, tolérés jusqu'à trois par heure.
    "verdict_retries_overdue": 1,
    "verdict_retries_exhausted": 1,
    # Même logique pour le moteur de recherche : une clé refusée (401, 403,
    # 432) ne se répare pas seule. Du 15 au 17 septembre 2026, personne ne
    # l'a su : les identités revendiquées n'étaient plus confrontées à leurs
    # domaines officiels, et le juge demandait là où il aurait rejeté.
    "organisation_search_rejected": 1,
    "classifier_cycle_unhealthy": 1,
    "retention_overdue": 1,
    "verdict_errors_last_hour": 3,
    "hook_errors_last_hour": 3,
    "partial_investigations_last_hour": 3,
    "missing_required_hook_sets": 3,
    "missing_deep_evidence": 3,
    "sender_domain_enrichment_gaps": 3,
    "slow_url_inspections": 3,
    "external_analysis_service_errors_last_hour": 3,
    "assistant_interpretation_errors_last_hour": 3,
    "organisation_search_errors_last_hour": 3,
    # Le secours d'une retenue et le repli de l'enveloppe des indésirables
    # sont passés : le message est livré. Chaque occurrence nouvelle réalerte.
    "review_fail_open_last_hour": 1,
    "junk_envelope_fallbacks_last_hour": 1,
}
SOFT_FAILURE_COUNTERS = (
    "core_comparison_mismatches",
    "core_comparison_errors",
    "hook_errors_last_hour",
    "partial_investigations_last_hour",
    "missing_required_hook_sets",
    "missing_deep_evidence",
    "sender_domain_enrichment_gaps",
    "slow_url_inspections",
    "external_analysis_service_errors_last_hour",
    "assistant_interpretation_errors_last_hour",
    "verdict_execution_mismatches",
    "feedback_application_mismatches",
    "verdict_provider_credit_exhausted",
    "verdict_retries_exhausted",
    "organisation_search_errors_last_hour",
    "review_fail_open_last_hour",
    "junk_envelope_fallbacks_last_hour",
)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    level = logging.ERROR if event.endswith(".error") else logging.INFO
    logger.log(
        level,
        _json(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": logging.getLevelName(level).lower(),
                "event": event,
                **fields,
            }
        ),
    )


def _counter_reasons(details: dict[str, object]) -> list[str]:
    return [
        key
        for key, threshold in DEGRADED_THRESHOLDS.items()
        if int(details.get(key) or 0) >= threshold
    ]


def _confirmed_reasons(
    observed: list[str] | set[str], previously_observed: list[str] | set[str]
) -> list[str]:
    """Ne retient que les dégradations vues deux fois de suite.

    Le superviseur passe toutes les minutes ; certains compteurs mesurent un
    instant, pas une durée. Un message qui met onze minutes à s'analyser puis
    aboutit fait apparaître un retard, disparu au tick suivant. Exiger deux
    observations coûte une minute de retard sur une vraie panne, et supprime
    des alertes qui ne décrivaient plus rien à l'instant où elles partaient.
    Une panne franche (down) ne passe pas par ici : elle alerte aussitôt.
    """
    return sorted(set(observed) & set(previously_observed))


def _increased_failure_counts(
    previous: dict[str, object], current: dict[str, object]
) -> dict[str, int]:
    return {
        key: int(current.get(key) or 0) - int(previous.get(key) or 0)
        for key in SOFT_FAILURE_COUNTERS
        if int(current.get(key) or 0) > int(previous.get(key) or 0)
    }


async def _smtp_envelope_preflight(
    host: str, port: int, sender: str, recipient: str
) -> dict[str, object]:
    """Teste EHLO/MAIL/RCPT/RSET sans DATA : aucun email n'est créé."""
    started = time.perf_counter()
    smtp = aiosmtplib.SMTP(
        hostname=host,
        port=port,
        timeout=15,
        start_tls=False,
    )
    try:
        await smtp.connect()
        await smtp.ehlo()
        await smtp.mail(sender)
        await smtp.rcpt(recipient)
        await smtp.rset()
        return {
            "status": "ok",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    except Exception as exc:  # noqa: BLE001 - le type suffit, aucun secret SMTP
        return {
            "status": "down",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error_type": type(exc).__name__,
        }
    finally:
        with contextlib.suppress(Exception):
            await smtp.quit()


async def _smtp_preflights(
    settings: Settings, action_address: str
) -> dict[str, dict[str, object]]:
    if not settings.watchdog_smtp_preflight_enabled:
        return {"ingress": {"status": "disabled"}, "relay": {"status": "disabled"}}
    ingress, relay = await asyncio.gather(
        _smtp_envelope_preflight(
            settings.watchdog_ingress_host,
            settings.watchdog_ingress_port,
            action_address,
            settings.operator_address,
        ),
        _smtp_envelope_preflight(
            settings.relay_host,
            settings.relay_port,
            action_address,
            settings.operator_address,
        ),
    )
    return {"ingress": ingress, "relay": relay}


# La sonde de bout en bout tourne à sa propre cadence, plus lente que le tick
# du superviseur : envoyer un vrai message chaque minute inonderait le pipeline.
# Entre deux envois, le dernier résultat reste affiché - une panne persiste à
# l'écran, elle ne clignote pas.
_PROBE_STATE: dict[str, object] = {"at": None, "result": {"status": "unknown"}}


async def _maybe_probe(
    pool: asyncpg.Pool[Any], settings: Settings
) -> dict[str, object]:
    if not settings.probe_enabled:
        return {"status": "disabled"}
    now = time.monotonic()
    last = _PROBE_STATE["at"]
    due = last is None or (now - float(last)) >= settings.probe_interval_seconds
    if due:
        try:
            _PROBE_STATE["result"] = await run_probe(pool, settings)
        except Exception as exc:  # noqa: BLE001 - la sonde ne casse pas le tick
            _PROBE_STATE["result"] = {"status": "unknown", "error": type(exc).__name__}
        _PROBE_STATE["at"] = now
    return dict(_PROBE_STATE["result"])  # type: ignore[arg-type]


# Sortie du corps de la fonction pour être exécutable seule : une requête que
# l'on ne peut lancer qu'en montant tout le superviseur ne se teste pas contre
# une vraie base, et c'est pourtant la seule façon de vérifier ce qu'elle
# compte.
REVIEW_GUARD_SQL = """
        SELECT
          count(*) FILTER (
            WHERE m.delivery_status='held'
              -- Un dossier abandonné est clos : il n'attend plus d'avis, et
              -- n'en recevra jamais. Le compter ici allumerait une alerte que
              -- plus rien ne pourrait éteindre.
              AND dc.state <> 'ignored'
              AND dc.updated_at < now()-interval '1 minute'
              AND NOT EXISTS (
                SELECT 1 FROM smtp_actions sa
                JOIN assistant_outbox ao ON ao.action_id=sa.id
                WHERE sa.case_id=dc.id AND sa.action='release_original'
                  AND (
                    ao.status IN ('pending','sending','sent')
                    OR (ao.status='error' AND ao.attempts < 5)
                  )
              )
          ) AS unprotected_holds,
          count(*) FILTER (
            WHERE m.delivery_status='held'
              AND dc.state <> 'ignored'
              AND dc.updated_at < now()-interval '10 minutes'
              AND NOT EXISTS (
                SELECT 1 FROM smtp_actions sa
                JOIN assistant_outbox ao ON ao.action_id=sa.id
                WHERE sa.case_id=dc.id AND sa.action='release_original'
                  AND ao.status='sent'
              )
          ) AS silent_holds
        FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
        """


# Les messages que le secours a gardés retenus parce que le Code les tient pour
# dangereux, et dont aucun avis n'est parti. Aucun filtre d'heure : chaque
# retentative réhorodate le dossier, et un filtre ferait clignoter le signal.
# Il retombe seul quand l'avis part, quand le dossier est abandonné ou clos,
# ou quand le message quitte la retenue.
FAIL_CLOSED_SQL = """
        SELECT count(*) AS fail_closed_holds
        FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
        WHERE m.delivery_status='held'
          AND dc.state NOT IN ('ignored','closed')
          AND dc.details->>'review_guard'='fail_closed'
          AND NOT EXISTS (
            SELECT 1 FROM smtp_actions sa
            JOIN assistant_outbox ao ON ao.action_id=sa.id
            WHERE sa.case_id=dc.id AND sa.action='release_original'
              AND ao.status='sent'
          )
        """


# Un retour authentifié n'est pris en compte que si ses effets durables sont
# cohérents. Cette requête ne surveille que les retours postérieurs à la
# migration de réparation : les choix historiques sont repris une fois par la
# migration 082, puis chaque nouveau retour est contrôlé après un bref délai de
# grâce. Une politique opposée posée plus tard, comme une règle attendue
# retirée plus tard, est un changement d'avis, pas un échec de prise en compte.
_FEEDBACK_INTEGRITY_CTE = """
WITH feedback AS (
    SELECT
        l.id,
        l.message_id,
        l.created_at,
        l.label,
        l.is_ground_truth,
        l.confidence,
        l.sender_normalized,
        l.participant_email,
        l.subject,
        l.context,
        CASE
          WHEN l.context->>'interpretation'='digest_choice'
               AND l.label='legitimate' THEN 'allow'
          WHEN l.context->>'interpretation'='digest_choice'
               AND l.label IN ('spam','dangerous','suspect') THEN 'hold'
          WHEN ai.binding=true
               AND ai.requested_action='release_original'
               AND l.label='legitimate' THEN 'allow'
          WHEN ai.binding=true
               AND ai.requested_action='suppress_future'
               AND l.label IN ('spam','dangerous','suspect') THEN 'hold'
          WHEN ai.binding=true
               AND ai.raw_response->>'choice'='A'
               AND l.label='legitimate' THEN 'allow'
          WHEN ai.binding=true
               AND ai.raw_response->>'choice'='B'
               AND l.label IN ('spam','dangerous','suspect') THEN 'hold'
          ELSE NULL
        END AS expected_policy
    FROM labels l
    LEFT JOIN assistant_interpretations ai
      ON ai.conversation_message_id::text=l.context->>'conversation_message_id'
    WHERE l.source='smtp_feedback_user'
      AND l.active=true
      AND l.created_at < now()-interval '2 minutes'
      AND l.created_at > coalesce(
          (
            SELECT max(created_at) FROM audit_log
            WHERE action='feedback.integrity_repaired'
          ),
          now()-interval '24 hours'
      )
), mismatches AS (
    SELECT f.*
    FROM feedback f
    WHERE
      f.label NOT IN ('legitimate','spam','dangerous','suspect')
      OR f.is_ground_truth=false
      OR f.confidence IS DISTINCT FROM 1::double precision
      OR nullif(f.sender_normalized,'') IS NULL
      OR position('@' in coalesce(f.sender_normalized,''))=0
      OR nullif(f.participant_email,'') IS NULL
      OR position('@' in coalesce(f.participant_email,''))=0
      OR (
        f.message_id IS NOT NULL
        AND EXISTS (
          SELECT 1 FROM clues c
          JOIN investigations i ON i.id=c.investigation_id
          WHERE i.message_id=f.message_id AND c.direction <> 'neutral'
        )
        AND (
          jsonb_typeof(f.context->'signals') IS DISTINCT FROM 'array'
          OR jsonb_array_length(
              CASE
                WHEN jsonb_typeof(f.context->'signals')='array'
                THEN f.context->'signals'
                ELSE '[]'::jsonb
              END
          )=0
        )
      )
      OR (
        f.expected_policy IS NOT NULL
        -- Un choix B retient l'expéditeur prouvé (souvent son domaine), ou
        -- rien si l'identité n'est pas prouvée : le journal en fait foi.
        AND NOT EXISTS (
          SELECT 1 FROM audit_log a
          WHERE a.action IN (
              'sender_list.proven_block_applied','sender_list.identity_unproven'
            )
            AND a.payload->>'message_id'=f.message_id::text
        )
        AND NOT EXISTS (
          SELECT 1 FROM sender_policies p
          WHERE sentimail_same_client(p.participant_email,f.participant_email)
            AND p.scope='sender'
            AND p.value_normalized=lower(f.sender_normalized)
            AND p.action=f.expected_policy
            AND p.active=true
        )
        AND NOT EXISTS (
          SELECT 1 FROM sender_policies p
          WHERE sentimail_same_client(p.participant_email,f.participant_email)
            AND p.scope='sender'
            AND p.value_normalized=lower(f.sender_normalized)
            AND p.action<>f.expected_policy
            AND p.active=true
            AND p.updated_at > f.created_at
        )
        -- La règle attendue a existé, puis a été retirée après coup : c'est
        -- une décision postérieure, pas un retour resté sans effet. Un
        -- opérateur qui révoque une autorisation ne pose pas de règle
        -- opposée, il désactive celle qui existait - sans cette clause, le
        -- retour d'origine paraissait n'avoir jamais été appliqué, et
        -- l'exploitation restait dégradée sur un geste volontaire.
        AND NOT EXISTS (
          SELECT 1 FROM sender_policies p
          WHERE sentimail_same_client(p.participant_email,f.participant_email)
            AND p.scope='sender'
            AND p.value_normalized=lower(f.sender_normalized)
            AND p.action=f.expected_policy
            AND p.active=false
            AND p.updated_at > f.created_at
        )
      )
)
"""

# Un compteur de retard sans le message derrière ne s'exploite pas : le
# 14 septembre 2026, l'alerte disait « des messages attendent leur analyse »
# sans nommer le message ni l'étape où il bloquait. Même fenêtre et même seuil
# que accepted_without_terminal_outcome, sinon la liste et le compteur se
# contredisent. Une inspection en cours n'est pas visible ici :
# external_analyses n'est écrite qu'à la fin de l'inspection.
#
# Un message qui attend, dans les temps, un essai planifié après une panne
# passagère du modèle n'est pas en retard : il attend une échéance choisie
# (15 octobre 2026). Il réapparaît ici dès que l'échéance est manquée.
STALLED_MESSAGES_SQL = """
-- stalled : acceptés depuis plus de dix minutes, sans livraison ni avis
SELECT m.id::text AS message_id,
       left(m.subject, 60) AS subject,
       m.delivery_status,
       extract(epoch FROM now()-m.captured_at)::int AS waiting_seconds,
       vr.status AS run_status,
       vr.attempts AS run_attempts,
       vr.error_type AS run_error_type,
       CASE WHEN vr.status='error' AND vr.completed_at IS NULL
                 AND vr.next_attempt_at IS NOT NULL
            THEN extract(epoch FROM now()-vr.next_attempt_at)::int
       END AS retry_overdue_seconds,
       llm.model_name AS llm_model,
       llm.stage AS llm_stage,
       extract(epoch FROM now()-llm.created_at)::int AS llm_since_seconds
FROM messages m
LEFT JOIN LATERAL (
    SELECT vr.status, vr.attempts, vr.error_type, vr.completed_at,
           vr.next_attempt_at
    FROM verdict_runs vr JOIN investigations i ON i.id=vr.investigation_id
    WHERE i.message_id=m.id
    ORDER BY vr.started_at DESC NULLS LAST LIMIT 1
) vr ON true
LEFT JOIN LATERAL (
    SELECT model_name, stage, created_at FROM verdict_llm_call_events
    WHERE message_id=m.id AND completed_at IS NULL
    ORDER BY created_at DESC LIMIT 1
) llm ON true
WHERE m.captured_at > now()-interval '24 hours'
  AND m.captured_at < now()-interval '10 minutes'
  AND m.delivery_status IN ('captured','analyzing','release_pending','deferred')
  AND NOT """ + retry_on_schedule_sql("m") + """
ORDER BY m.captured_at
LIMIT 5
"""

# Les messages dont l'essai planifié a manqué son échéance.
RETRY_OVERDUE_SQL = """
SELECT count(*) AS verdict_retries_overdue FROM messages m
WHERE m.delivery_status IN ('captured','analyzing')
  AND """ + retry_overdue_sql("m")

# Ce que la rémission raconte : le sort des messages qui attendaient pendant
# l'épisode. Le mail « c'est reparti » disait tout est reparti, rien d'autre.
EPISODE_OUTCOME_SQL = """
SELECT m.id::text AS message_id,
       left(m.subject, 60) AS subject,
       m.delivery_status,
       extract(epoch FROM (
         SELECT max(de.created_at) FROM delivery_events de
         JOIN delivery_cases dc ON dc.id=de.case_id
         WHERE dc.message_id=m.id AND de.event_type IN (
           'original_delivered','original_released',
           'original_filed_as_junk','policy_suppressed'
         )
       ) - m.captured_at)::int AS waited_seconds
FROM messages m
WHERE m.id::text = ANY($1::text[])
ORDER BY m.captured_at
"""

FEEDBACK_INTEGRITY_SQL = _FEEDBACK_INTEGRITY_CTE + """
SELECT count(*) AS feedback_application_mismatches FROM mismatches
"""

FEEDBACK_INTEGRITY_EXAMPLES_SQL = _FEEDBACK_INTEGRITY_CTE + """
SELECT
  'feedback'::text AS kind,
  message_id::text AS message_id,
  'authenticated_smtp_feedback'::text AS component,
  'application_mismatch'::text AS error_type,
  created_at AS observed_at,
  left(subject,60) AS subject
FROM mismatches
ORDER BY created_at DESC
LIMIT 12
"""


# Une analyse non demandée n'est pas une analyse manquante. L'exemption exige
# un parcours rapide identifié et son exécution terminale réelle, jamais la
# seule déclaration d'un fournisseur ou la seule absence d'enquêteur.
DEEP_ANALYSIS_NOT_APPLICABLE_SQL = """(
    vr.status='complete' AND EXISTS (
        SELECT 1 FROM messages fast_m
        JOIN delivery_cases fast_dc ON fast_dc.message_id=fast_m.id
        WHERE fast_m.id=i.message_id AND fast_dc.binding=true
          AND fast_dc.investigation_id=vr.investigation_id
          AND (
            (
              vr.response#>>'{api,provider}'='authenticated_sender_policy'
              AND vr.input_snapshot->>'schema'='sentimail-authenticated-sender-policy-v1'
              AND vr.response#>>'{verdict,delivery_decision}'='suppress'
              AND fast_m.delivery_status='suppressed'
              AND fast_dc.state='policy_suppressed'
              AND fast_dc.original_delivery_allowed=false
              AND fast_dc.details#>>'{final_judgment,delivery_decision}'='suppress'
              AND EXISTS (SELECT 1 FROM delivery_events fast_de
                  WHERE fast_de.case_id=fast_dc.id AND fast_de.event_type='policy_suppressed')
            ) OR (
              vr.response#>>'{api,provider}'='express_path'
              AND vr.response#>>'{verdict,delivery_decision}'='deliver'
              AND vr.response#>>'{verdict,classification}'='legitimate'
              AND fast_m.delivery_status='delivered'
              AND fast_dc.original_delivery_allowed=true
              AND fast_dc.details#>>'{final_judgment,delivery_decision}'='deliver'
              AND EXISTS (SELECT 1 FROM delivery_events fast_de
                  WHERE fast_de.case_id=fast_dc.id
                    AND fast_de.event_type IN ('original_delivered','original_released'))
            )
          )
    )
)"""


async def _model_usage_24h(pool: Any, *, as_of: datetime | None = None) -> dict[str, Any]:
    """Compte toutes les tentatives observées ; une mesure absente reste inconnue."""
    end = (as_of or datetime.now(timezone.utc)).astimezone(timezone.utc)
    period = {"window_start_utc": (end-timedelta(hours=24)).isoformat(), "window_end_utc": end.isoformat()}
    try:
        async with asyncio.timeout(3):
            value = await pool.fetchval("""
                WITH attempts AS MATERIALIZED (
                    SELECT * FROM llm_attempt_events WHERE created_at >= $1 AND created_at < $2
                ), groups AS (
                    SELECT role,provider,model_name,count(*) AS attempts,
                        count(DISTINCT message_id) AS distinct_messages,
                        count(*) FILTER (WHERE status='complete') AS complete,
                        count(*) FILTER (WHERE status='error') AS error,
                        count(*) FILTER (WHERE status='cancelled') AS cancelled,
                        count(*) FILTER (WHERE status='started') AS started,
                        count(*) FILTER (WHERE num_nonnulls(input_tokens,output_tokens,cache_read_tokens,cache_creation_tokens)>0) AS usage_reported,
                        coalesce(sum(input_tokens),0) AS input_tokens,coalesce(sum(output_tokens),0) AS output_tokens,
                        coalesce(sum(cache_read_tokens),0) AS cache_read_tokens,
                        coalesce(sum(cache_creation_tokens),0) AS cache_creation_tokens
                    FROM attempts GROUP BY role,provider,model_name
                ) SELECT jsonb_build_object('attempts',count(*),
                    'distinct_messages',count(DISTINCT message_id),
                    'unattributed_attempts',count(*) FILTER (WHERE message_id IS NULL),
                    'usage_reported',count(*) FILTER (WHERE num_nonnulls(input_tokens,output_tokens,cache_read_tokens,cache_creation_tokens)>0),
                    'groups',coalesce((SELECT jsonb_agg(to_jsonb(g) ORDER BY role,provider,model_name) FROM groups g),'[]'))
                FROM attempts
                """, end-timedelta(hours=24), end)
        value = json.loads(value) if isinstance(value, str) else value
        if not isinstance(value, dict):
            raise ValueError("synthèse de consommation invalide")
        return {"status": "ok", **period, **value}
    except Exception as exc:
        return {"status": "unavailable", **period, "error_type": type(exc).__name__}


async def _snapshot(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    *,
    previously_observed: frozenset[str] | set[str] = frozenset(),
) -> dict[str, object]:
    row = await pool.fetchrow(
        """
        SELECT
          count(*) FILTER (
            WHERE m.delivery_status IN ('captured','analyzing')
              AND m.captured_at < now()-interval '10 minutes'
              AND NOT """ + retry_on_schedule_sql("m") + """
          ) AS analysis_backlog,
          count(*) FILTER (
            WHERE m.delivery_status IN ('release_pending','deferred')
              AND m.captured_at < now()-interval '5 minutes'
          ) AS delivery_backlog
        FROM messages m
        -- Les retards ouverts restent surveillés même s'ils datent de plusieurs mois.
        WHERE m.delivery_status IN ('captured','analyzing','release_pending','deferred')
        """
    )
    outbox_errors = await pool.fetchval(
        """
        SELECT count(*) FROM assistant_outbox
        WHERE (status='error' AND attempts >= 5)
           OR (status IN ('pending','sending') AND created_at < now()-interval '10 minutes')
        """
    )
    review_guard = await pool.fetchrow(REVIEW_GUARD_SQL)
    fail_closed_holds = await pool.fetchval(FAIL_CLOSED_SQL)
    # Une retenue livrée faute d'avis, en boîte de réception ou dans
    # Indésirables selon son classement : chaque secours se voit.
    review_fail_open = await pool.fetchval(
        """
        SELECT count(*) AS review_fail_open_last_hour FROM audit_log
        WHERE action='review.fail_open_requested'
          AND created_at > now()-interval '1 hour'
        """
    )
    # Un indésirable parti annoté, liens actifs, faute d'enveloppe neutralisée.
    junk_envelope_fallbacks = await pool.fetchval(
        """
        SELECT count(*) AS junk_envelope_fallbacks_last_hour FROM delivery_events
        WHERE event_type='original_filed_as_junk'
          AND details->>'junk_envelope'='annotated_original'
          AND created_at > now()-interval '1 hour'
        """
    )
    workflow = await pool.fetchrow(
        """
        SELECT
          count(*) FILTER (
            WHERE m.captured_at > now()-interval '24 hours'
              AND m.captured_at < now()-interval '2 minutes'
              AND m.delivery_status='delivered'
              AND NOT EXISTS (
                SELECT 1 FROM delivery_events de
                WHERE de.case_id=dc.id
                  -- Un classement en indésirables est une livraison : il a son
                  -- propre événement, et l'oublier ici ferait accuser de
                  -- silence les messages les mieux traités.
                  AND de.event_type IN (
                    'original_delivered','original_released',
                    'original_filed_as_junk'
                  )
              )
          ) AS delivered_without_smtp_event,
          count(*) FILTER (
            WHERE m.captured_at > now()-interval '24 hours'
              AND m.captured_at < now()-interval '10 minutes'
              AND (
                (
                  m.delivery_status IN ('captured','analyzing','release_pending','deferred')
                  AND NOT """ + retry_on_schedule_sql("m") + """
                )
                OR (
                  m.delivery_status='held'
                  AND NOT EXISTS (
                    SELECT 1 FROM smtp_actions sa
                    JOIN assistant_outbox ao ON ao.action_id=sa.id
                    WHERE sa.case_id=dc.id AND sa.action='release_original'
                      AND ao.status='sent'
                  )
                )
              )
          ) AS accepted_without_terminal_outcome,
          count(*) FILTER (
            WHERE m.captured_at > now()-interval '24 hours'
              AND m.captured_at < now()-interval '2 minutes'
              AND m.delivery_status='suppressed'
              AND NOT EXISTS (
                SELECT 1 FROM delivery_events de
                WHERE de.case_id=dc.id AND de.event_type='policy_suppressed'
              )
          ) AS suppressed_without_event,
          count(*) FILTER (
            WHERE m.captured_at > now()-interval '24 hours'
              AND m.delivery_status='delivered'
              AND EXISTS (
                SELECT 1 FROM delivery_events de
                WHERE de.case_id=dc.id
                  AND de.event_type IN ('original_delivered','original_released')
                  AND de.smtp_queue_id IS NULL
                  AND de.created_at > coalesce(
                    (
                      SELECT max(al.created_at) FROM audit_log al
                      WHERE al.action='code.trial_roles_identity_and_supervision_enabled'
                    ),
                    '-infinity'::timestamptz
                  )
              )
          ) AS smtp_events_without_queue_id
        FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
        WHERE m.captured_at > now()-interval '24 hours'
        """
    )
    # Le contrôle inverse de verdict_execution_mismatches : celui-ci guette un
    # ordre de livraison resté sans effet, celui-là un ordre de classement.
    # Le 14 août, deux messages jugés indésirables - dont une extorsion - sont
    # arrivés en boîte de réception parce que l'écriture de leur classement
    # avait échoué, et rien ne l'a signalé.
    junk_not_filed = await pool.fetchval(
        """
        SELECT count(*) AS junk_not_filed
        FROM delivery_cases dc JOIN messages m ON m.id=dc.message_id
        WHERE m.captured_at > now()-interval '24 hours'
          AND m.captured_at < now()-interval '10 minutes'
          AND dc.details->'final_judgment'->>'delivery_decision'='junk'
          AND m.delivery_status='delivered'
          AND NOT EXISTS (
              SELECT 1 FROM delivery_events de
              WHERE de.case_id=dc.id AND de.event_type='original_filed_as_junk'
          )
        """
    )
    # Un enquêteur profond qui cesse de tourner ne casse rien : il disparaît.
    # Sans ce contrôle, un contournement de chemin d'exécution retirerait
    # silencieusement une famille entière de critères.
    missing_deep_hook_runs = await pool.fetchval(
        f"""
        SELECT count(*) AS missing_deep_hook_runs FROM verdict_runs vr
        JOIN investigations i ON i.id=vr.investigation_id
        WHERE vr.status='complete'
          AND NOT {DEEP_ANALYSIS_NOT_APPLICABLE_SQL}
          AND vr.completed_at > now()-interval '1 hour'
          AND vr.completed_at < now()-interval '2 minutes'
          AND EXISTS (
              SELECT 1 FROM hook_runs hr
              WHERE hr.investigation_id=i.id AND hr.hook_name='deep_evidence'
          )
          AND EXISTS (
              SELECT 1 FROM unnest($1::text[]) AS required(name)
              WHERE NOT EXISTS (
                  SELECT 1 FROM hook_runs hr
                  WHERE hr.investigation_id=i.id AND hr.hook_name=required.name
              )
              -- Le contrôle porte sur chaque enquêteur, après son activation.
              -- La migration borne le démarrage des nouveaux sans accuser le passé.
              AND vr.created_at > COALESCE(
                  (SELECT MIN(hr.created_at) FROM hook_runs hr WHERE hr.hook_name=required.name),
                  (SELECT MIN(created_at) FROM audit_log WHERE action='code.action_destination_coherence')
              )
          )
        """,
        list(REQUIRED_DEEP_HOOKS),
    )
    # « Jamais contourné » se garantit : l'enquêteur qui confronte le domaine
    # réel au message doit rendre un constat à chaque passage. Un « skip » ou
    # une erreur ici est le silence qui a livré le faux reçu du 16 septembre
    # 2026, et il doit sonner.
    sender_relation_silent = await pool.fetchval(
        f"""
        SELECT count(*) AS sender_relation_silent FROM hook_runs hr
        WHERE hr.hook_name='sender_relation'
          AND hr.status <> 'ok'
          AND hr.created_at > now()-interval '1 hour'
          AND NOT EXISTS (SELECT 1 FROM verdict_runs vr JOIN investigations i ON i.id=vr.investigation_id
              WHERE i.id=hr.investigation_id AND {DEEP_ANALYSIS_NOT_APPLICABLE_SQL})
        """
    )
    coherence_hook_failures = await pool.fetchval(
        f"""
        SELECT count(*) AS coherence_hook_failures FROM hook_runs hr
        WHERE hook_name IN ('sender_activity','action_destination')
          AND (
              (status <> 'ok' AND NOT (status='skip' AND coalesce(facts->>'status','')='not_applicable'))
              OR jsonb_array_length(coalesce(facts->'failure_types','[]'::jsonb)) > 0
          )
          AND hr.created_at > now()-interval '1 hour'
          AND NOT EXISTS (SELECT 1 FROM verdict_runs vr JOIN investigations i ON i.id=vr.investigation_id
              WHERE i.id=hr.investigation_id AND {DEEP_ANALYSIS_NOT_APPLICABLE_SQL})
        """
    )
    # Un échec n'est acquis qu'à l'épuisement, marqué par la date de fin : un
    # troisième échec passager attend encore son quatrième essai.
    verdict_errors = await pool.fetchval(
        """
        SELECT count(*) FROM verdict_runs
        WHERE status='error' AND attempts >= $1 AND completed_at IS NOT NULL
          AND started_at > now()-interval '1 hour'
        """,
        VERDICT_MAX_ATTEMPTS,
    )
    provider_credit_exhausted = await pool.fetchval(
        """
        SELECT count(*) AS verdict_provider_credit_exhausted
        FROM verdict_runs
        WHERE status='error' AND attempts >= $1 AND completed_at IS NOT NULL
          AND error_detail='LLM HTTP 402'
          AND started_at > now()-interval '1 hour'
        """,
        VERDICT_MAX_ATTEMPTS,
    )
    verdict_retries_overdue = await pool.fetchval(RETRY_OVERDUE_SQL)
    # Au-delà du plafond historique, un run n'a pu continuer que par les
    # essais espacés (ou par la reprise d'un essai coupé au redémarrage) :
    # son épuisement est celui de toute la série.
    verdict_retries_exhausted = await pool.fetchval(
        """
        SELECT count(*) AS verdict_retries_exhausted FROM verdict_runs
        WHERE status='error' AND attempts > $1
          AND completed_at > now()-interval '1 hour'
        """,
        VERDICT_MAX_ATTEMPTS,
    )
    # Le moteur de recherche, sur lequel repose la confrontation d'un nom à
    # ses domaines officiels. Un refus de clé est un état, pas un compteur :
    # on compte les refus postérieurs au dernier succès réel (une recherche
    # qui rend au moins un résultat s'inscrit toujours dans `search_lookups`),
    # pour que le signal retombe seul à ce premier succès et ne clignote pas
    # quand une heure passe sans recherche neuve. Sept jours de fenêtre :
    # au-delà, un refus ancien sans aucune recherche depuis ne décrit plus
    # rien. Le détail garde le nombre de refus ; le signal, lui, vaut 0 ou 1,
    # pour qu'une panne qui dure ne réveille pas une alerte à chaque nom
    # cherché.
    organisation_search_rejections = await pool.fetchval(
        """
        SELECT count(*) AS organisation_search_rejected FROM hook_runs hr
        WHERE hr.hook_name='sender_relation'
          AND hr.facts->>'search_unavailable'='rejected'
          AND hr.created_at > now()-interval '7 days'
          AND hr.created_at > COALESCE(
              (SELECT max(checked_at) FROM search_lookups),
              '-infinity'::timestamptz
          )
        """
    )
    organisation_search_errors = await pool.fetchval(
        """
        SELECT count(*) AS organisation_search_errors_last_hour FROM hook_runs hr
        WHERE hr.hook_name='sender_relation'
          AND hr.facts->>'search_unavailable'='error'
          AND hr.created_at > now()-interval '1 hour'
        """
    )
    verdict_execution_mismatches = await pool.fetchval(
        """
        SELECT count(*) FROM verdict_runs vr
        JOIN investigations i ON i.id=vr.investigation_id
        JOIN messages m ON m.id=i.message_id
        JOIN delivery_cases dc ON dc.message_id=m.id
        WHERE vr.status='complete'
          AND vr.prompt_version LIKE 'code-sentinel-verdict-%'
          AND vr.completed_at > now()-interval '1 hour'
          AND vr.completed_at < now()-interval '2 minutes'
          AND (
            vr.response->'verdict'->>'delivery_decision' IS NULL
            OR vr.response->'verdict'->>'delivery_decision'
                 IS DISTINCT FROM dc.details->'final_judgment'->>'delivery_decision'
            OR (
              vr.response->'verdict'->>'delivery_decision'='deliver'
              AND (
                dc.original_delivery_allowed=false
                OR m.delivery_status IN ('captured','analyzing','held')
              )
            )
            OR (
              vr.response->'verdict'->>'delivery_decision'='suppress'
              AND (
                m.delivery_status<>'suppressed'
                OR dc.original_delivery_allowed=true
                OR NOT EXISTS (
                  SELECT 1 FROM delivery_events de
                  WHERE de.case_id=dc.id AND de.event_type='policy_suppressed'
                )
              )
            )
          )
        """
    )
    feedback_application_mismatches = await pool.fetchval(
        FEEDBACK_INTEGRITY_SQL
    )
    soft_failures = await pool.fetchrow(
        f"""
        SELECT
          (
            SELECT count(*) FROM hook_runs hr
            JOIN investigations i ON i.id=hr.investigation_id
            WHERE hr.status='error' AND hr.created_at > now()-interval '1 hour'
          ) AS hook_errors_last_hour,
          (
            SELECT count(*) FROM investigations i
            WHERE i.status IN ('partial','error')
              AND i.started_at > now()-interval '1 hour'
          ) AS partial_investigations_last_hour,
          (
            SELECT count(*) FROM investigations i
            WHERE i.started_at > now()-interval '1 hour'
              AND i.started_at < now()-interval '2 minutes'
              AND (
                SELECT count(DISTINCT hr.hook_name) FROM hook_runs hr
                WHERE hr.investigation_id=i.id
                  AND hr.hook_name=ANY($1::text[])
              ) < $2
          ) AS missing_required_hook_sets,
          (
            SELECT count(*) FROM verdict_runs vr
            JOIN investigations i ON i.id=vr.investigation_id
            WHERE vr.status='complete'
              AND NOT {DEEP_ANALYSIS_NOT_APPLICABLE_SQL}
              AND vr.completed_at > now()-interval '1 hour'
              AND NOT EXISTS (
                SELECT 1 FROM hook_runs hr
                WHERE hr.investigation_id=i.id AND hr.hook_name='deep_evidence'
              )
          ) AS missing_deep_evidence,
          (
            SELECT count(*) FROM investigations i
            JOIN messages m ON m.id=i.message_id
            WHERE i.started_at > now()-interval '1 hour'
              AND i.started_at < now()-interval '10 minutes'
              AND position('@' in coalesce(m.from_header,'')) > 0
              AND NOT EXISTS (SELECT 1 FROM verdict_runs vr
                  WHERE vr.investigation_id=i.id AND {DEEP_ANALYSIS_NOT_APPLICABLE_SQL})
              AND NOT EXISTS (
                SELECT 1 FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
                WHERE e.message_id=m.id AND e.entity_type='domain'
                  AND e.role='address:from' AND en.status='ok'
              )
          ) AS sender_domain_enrichment_gaps,
          (
            SELECT count(*) FROM external_analyses ea
            JOIN messages m ON m.id=ea.message_id
            WHERE ea.status='error' AND ea.error_type IS NOT NULL
              AND ea.completed_at > now()-interval '1 hour'
          ) AS external_analysis_service_errors_last_hour,
          -- Une inspection d'URL qui dépasse le plafond que le bac à sable
          -- s'impose (5 s par saut, 40 s au total) signale que ce plafond ne
          -- tient plus. C'est ce qui manquait le 18 août : une fermeture TLS de
          -- trente secondes par URL ne laissait aucune trace d'erreur, et le
          -- superviseur ne voyait le problème qu'au bout de dix minutes de
          -- retard cumulé - le symptôme, pas la cause.
          (
            SELECT count(*) FROM external_analyses ea
            WHERE ea.subject_kind='url'
              AND ea.completed_at > now()-interval '1 hour'
              AND ea.completed_at - ea.started_at > interval '45 seconds'
          ) AS slow_url_inspections,
          (
            SELECT count(*) FROM conversation_messages
            WHERE processing_status='error'
              AND created_at > now()-interval '1 hour'
          ) AS assistant_interpretation_errors_last_hour
        """,
        list(REQUIRED_STATIC_HOOKS),
        len(REQUIRED_STATIC_HOOKS),
    )
    soft_failure_examples = await pool.fetch(
        """
        SELECT failures.*, left(sujet.subject, 60) AS subject FROM (
          SELECT 'hook'::text AS kind,i.message_id::text AS message_id,
                 hr.hook_name AS component,hr.error_type,hr.created_at AS observed_at
          FROM hook_runs hr JOIN investigations i ON i.id=hr.investigation_id
          WHERE hr.status='error' AND hr.created_at > now()-interval '1 hour'
          UNION ALL
          SELECT 'external_analysis',ea.message_id::text,ea.source,ea.error_type,
                 ea.completed_at
          FROM external_analyses ea
          WHERE ea.status='error' AND ea.error_type IS NOT NULL
            AND ea.completed_at > now()-interval '1 hour'
          UNION ALL
          SELECT 'assistant',cm.message_id::text,'smtp_reply_interpretation',
                 'processing_error',cm.created_at
          FROM conversation_messages cm
          WHERE cm.processing_status='error'
            AND cm.created_at > now()-interval '1 hour'
          UNION ALL
          SELECT 'verdict_execution',i.message_id::text,'final_judgment',
                 'execution_mismatch',vr.completed_at
          FROM verdict_runs vr
          JOIN investigations i ON i.id=vr.investigation_id
          JOIN messages m ON m.id=i.message_id
          JOIN delivery_cases dc ON dc.message_id=m.id
          WHERE vr.status='complete'
            AND vr.prompt_version LIKE 'code-sentinel-verdict-%'
            AND vr.completed_at > now()-interval '1 hour'
            AND vr.completed_at < now()-interval '2 minutes'
            AND (
              vr.response->'verdict'->>'delivery_decision' IS NULL
              OR vr.response->'verdict'->>'delivery_decision'
                   IS DISTINCT FROM dc.details->'final_judgment'->>'delivery_decision'
              OR (
                vr.response->'verdict'->>'delivery_decision'='deliver'
                AND (
                  dc.original_delivery_allowed=false
                  OR m.delivery_status IN ('captured','analyzing','held')
                )
              )
              OR (
                vr.response->'verdict'->>'delivery_decision'='suppress'
                AND (
                  m.delivery_status<>'suppressed'
                  OR dc.original_delivery_allowed=true
                  OR NOT EXISTS (
                    SELECT 1 FROM delivery_events de
                    WHERE de.case_id=dc.id AND de.event_type='policy_suppressed'
                  )
                )
              )
            )
          UNION ALL
          SELECT 'delivery_guard',m.id::text,'fail_closed',
                 dc.details->>'review_guard_reason',dc.updated_at
          FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
          WHERE m.delivery_status='held'
            AND dc.state NOT IN ('ignored','closed')
            AND dc.details->>'review_guard'='fail_closed'
            AND NOT EXISTS (
              SELECT 1 FROM smtp_actions sa
              JOIN assistant_outbox ao ON ao.action_id=sa.id
              WHERE sa.case_id=dc.id AND sa.action='release_original'
                AND ao.status='sent'
            )
          UNION ALL
          -- L'identifiant vient d'une charge d'audit : un texte mal formé
          -- ferait échouer sa conversion en uuid plus bas, et tout le relevé.
          SELECT 'delivery_guard',al.payload->>'message_id','fail_open',
                 al.payload->>'route',al.created_at
          FROM audit_log al
          WHERE al.action='review.fail_open_requested'
            AND al.created_at > now()-interval '1 hour'
            AND al.payload->>'message_id' ~ '^[0-9a-f-]{36}$'
          UNION ALL
          SELECT 'junk_envelope',dc.message_id::text,'junk_envelope',
                 de.details->>'junk_envelope_error',de.created_at
          FROM delivery_events de JOIN delivery_cases dc ON dc.id=de.case_id
          WHERE de.event_type='original_filed_as_junk'
            AND de.details->>'junk_envelope'='annotated_original'
            AND de.created_at > now()-interval '1 hour'
        ) failures
        -- Le sujet rend l'exemple exploitable : « des verdicts n'ont pas été
        -- exécutés » ne dit rien tant qu'on ne sait pas de quel message il
        -- s'agit, et un identifiant interne n'apprend rien au destinataire.
        LEFT JOIN messages sujet ON sujet.id = failures.message_id::uuid
        ORDER BY failures.observed_at DESC LIMIT 12
        """
    )
    feedback_failure_examples = await pool.fetch(FEEDBACK_INTEGRITY_EXAMPLES_SQL)
    llm = await pool.fetchrow(
        """
        SELECT
          count(*) FILTER (WHERE created_at > now()-interval '1 hour') AS hourly,
          count(*) FILTER (WHERE created_at > now()-interval '24 hours') AS daily
        FROM verdict_llm_call_events
        WHERE created_at > now()-interval '24 hours'
        """
    )
    # Une rétention arrêtée est une dérive silencieuse : le contenu resterait
    # conservé au-delà de la fenêtre annoncée sans que personne ne le voie.
    retention_overdue = await pool.fetchval(
        f"""
        SELECT count(*) FROM messages m
        WHERE m.redacted_at IS NULL
          AND m.captured_at < now() - (($1 + 2) * interval '1 day')
          AND {RETENTION_ELIGIBLE_SQL}
        """,
        settings.retention_redact_after_days,
        list(RETENTION_OPEN_STATUSES),
    )
    stalled_messages = await pool.fetch(STALLED_MESSAGES_SQL)
    classifier_errors = await pool.fetchval("""SELECT count(*) FROM audit_log
        WHERE action='classifier.error' AND created_at > now()-interval '1 hour'""")
    classifier_unsafe = await pool.fetchval("""SELECT count(*) FROM audit_log
        WHERE action='classifier.disabled_after_divergence'
        AND created_at > now()-interval '1 day'""")
    classifier_cycle_unhealthy = await pool.fetchval("""SELECT count(*) FROM classifier_automation
        WHERE enabled AND (status='error'
          OR coalesce(last_completed_at,created_at)<now()-interval '36 hours'
          OR (status='running' AND last_started_at<now()-interval '10 minutes'))""")
    try:
        classifier_state = await asyncio.wait_for(classifier_report(pool), timeout=5)
    except Exception as exc:
        # La console doit dire qu'elle ne sait plus, plutôt que conserver un
        # ancien feu vert ou empêcher les autres contrôles du superviseur.
        classifier_state = {"error": type(exc).__name__}
    core_state = await core_health_snapshot(pool)
    backup_age = (
        datetime.now(timezone.utc).timestamp() - BACKUP_HEARTBEAT.stat().st_mtime
        if BACKUP_HEARTBEAT.exists()
        else None
    )
    identite = await instance_identity(pool, settings)
    preflight = await _smtp_preflights(settings, identite.action_address)
    mail_e2e = await _maybe_probe(pool, settings)
    details = {
        "core_rollout": core_state,
        **core_state["counters"],
        "model_usage_24h": await _model_usage_24h(pool),
        "classifier": classifier_state,
        "classifier_cycle_unhealthy": int(classifier_cycle_unhealthy or 0),
        "classifier_errors_last_hour": int(classifier_errors or 0),
        "classifier_unsafe_divergences": int(classifier_unsafe or 0),
        "mail_e2e": mail_e2e,
        "analysis_backlog": int(row["analysis_backlog"]),
        "delivery_backlog": int(row["delivery_backlog"]),
        "outbox_errors": int(outbox_errors),
        "unprotected_holds": int(review_guard["unprotected_holds"]),
        "silent_holds": int(review_guard["silent_holds"]),
        "fail_closed_holds": int(fail_closed_holds or 0),
        "review_fail_open_last_hour": int(review_fail_open or 0),
        "junk_envelope_fallbacks_last_hour": int(junk_envelope_fallbacks or 0),
        "delivered_without_smtp_event": int(workflow["delivered_without_smtp_event"]),
        "accepted_without_terminal_outcome": int(
            workflow["accepted_without_terminal_outcome"]
        ),
        "suppressed_without_event": int(workflow["suppressed_without_event"]),
        "smtp_events_without_queue_id": int(workflow["smtp_events_without_queue_id"]),
        "junk_not_filed": int(junk_not_filed or 0),
        "missing_deep_hook_runs": int(missing_deep_hook_runs or 0),
        "coherence_hook_failures": int(coherence_hook_failures or 0),
        "sender_relation_silent": int(sender_relation_silent or 0),
        "smtp_preflight": preflight,
        "verdict_errors_last_hour": int(verdict_errors),
        "verdict_provider_credit_exhausted": int(
            provider_credit_exhausted or 0
        ),
        "verdict_retries_overdue": int(verdict_retries_overdue or 0),
        "verdict_retries_exhausted": int(verdict_retries_exhausted or 0),
        "organisation_search_rejected": min(int(organisation_search_rejections or 0), 1),
        "organisation_search_rejections": int(organisation_search_rejections or 0),
        "organisation_search_errors_last_hour": int(
            organisation_search_errors or 0
        ),
        "hook_errors_last_hour": int(soft_failures["hook_errors_last_hour"]),
        "partial_investigations_last_hour": int(
            soft_failures["partial_investigations_last_hour"]
        ),
        "missing_required_hook_sets": int(
            soft_failures["missing_required_hook_sets"]
        ),
        "missing_deep_evidence": int(soft_failures["missing_deep_evidence"]),
        "sender_domain_enrichment_gaps": int(
            soft_failures["sender_domain_enrichment_gaps"]
        ),
        "slow_url_inspections": int(soft_failures["slow_url_inspections"]),
        "external_analysis_service_errors_last_hour": int(
            soft_failures["external_analysis_service_errors_last_hour"]
        ),
        "assistant_interpretation_errors_last_hour": int(
            soft_failures["assistant_interpretation_errors_last_hour"]
        ),
        "verdict_execution_mismatches": int(verdict_execution_mismatches),
        "feedback_application_mismatches": int(
            feedback_application_mismatches or 0
        ),
        "soft_failure_examples": [
            *[dict(value) for value in feedback_failure_examples],
            *[dict(value) for value in soft_failure_examples],
        ][:12],
        "stalled_messages": [dict(value) for value in stalled_messages][:5],
        "retention_overdue": int(retention_overdue or 0)
        if settings.retention_enabled
        else 0,
        "verdict_llm_hourly": int(llm["hourly"]),
        "verdict_llm_daily": int(llm["daily"]),
        "backup_age_seconds": round(backup_age) if backup_age is not None else None,
    }
    observed_reasons = _counter_reasons(details)
    if int(llm["hourly"]) >= int(settings.verdict_llm_hourly_limit * 0.8):
        observed_reasons.append("verdict_llm_hourly_near_limit")
    if int(llm["daily"]) >= int(settings.verdict_llm_daily_limit * 0.8):
        observed_reasons.append("verdict_llm_daily_near_limit")
    if backup_age is None or backup_age > 90_000:
        observed_reasons.append("backup_stale")
    down_reasons = [
        f"smtp_{name}_preflight_failed"
        for name, result in preflight.items()
        if result.get("status") == "down"
    ]
    # Un message qui n'entre plus dans le pipeline est une panne franche : le
    # préambule SMTP peut réussir pendant que la capture est morte.
    if mail_e2e.get("status") == "down":
        down_reasons.append("mail_e2e_" + str(mail_e2e.get("phase") or "failed"))
    # Ce qui a été vu reste inscrit dans le détail, même sans alerte : le tick
    # suivant s'en sert pour confirmer, et la console le montre en continu.
    details["observed_reasons"] = sorted(set(observed_reasons))
    degraded_reasons = _confirmed_reasons(observed_reasons, previously_observed)
    degraded_reasons.extend(down_reasons)
    details["reasons"] = degraded_reasons
    status = "down" if down_reasons else "degraded" if degraded_reasons else "ok"
    return {"status": status, "details": details}


async def _notify(
    settings: Settings, action_address: str, assistant_sender: str,
    status: str, details: dict[str, object]
) -> str | None:
    # Une exploitation portée par une seule adresse s'arrête de fonctionner dès
    # que cette personne est absente : l'alerte part vers chacun. Sans personne
    # à prévenir, il n'y a rien à composer - un courrier sans destinataire
    # serait refusé par le relais et compterait pour une alerte émise.
    destinataires = list(settings.operator_addresses)
    if not destinataires:
        return None
    rendu = watchdog_lettre(status, details)
    email = EmailMessage()
    email["From"] = assistant_sender
    email["To"] = ", ".join(destinataires)
    email["Reply-To"] = action_address
    email["Subject"] = rendu.subject
    # Une alerte sans date se range n'importe où dans la boîte de l'opérateur,
    # au moment précis où l'ordre d'arrivée est ce qui compte.
    email["Date"] = formatdate(localtime=True)
    email.set_content(rendu.text)
    email.add_alternative(rendu.html, subtype="html")
    result = await aiosmtplib.send(
        email,
        sender=action_address,
        recipients=destinataires,
        hostname=settings.relay_host,
        port=settings.relay_port,
        start_tls=False,
        timeout=30,
    )
    return extract_queue_id(result)


async def _store_status(
    pool: asyncpg.Pool[Any], status: str, details: dict[str, object]
) -> None:
    """Publie l'état courant et conserve la trace de chaque changement."""
    async with pool.acquire() as conn, conn.transaction():
        previous = await conn.fetchval(
            "SELECT status FROM operational_status WHERE component='sentimail-v3' FOR UPDATE"
        )
        await conn.execute(
            """
            INSERT INTO operational_status (component,status,details,observed_at)
            VALUES ('sentimail-v3',$1,$2::jsonb,now())
            ON CONFLICT (component) DO UPDATE SET
              status=EXCLUDED.status,details=EXCLUDED.details,observed_at=now()
            """,
            status,
            _json(details),
        )
        # Seules les transitions sont historisées : un état stable n'a pas besoin
        # d'une ligne par minute pour rester lisible.
        if previous is None or str(previous) != status:
            await conn.execute(
                """
                INSERT INTO operational_events (
                    component, status, previous_status, reasons, details
                ) VALUES ('sentimail-v3',$1,$2,$3::jsonb,$4::jsonb)
                """,
                status,
                previous,
                _json(details.get("reasons") or []),
                _json(details),
            )


async def _episode(
    pool: asyncpg.Pool[Any],
    previous_details: dict[str, object],
    history: dict[str, object],
    now: datetime,
) -> dict[str, object]:
    """La durée de l'épisode et le sort des messages qui attendaient."""
    episode: dict[str, object] = {}
    sent_at = history.get("degraded_sent_at")
    if sent_at:
        try:
            episode["duration_seconds"] = int(
                (now - datetime.fromisoformat(str(sent_at))).total_seconds()
            )
        except ValueError:
            pass
    ids = [
        str(message.get("message_id"))
        for message in previous_details.get("stalled_messages") or []  # type: ignore[union-attr]
        if isinstance(message, dict) and message.get("message_id")
    ]
    if ids:
        rows = await pool.fetch(EPISODE_OUTCOME_SQL, ids)
        episode["messages"] = [dict(row) for row in rows]
    return episode


async def _check(pool: asyncpg.Pool[Any], settings: Settings) -> None:
    # L'état précédent se lit avant le relevé : c'est lui qui dit ce qui avait
    # déjà été observé, et donc ce qu'une seconde observation peut confirmer.
    previous = await pool.fetchrow(
        "SELECT status,details FROM operational_status WHERE component='sentimail-v3'"
    )
    previous_status = str(previous["status"]) if previous is not None else None
    previous_details = previous["details"] if previous is not None else {}
    if isinstance(previous_details, str):
        previous_details = json.loads(previous_details)
    snapshot = await _snapshot(
        pool,
        settings,
        previously_observed=frozenset(previous_details.get("observed_reasons") or []),
    )
    previous_reasons = set(previous_details.get("reasons") or [])
    current_reasons = set(snapshot["details"].get("reasons") or [])
    new_reasons = sorted(current_reasons - previous_reasons)
    new_soft_failures = _increased_failure_counts(
        previous_details, snapshot["details"]
    )
    alert_pending = bool(previous_details.get("alert_pending"))
    should_notify = (
        (previous is None and snapshot["status"] != "ok")
        or (previous is not None and previous_status != snapshot["status"])
        or bool(new_reasons)
        or bool(new_soft_failures)
        or alert_pending
    )
    now = datetime.now(timezone.utc)
    history = dict(previous_details.get("alert_history") or {})
    signature = ",".join(sorted(current_reasons)) or "-"
    if should_notify and not alert_pending and snapshot["status"] == "degraded":
        last_sent = history.get("degraded_sent_at")
        recently_alerted = False
        if last_sent:
            try:
                recently_alerted = (
                    now - datetime.fromisoformat(str(last_sent)) < ALERT_COOLDOWN
                )
            except ValueError:
                recently_alerted = False
        if history.get("degraded_signature") == signature and recently_alerted:
            should_notify = False
            await pool.execute(
                """
                INSERT INTO audit_log(actor,action,payload)
                VALUES ('watchdog','operational.alert_suppressed',$1::jsonb)
                """,
                _json(
                    {
                        "signature": signature,
                        "last_sent_at": last_sent,
                        "new_soft_failure_occurrences": new_soft_failures,
                    }
                ),
            )
    if (
        should_notify
        and not alert_pending
        and snapshot["status"] == "ok"
        and not history.get("episode_alerted")
    ):
        # La rémission d'une dégradation dont l'alerte a été retenue n'a rien
        # à annoncer : l'utilisateur n'a jamais su que ça allait mal.
        should_notify = False
    if should_notify:
        notification_status = previous_status if alert_pending else str(snapshot["status"])
        notification_details = (
            {
                **previous_details,
                "current_status": snapshot["status"],
                "current_reasons": snapshot["details"].get("reasons", []),
            }
            if alert_pending
            else {
                **snapshot["details"],
                "new_soft_failure_occurrences": new_soft_failures,
            }
        )
        if (
            not alert_pending
            and snapshot["status"] == "ok"
            and previous_status in ("degraded", "down")
        ):
            notification_details["episode"] = await _episode(
                pool, previous_details, history, now
            )
        identite = await instance_identity(pool, settings)
        try:
            queue_id = await _notify(
                settings, identite.action_address, identite.assistant_sender,
                str(notification_status), notification_details
            )
        except Exception as exc:
            failed_details = {
                **snapshot["details"],
                "alert_pending": True,
                "alert_error_type": type(exc).__name__,
            }
            await _store_status(pool, "down", failed_details)
            await pool.execute(
                """
                INSERT INTO audit_log(actor,action,payload)
                VALUES ('watchdog','operational.alert_failed',$1::jsonb)
                """,
                _json(
                    {
                        "previous": previous_status,
                        "new_reasons": new_reasons,
                        "new_soft_failure_occurrences": new_soft_failures,
                        "error_type": type(exc).__name__,
                    }
                ),
            )
            set_status("watchdog", "down")
            raise
        await pool.execute(
            """
            INSERT INTO audit_log(actor,action,payload)
            VALUES ('watchdog','operational.status_changed',$1::jsonb)
            """,
            _json(
                {
                    "previous": previous_status,
                    "new_reasons": new_reasons,
                    "new_soft_failure_occurrences": new_soft_failures,
                    "alert_smtp_queue_id": queue_id,
                    **snapshot,
                }
            ),
        )
        if str(notification_status) == "ok":
            history["episode_alerted"] = False
        else:
            history["degraded_signature"] = signature
            history["degraded_sent_at"] = now.isoformat()
            history["episode_alerted"] = True
    await _store_status(
        pool,
        str(snapshot["status"]),
        {**snapshot["details"], "alert_history": history},
    )
    # La santé publiée ici est celle du superviseur, pas celle du système
    # qu'il observe. Un SentiMail dégradé se signale par son alerte et par
    # operational_status ; marquer le conteneur en panne pour autant ferait
    # croire à un superviseur muet, et bloquerait toute dépendance de service.
    set_status("watchdog", "ok")
    _log("watchdog.snapshot", **snapshot)


async def main() -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    _log("worker.started", component="watchdog")
    # Le fichier que le MX lit pour refuser les sources du registre. Le volume
    # est partagé avec le conteneur Postfix ; l'export est atomique et muet
    # quand rien n'a changé.
    hostile_path = os.environ.get(
        "HOSTILE_EXPORT_PATH", "/hostile-export/hostile.cidr"
    )
    while True:
        pulse("watchdog")
        try:
            await _check(pool, settings)
        except Exception as exc:  # noqa: BLE001 - watchdog loop must survive checks
            set_status("watchdog", "down")
            _log("watchdog.error", error=type(exc).__name__, detail=str(exc)[:300])
        try:
            entries = await export_hostile_cidr(pool, hostile_path)
            _log("hostile_export.tick", entries=entries)
        except Exception as exc:  # noqa: BLE001 - l'export attendra le tick suivant
            _log("hostile_export.error", error=type(exc).__name__)
        pulse("watchdog")
        await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(main())
