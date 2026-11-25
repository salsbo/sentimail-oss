"""Réserve les jugements et leurs quotas sous les verrous PostgreSQL."""

from __future__ import annotations

from typing import Any
import asyncpg
from sentimail_v3.code.tenancy import Quota, domain_of, protected_recipient, quota_of
from sentimail_v3.config import Settings
from sentimail_v3.judgment.verdict_retry import ATTEMPTS_CEILING
from sentimail_v3.judgment.prompt import PROMPT_VERSION

ENGINE = "llm"
class VerdictQuotaExceeded(RuntimeError):
    pass

async def _claim(pool: asyncpg.Pool[Any], settings: Settings) -> asyncpg.Record | None:
    configured_model = await pool.fetchval(
        "SELECT model_name FROM llm_role_providers WHERE role='verdict'"
    )
    return await pool.fetchrow(
        """
        WITH candidate AS (
            SELECT i.id, m.engine_generation
            FROM investigations i
            JOIN messages m ON m.id=i.message_id
            LEFT JOIN verdict_runs vr
              ON vr.investigation_id=i.id AND vr.engine=$1
             AND vr.prompt_version=$2
            WHERE (
                    ($6::boolean=false AND m.delivery_status='delivered')
                 OR ($6::boolean=true AND m.delivery_status IN ('captured','analyzing')
                     AND (
                       -- Ce qu'on attendait vraiment : que l'investigation ait
                       -- fini. Attendre une durée à la place coûtait trente
                       -- secondes sur chaque message, y compris ceux dont le
                       -- dossier était prêt en zéro seconde.
                       i.completed_at IS NOT NULL
                       -- Filet : un dossier dont l'investigation n'aboutit
                       -- jamais doit finir par être jugé, sans quoi le retard
                       -- deviendrait un silence.
                       OR m.captured_at < now() - ($7 * interval '1 second')
                     ))
                  )
              AND ($3::text IS NULL OR i.completed_at >= $3::text::timestamptz)
              -- Une panne d'exécution après acceptation ne rend pas le juge
              -- compétent une seconde fois, même si un ancien run reste error.
              AND NOT EXISTS (
                SELECT 1 FROM verdicts accepted
                WHERE accepted.investigation_id=i.id AND accepted.is_binding
              )
              -- Un run en erreur sans date de fin attend un nouvel essai : à
              -- son échéance planifiée après une panne passagère du modèle,
              -- sinon selon la cadence historique (15 s par essai déjà fait).
              -- La date de fin, posée à l'épuisement, est la seule marque
              -- d'abandon : les dossiers déjà remis à l'humain ne reviennent
              -- jamais ici, quel que soit leur nombre d'essais.
              AND (vr.id IS NULL OR (
                    vr.status='error' AND vr.completed_at IS NULL
                    AND vr.attempts < $4
                    AND coalesce(
                          vr.next_attempt_at,
                          vr.started_at + vr.attempts * interval '15 seconds'
                        ) <= now()
              ))
            ORDER BY i.completed_at, i.id
            FOR UPDATE OF i SKIP LOCKED
            LIMIT 1
        ), upserted AS (
            INSERT INTO verdict_runs (
                investigation_id, engine, model_name, prompt_version,
                status, attempts, started_at, engine_generation
            )
            SELECT id,$1,$5,$2,'running',1,now(),engine_generation FROM candidate
            ON CONFLICT (investigation_id, engine, prompt_version) DO UPDATE SET
                status='running', attempts=verdict_runs.attempts+1,
                model_name=EXCLUDED.model_name, started_at=now(),
                error_type=NULL, error_detail=NULL
            -- Le même prédicat que la sélection : s'il était plus strict, le
            -- candidat serait choisi sans être pris, à chaque passage.
            WHERE verdict_runs.status='error' AND verdict_runs.completed_at IS NULL
              AND verdict_runs.attempts < $4
              AND coalesce(
                    verdict_runs.next_attempt_at,
                    verdict_runs.started_at + verdict_runs.attempts * interval '15 seconds'
                  ) <= now()
            RETURNING *
        )
        SELECT u.*, i.message_id
        FROM upserted u
        JOIN investigations i ON i.id=u.investigation_id
        """,
        ENGINE,
        PROMPT_VERSION,
        settings.verdict_not_before,
        ATTEMPTS_CEILING,
        str(configured_model or settings.deepseek_verdict_model),
        settings.decision_mode,
        settings.analysis_wait_seconds,
    )

async def _verdict_domain(pool: asyncpg.Pool[Any], message_id: object) -> str:
    """Le domaine protégé auquel ce message était adressé."""
    recipients = await pool.fetchval(
        "SELECT envelope_recipients FROM messages WHERE id=$1", message_id
    )
    recipient = await protected_recipient(pool, list(recipients or []))
    return domain_of(recipient) if recipient else ""

async def _reserve_verdict_call(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    run: asyncpg.Record,
    *,
    model_name: str,
    stage: str,
) -> tuple[int | None, str | None]:
    """Réserve un verdict sous deux plafonds : celui du domaine, puis le global.

    Compter globalement seul revenait à faire payer aux uns le courrier des
    autres : un domaine très sollicité épuisait le budget, et les voisins
    voyaient leurs messages retenus sans que rien chez eux ne l'explique. Le
    plafond global reste au-dessus, parce que la dépense totale est commune.
    """
    domain = await _verdict_domain(pool, run["message_id"])
    quota = await quota_of(
        pool,
        domain,
        Quota(
            assistant_hourly=settings.assistant_llm_hourly_limit,
            assistant_daily=settings.assistant_llm_daily_limit,
            verdict_hourly=settings.verdict_llm_hourly_limit,
            verdict_daily=settings.verdict_llm_daily_limit,
        ),
    )
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute(
            "SELECT pg_advisory_xact_lock(hashtext('sentimail-v3-verdict-quota'))"
        )
        counts = await connection.fetchrow(
            """
            SELECT
              count(*) FILTER (WHERE created_at > now()-interval '1 hour') AS hourly,
              count(*) FILTER (WHERE created_at > now()-interval '24 hours') AS daily,
              count(*) FILTER (
                WHERE created_at > now()-interval '1 hour' AND domain_fqdn=$1
              ) AS domain_hourly,
              count(*) FILTER (
                WHERE created_at > now()-interval '24 hours' AND domain_fqdn=$1
              ) AS domain_daily
            FROM verdict_llm_call_events
            WHERE created_at > now()-interval '24 hours'
            """,
            domain,
        )
        if int(counts["hourly"]) >= settings.verdict_llm_hourly_limit:
            return None, "global_hourly"
        if int(counts["daily"]) >= settings.verdict_llm_daily_limit:
            return None, "global_daily"
        if domain and int(counts["domain_hourly"]) >= quota.verdict_hourly:
            return None, "domain_hourly"
        if domain and int(counts["domain_daily"]) >= quota.verdict_daily:
            return None, "domain_daily"
        event_id = await connection.fetchval(
            """
            INSERT INTO verdict_llm_call_events (
                verdict_run_id,message_id,attempt,model_name,domain_fqdn,stage
            ) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id
            """,
            run["id"],
            run["message_id"],
            run["attempts"],
            model_name,
            domain,
            stage,
        )
        return int(event_id), None

async def resume_interrupted_runs(pool: asyncpg.Pool[Any]) -> None:
    """Rend reprenables les essais qu'un arrêt a coupés en plein travail.

    Un run « running » au démarrage n'a ni réussi ni échoué : il repasse en
    erreur sans date de fin. Un essai planifié garde son échéance, déjà
    passée, et repart aussitôt ; un essai planifié encore à venir n'est pas
    touché et attend son heure. Un essai coupé compte comme fait.
    """
    await pool.execute(
        "UPDATE verdict_runs SET status='error' WHERE status='running'"
    )
