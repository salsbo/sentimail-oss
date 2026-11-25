"""Rassembler ce qui s'est passé, et le publier là où l'état se lit déjà.

Le calcul vit dans `evaluation`, qui ne connaît ni base ni réseau. Ici on va
chercher les lignes, on assemble le rapport, et on le pose dans
`operational_status` sous son propre composant - la console d'administration
lit déjà cette table pour la page d'état, et n'a pas le droit d'importer le
collector.

Deux précautions qui tiennent tout le reste.

**L'issue se reconstruit depuis les événements de livraison.** Le champ
`original_delivery_allowed` du dossier est mis à jour après la réponse de
l'utilisateur : il raconte l'état final, pas la décision du moment. Une mesure
bâtie dessus compterait un message retenu puis libéré comme livré d'emblée, et
afficherait un taux de sollicitation nul. Les événements, eux, ne se
réécrivent pas.

**La mesure ne dégrade jamais l'état.** Un taux d'erreur élevé est une
information de qualité, pas une panne : le publier en « degraded » ferait
sonner l'alerte du superviseur pour quelque chose qui n'appelle aucune
intervention immédiate.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg

from sentimail_v3.supervision.evaluation import (
    ASK,
    DELIVER,
    JUNK,
    confusion_matrix,
    generalized_risk,
    hold_precision,
    labelling_coverage,
    lam_percent,
    trec_rates,
    utility_score,
)

COMPONENT = "evaluation"
DEFAULT_WINDOW_DAYS = 30

# Une erreur ou une réponse ne constitue pas une première exécution. Les
# événements d'exécution sont triés, au lieu de privilégier un classement final.
_ROWS_SQL = """
SELECT
  m.delivery_status, dc.id AS case_id, dc.state AS case_state,
  first_execution.event_type AS first_event_type,
  first_execution.created_at AS first_event_at,
  (
    SELECT CASE
             WHEN l.label = 'legitimate' THEN 'legitimate'
             WHEN l.label IN ('spam', 'dangerous', 'suspect') THEN 'spam'
             ELSE 'ambiguous'
           END
    FROM labels l
    WHERE l.message_id = m.id AND l.is_ground_truth AND l.active
    ORDER BY l.created_at DESC, l.id DESC LIMIT 1
  ) AS truth
FROM messages m
LEFT JOIN delivery_cases dc ON dc.message_id = m.id
LEFT JOIN LATERAL (
  SELECT de.event_type, de.created_at
  FROM delivery_events de
  WHERE de.case_id = dc.id
    AND de.event_type IN (
      'original_delivered', 'original_released', 'original_filed_as_junk',
      'review_notice_delivered', 'policy_suppressed'
    )
  ORDER BY de.created_at, de.id LIMIT 1
) first_execution ON true
WHERE m.captured_at >= $1 AND m.captured_at < $2
"""

_EXECUTION_OUTCOMES = {
    "original_delivered": DELIVER,
    "original_released": DELIVER,
    "original_filed_as_junk": JUNK,
    "review_notice_delivered": ASK,
    "policy_suppressed": "suppressed",
}
_EXCLUDED_OUTCOMES = ("suppressed", "undeliverable", "pending", "unconfirmed")


def first_outcome(row: dict[str, Any]) -> str:
    """Une absence de preuve de livraison ne devient jamais une livraison."""
    event = row.get("first_event_type")
    if event in _EXECUTION_OUTCOMES:
        return _EXECUTION_OUTCOMES[event]
    status = row.get("delivery_status")
    if status in ("suppressed", "undeliverable"):
        return str(status)
    if status == "delivered" or row.get("case_state") in ("closed", "ignored"):
        return "unconfirmed"
    return "pending"


def assemble(
    rows: list[dict[str, Any]], *, days: int, start: datetime, end: datetime
) -> dict[str, Any]:
    """Sépare la population captée, les exécutions et la qualité mesurable."""
    protected = [r for r in rows if r.get("delivery_status") != "consumed"]
    outcomes: Counter[str] = Counter()
    residuals: Counter[str] = Counter()
    quality: list[dict[str, Any]] = []
    for row in protected:
        outcome = first_outcome(row)
        outcomes[outcome] += 1
        if outcome in (DELIVER, ASK, JUNK):
            # L'abandon n'est pas une qualification. Un vrai label actif reste
            # utilisable ; son absence reste inconnue, même après l'abandon.
            quality.append({"outcome": outcome, "truth": row.get("truth")})
        if row.get("case_id") is None:
            residuals["missing_case"] += 1
        if row.get("first_event_type") is None:
            residuals["without_execution_event"] += 1
            if row.get("delivery_status") in ("delivered", "suppressed"):
                residuals[f"{row['delivery_status']}_without_event"] += 1
        if outcome == "unconfirmed":
            residuals["unconfirmed"] += 1
    rates = trec_rates(quality)
    return {
        "schema_version": 2,
        "window_days": days,
        "window_start_utc": start.isoformat(),
        "window_end_utc": end.isoformat(),
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "population": {
            "captured": len(rows),
            "consumed_excluded": len(rows) - len(protected),
            "protected": len(protected),
            "quality_evaluated": len(quality),
            "quality_exclusions": {key: outcomes[key] for key in _EXCLUDED_OUTCOMES},
            "ignored": sum(r.get("case_state") == "ignored" for r in protected),
            "ignored_with_notice": sum(
                r.get("case_state") == "ignored" and first_outcome(r) == ASK
                for r in protected
            ),
        },
        "executions": {key: outcomes[key] for key in (DELIVER, ASK, JUNK, *_EXCLUDED_OUTCOMES)},
        "final_statuses": dict(Counter(r.get("delivery_status") for r in protected)),
        "residuals": {key: residuals[key] for key in (
            "missing_case", "without_execution_event", "delivered_without_event",
            "suppressed_without_event", "unconfirmed",
        )},
        "coverage": labelling_coverage(quality),
        "matrix": confusion_matrix(quality),
        "hold_precision": hold_precision(quality),
        "generalized_risk": generalized_risk(quality),
        "trec_rates": rates,
        "lam_optimistic": lam_percent(rates["hm_optimistic"], rates["sm_optimistic"]),
        "lam_pessimistic": lam_percent(rates["hm_pessimistic"], rates["sm_pessimistic"]),
        "utility": utility_score(quality),
    }


async def collect(
    pool: asyncpg.Pool[Any], *, days: int = DEFAULT_WINDOW_DAYS,
    as_of: datetime | None = None,
) -> dict[str, Any]:
    """Le rapport complet : conditions de validité d'abord, taux ensuite."""
    if not isinstance(days, int) or isinstance(days, bool) or days <= 0:
        raise ValueError("la fenêtre doit compter un nombre positif de jours")
    end = as_of or datetime.now(timezone.utc)
    if end.tzinfo is None or end.utcoffset() is None:
        raise ValueError("la borne de mesure doit porter son fuseau horaire")
    end = end.astimezone(timezone.utc)
    start = end - timedelta(days=days)
    rows = [dict(row) for row in await pool.fetch(_ROWS_SQL, start, end)]
    return assemble(rows, days=days, start=start, end=end)


async def publish(
    pool: asyncpg.Pool[Any], *, days: int = DEFAULT_WINDOW_DAYS
) -> dict[str, Any]:
    """Pose le rapport à côté de l'état opérationnel, sans jamais l'altérer."""
    rapport = await collect(pool, days=days)
    await pool.execute(
        """
        INSERT INTO operational_status (component,status,details,observed_at)
        VALUES ($1,'ok',$2::jsonb,now())
        ON CONFLICT (component) DO UPDATE SET
          status='ok', details=EXCLUDED.details, observed_at=now()
        """,
        COMPONENT,
        json.dumps(rapport, ensure_ascii=False, default=str),
    )
    return rapport
