"""Surveille la bascule du cœur et le travail restant, sans lire les courriers."""

from __future__ import annotations

import asyncio
from typing import Any

from sentimail_v3.judgment.claims import ENGINE
from sentimail_v3.judgment.prompt import PROMPT_VERSION
from sentimail_v3.judgment.verdict_retry import ATTEMPTS_CEILING
from sentimail_v3.supervision import core_rollout

TIMEOUT_SECONDS = 5
COUNTERS = (
    "core_qualification_lost", "core_comparison_mismatches",
    "core_comparison_errors", "core_health_unavailable",
)

# Le drainage concerne ce qui peut encore être pris par le worker courant.
# Les erreurs historiques rattachées à du courrier déjà livré ou retenu ne
# sont pas une file de travail ; les compter empêcherait toute fin de bascule.
DRAIN_SQL = """
    SELECT
      count(*) FILTER (WHERE vr.id IS NOT NULL) AS legacy_runs_inflight,
      count(*) FILTER (WHERE vr.id IS NULL) AS legacy_unclaimed
    FROM messages m JOIN investigations i ON i.message_id=m.id
    LEFT JOIN verdict_runs vr ON vr.investigation_id=i.id
      AND vr.engine=$1 AND vr.prompt_version=$2
    WHERE m.engine_generation='legacy'
      AND m.delivery_status IN ('captured','analyzing')
      AND NOT EXISTS (SELECT 1 FROM verdicts accepted
        WHERE accepted.investigation_id=i.id AND accepted.is_binding)
      AND (vr.id IS NULL OR (
        vr.completed_at IS NULL AND (
          vr.status='running' OR (vr.status='error' AND vr.attempts<$3)
        )
      ))
"""


def _comparison_counts(value: dict[str, Any]) -> dict[str, int]:
    return {key: int(value.get(key) or 0) for key in ("cases", "mismatches", "errors", "excluded")}


async def _read(pool: Any, result: dict[str, Any]) -> None:
    config = await pool.fetchrow("SELECT mode,canary_percent,qualification_id FROM core_rollout_config WHERE singleton")
    if config is None:
        raise RuntimeError("configuration de bascule absente")
    mode = str(config["mode"])
    if mode not in {"legacy", "shadow", "canary", "active"}:
        raise ValueError("mode de bascule inconnu")
    result.update(mode=mode, canary_percent=int(config["canary_percent"] or 0))
    report = await core_rollout.activation_status(pool, qualification_id=config["qualification_id"])
    qualified = bool(report["eligible"])
    blockers = list(report["blockers"])
    # Une preuve récente ne remplace pas le rapport effectivement attaché à
    # une configuration active ; l'absence de cette liaison reste visible.
    if mode in {"canary", "active"} and config["qualification_id"] is None:
        qualified = False
        blockers.append("qualification non rattachée à la configuration")
    result.update(
        qualified=qualified,
        qualified_generation=core_rollout.GENERATION if qualified else None,
        configured_qualification_id=config["qualification_id"],
        qualification_id=(report.get("qualification") or {}).get("id"),
        blockers=blockers,
        offline=_comparison_counts(report["offline"]),
        shadow=_comparison_counts(report["shadow"]),
        audit_failures=int(report.get("audit_failures") or 0),
    )
    counters = result["counters"]
    counters["core_qualification_lost"] = int(mode in {"canary", "active"} and not qualified)
    counters["core_comparison_mismatches"] = result["offline"]["mismatches"] + result["shadow"]["mismatches"]
    counters["core_comparison_errors"] = result["offline"]["errors"] + result["shadow"]["errors"] + result["audit_failures"]
    drain = await pool.fetchrow(DRAIN_SQL, ENGINE, PROMPT_VERSION, ATTEMPTS_CEILING)
    result["legacy_runs_inflight"] = int(drain["legacy_runs_inflight"])
    result["legacy_unclaimed"] = int(drain["legacy_unclaimed"])
    result["legacy_inflight"] = result["legacy_runs_inflight"] + result["legacy_unclaimed"]


async def snapshot(pool: Any) -> dict[str, Any]:
    """Un échec de lecture dégrade le contrôle, sans bloquer les autres sondes."""
    result: dict[str, Any] = {"generation": core_rollout.GENERATION,
                              "counters": dict.fromkeys(COUNTERS, 0)}
    try:
        async with asyncio.timeout(TIMEOUT_SECONDS):
            await _read(pool, result)
    except Exception as exc:
        result["error"] = type(exc).__name__
        result["counters"]["core_health_unavailable"] = 1
    result["status"] = "degraded" if any(result["counters"].values()) else "ok"
    return result
