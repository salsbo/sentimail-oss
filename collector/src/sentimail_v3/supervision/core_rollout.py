"""Bascule explicite des nouvelles captures, sans seconde autorité de livraison."""

from __future__ import annotations

import asyncio
import argparse
import hashlib
import json
import re
from typing import Any
from uuid import UUID

from sentimail_v3.judgment.classifier_runtime import corpus_fingerprint
from sentimail_v3.observation.observation_cache import package_fingerprint

GENERATION = "core-v1"
CORE_VERSION = "sentimail-core-1"
SUITE_VERSION = "sentimail-core-equivalence-1"
ORACLE_REVISION = "b07a5ec052cd995ecb861b43bfd05f555df08635"
REQUIRED_COVERAGE = frozenset({
    "legitimate", "spam", "suspect", "dangerous", "undetermined",
    "material_danger", "authenticated_hold", "static_incomplete", "deep_incomplete",
    "identity_destination_conflict", "otp", "policy_b", "real_doubt", "retry",
    "invalid_response", "invalid_reference", "low_confidence",
})
_CONTEXT_FIELDS = ("core_version", "oracle_revision", "suite_version", "package_sha256", "corpus_sha256")


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode()).hexdigest()


async def qualification_context(executor: Any) -> dict[str, str]:
    editions = await executor.fetch("SELECT id::text,status,version FROM code_editions ORDER BY id")
    return {"core_version": CORE_VERSION, "oracle_revision": ORACLE_REVISION,
            "suite_version": SUITE_VERSION, "package_sha256": package_fingerprint(),
            "corpus_sha256": _hash({"articles": await corpus_fingerprint(executor),
                                    "editions": [dict(r) for r in editions]})}


async def required_coverage(executor: Any) -> frozenset[str]:
    """Le passage de chaque article actif complète les scénarios de décision.

    Ce passage prouve la lecture de l'article et de ses paramètres dans le
    dossier, sans prétendre exercer un détecteur non associé à cet article.
    """
    articles = await executor.fetch("""SELECT DISTINCT a.article_code FROM code_articles a
        JOIN code_editions e ON e.id=a.edition_id WHERE a.enabled AND e.status='active'""")
    return REQUIRED_COVERAGE | {"article:"+row["article_code"] for row in articles}


async def record_comparison(
    pool: Any, *, dossier: Any, proposed_response: Any, legacy: dict, candidate: dict,
    message_id: str | None = None, coverage=(), source: str = "shadow", error_type: str | None = None,
    exclusion_reason: str | None = None,
) -> dict[str, Any] | None:
    """Un seul dossier et une seule réponse, deux résultats purs, aucune action SMTP."""
    context = {"core_version": CORE_VERSION, "oracle_revision": ORACLE_REVISION,
               "suite_version": SUITE_VERSION, "package_sha256": package_fingerprint(),
               "corpus_sha256": None}
    try:
        if source not in {"offline", "shadow"}:
            raise ValueError("source de comparaison inconnue")
        if not isinstance(legacy, dict) or not isinstance(candidate, dict):
            raise ValueError("deux résultats logiques sont requis")
        if exclusion_reason is not None:
            error_type = exclusion_reason
        if error_type is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", error_type):
            error_type = "ComparisonError"
        context = await asyncio.wait_for(qualification_context(pool), timeout=3)
        old_hash, new_hash = _hash(legacy), _hash(candidate)
        status = "excluded" if exclusion_reason else "error" if error_type else "complete"
        async with asyncio.timeout(3):
            identifier = await pool.fetchval("""INSERT INTO core_rollout_comparisons(
              message_id,source,core_version,oracle_revision,suite_version,package_sha256,corpus_sha256,
              dossier_sha256,response_sha256,legacy_sha256,candidate_sha256,agreement,status,error_type,coverage)
              VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::text[]) RETURNING id""",
              message_id,source,*(context[k] for k in _CONTEXT_FIELDS),_hash(dossier),_hash(proposed_response),
              old_hash,new_hash,old_hash == new_hash and not error_type,status,error_type,
              sorted({label for label in coverage if isinstance(label,str) and
                  (label in REQUIRED_COVERAGE or re.fullmatch(r"article:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",label))})
              if status == "complete" else [])
        return {"id": identifier, "agreement": old_hash == new_hash and not error_type,
                "status": status, "context": context}
    except Exception as exc:
        # Un audit perdu ne ressemble jamais à une absence de divergence.
        # Si la base ne peut même pas tracer l'échec, l'appelant reçoit cette
        # panne : il ne peut de toute façon pas y accepter un verdict durable.
        async with asyncio.timeout(3):
            await pool.execute("""INSERT INTO audit_log(actor,action,payload)
                VALUES('core_rollout','core.comparison_failed',$1::jsonb)""",
                json.dumps({"context": context, "error_type": type(exc).__name__}))
        return None


async def _comparison_summary(executor: Any, context: dict[str, str], *, source: str = "offline") -> dict[str, Any]:
    rows = await executor.fetch("""SELECT dossier_sha256,response_sha256,legacy_sha256,
      candidate_sha256,agreement,status,coverage FROM core_rollout_comparisons
      WHERE source=$6 AND core_version=$1 AND oracle_revision=$2 AND suite_version=$3
        AND package_sha256=$4 AND corpus_sha256=$5
      ORDER BY dossier_sha256,response_sha256,legacy_sha256,candidate_sha256,status,coverage,agreement""",
      *(context[k] for k in _CONTEXT_FIELDS),source)
    cases: dict[tuple, list[dict]] = {}
    excluded = set()
    for row in rows:
        value = dict(row)
        case = (value["dossier_sha256"], value["response_sha256"])
        if value["status"] == "excluded":
            excluded.add(case)
        else:
            cases.setdefault(case, []).append(value)
    errors = sum(any(v["status"] != "complete" for v in values) for values in cases.values())
    mismatches = sum(any(v["status"] == "complete" and not v["agreement"] for v in values) for values in cases.values())
    required = await required_coverage(executor)
    coverage = _independent_coverage(cases, required=required)
    return {"cases": len(cases), "errors": errors, "mismatches": mismatches,
            "excluded": len(excluded), "coverage": coverage, "required_coverage": sorted(required),
            "comparison_set_sha256": _hash([dict(r) for r in rows])}


def _independent_coverage(cases: dict[tuple, list[dict]], required=None) -> list[str]:
    """Chaque scénario exigé doit disposer d'une paire d'entrées distincte."""
    required = REQUIRED_COVERAGE if required is None else frozenset(required)
    possibilities = {label: [] for label in required}
    for case, rows in sorted(cases.items()):
        if not all(r["status"] == "complete" and r["agreement"] for r in rows):
            continue
        for label in set().union(*(set(r["coverage"] or []) for r in rows))&required:
            possibilities[label].append(case)
    matched: dict[tuple,str] = {}
    def assign(label: str, seen: set[tuple]) -> bool:
        for case in possibilities[label]:
            if case in seen:
                continue
            seen.add(case)
            if case not in matched or assign(matched[case], seen):
                matched[case] = label
                return True
        return False
    for label in sorted(required):
        assign(label, set())
    return sorted(matched.values())


def _blockers(report: dict[str, Any] | None) -> list[str]:
    if not report:
        return ["qualification absente"]
    blockers = []
    if report.get("status") != "complete": blockers.append("qualification incomplète")
    if not report.get("cases"): blockers.append("aucun cas comparé")
    if report.get("mismatches"): blockers.append("divergence logique")
    if report.get("errors"): blockers.append("comparaison en erreur")
    if set(report.get("required_coverage",REQUIRED_COVERAGE))-set(report.get("coverage") or []):
        blockers.append("couverture insuffisante")
    return blockers


async def publish_qualification(pool: Any, *, case_set_sha256: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", case_set_sha256):
        raise ValueError("empreinte du jeu de cas invalide")
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute("LOCK TABLE code_articles,code_editions,core_rollout_comparisons IN SHARE MODE")
        context = await qualification_context(connection)
        summary = await _comparison_summary(connection, context)
        boundary = await _comparison_boundary(connection, context)
        summary["status"] = "complete" if not _blockers({**summary,"status":"complete"}) else "incomplete"
        identifier = await connection.fetchval("""INSERT INTO core_rollout_qualifications(
          core_version,oracle_revision,suite_version,package_sha256,corpus_sha256,case_set_sha256,
          comparison_set_sha256,cases,mismatches,errors,excluded,coverage,status,
          comparison_rows,comparison_last_id)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::text[],$13,$14,$15) RETURNING id""",
          *(context[k] for k in _CONTEXT_FIELDS),case_set_sha256,summary["comparison_set_sha256"],
          summary["cases"],summary["mismatches"],summary["errors"],summary["excluded"],summary["coverage"],summary["status"],
          boundary["rows"],boundary["last_id"])
        return {"id": identifier, **context, **summary}


async def _comparison_boundary(executor: Any, context: dict[str, str]) -> Any:
    return await executor.fetchrow("""SELECT count(*) AS rows,coalesce(max(id),0) AS last_id
        FROM core_rollout_comparisons WHERE source='offline'
          AND core_version=$1 AND oracle_revision=$2 AND suite_version=$3
          AND package_sha256=$4 AND corpus_sha256=$5""", *(context[k] for k in _CONTEXT_FIELDS))


async def _capture_qualified(connection: Any, qualification_id: int) -> bool:
    """Relit des métadonnées bornées ; les preuves publiées sont immuables en SQL.

    La configuration fait toujours la relecture et le hachage complets. Lors du
    SMTP, la frontière détecte tout nouvel ajout hors ligne, et EXISTS arrête au
    premier désaccord ou échec. Aucun dossier historique ne remonte en Python.
    """
    context = await qualification_context(connection)
    row = await connection.fetchrow("""SELECT * FROM core_rollout_qualifications
        WHERE id=$6 AND core_version=$1 AND oracle_revision=$2 AND suite_version=$3
          AND package_sha256=$4 AND corpus_sha256=$5""",
        *(context[k] for k in _CONTEXT_FIELDS),qualification_id)
    if not row or _blockers({**dict(row), "required_coverage": await required_coverage(connection)}):
        return False
    boundary = await _comparison_boundary(connection, context)
    if (row["comparison_rows"],row["comparison_last_id"]) != (boundary["rows"],boundary["last_id"]):
        return False
    failed = await connection.fetchval("""SELECT EXISTS (
        SELECT 1 FROM core_rollout_comparisons WHERE source='shadow'
          AND core_version=$1 AND oracle_revision=$2 AND suite_version=$3
          AND package_sha256=$4 AND corpus_sha256=$5
          AND (status='error' OR (status='complete' AND NOT agreement))
        ) OR EXISTS (
        SELECT 1 FROM audit_log WHERE action='core.comparison_failed'
          AND payload#>>'{context,core_version}'=$1 AND payload#>>'{context,oracle_revision}'=$2
          AND payload#>>'{context,suite_version}'=$3 AND payload#>>'{context,package_sha256}'=$4
          AND (payload#>>'{context,corpus_sha256}' IS NULL OR payload#>>'{context,corpus_sha256}'=$5)
        )""", *(context[k] for k in _CONTEXT_FIELDS))
    return not failed


async def activation_status(executor: Any, *, qualification_id: int | None = None) -> dict[str, Any]:
    context = await qualification_context(executor)
    report = await executor.fetchrow("""SELECT * FROM core_rollout_qualifications
      WHERE core_version=$1 AND oracle_revision=$2 AND suite_version=$3
        AND package_sha256=$4 AND corpus_sha256=$5 AND ($6::bigint IS NULL OR id=$6)
      ORDER BY id DESC LIMIT 1""", *(context[k] for k in _CONTEXT_FIELDS),qualification_id)
    value = dict(report) if report else None
    offline = await _comparison_summary(executor, context)
    if value:
        value["required_coverage"] = offline["required_coverage"]
    blockers = _blockers(value)
    if value and value["comparison_set_sha256"] != offline["comparison_set_sha256"]:
        blockers.append("comparaisons modifiées depuis qualification")
    if value and any(value[key] != offline[key] for key in ("cases","mismatches","errors","excluded","coverage")):
        blockers.append("rapport incohérent avec les comparaisons")
    if value and _blockers({**offline,"status":"complete"}):
        blockers.append("preuves courantes insuffisantes")
    shadow = await _comparison_summary(executor, context, source="shadow")
    if shadow["mismatches"]: blockers.append("divergence observée en ombre")
    if shadow["errors"]: blockers.append("comparaison en ombre en erreur")
    audit_failures = await executor.fetchval("""SELECT count(*) FROM audit_log
      WHERE action='core.comparison_failed'
        AND payload#>>'{context,core_version}'=$1 AND payload#>>'{context,oracle_revision}'=$2
        AND payload#>>'{context,suite_version}'=$3 AND payload#>>'{context,package_sha256}'=$4
        AND (payload#>>'{context,corpus_sha256}' IS NULL OR payload#>>'{context,corpus_sha256}'=$5)""",
        *(context[k] for k in _CONTEXT_FIELDS))
    if audit_failures:
        blockers.append("échec d'audit de comparaison pour ce contexte")
    return {"eligible": not blockers, "blockers": blockers, "context": context, "qualification": value,
            "offline": offline, "shadow": shadow, "audit_failures": audit_failures}


async def configure_rollout(pool: Any, mode: str, *, canary_percent: int = 0) -> dict[str, Any]:
    if mode not in {"legacy", "shadow", "canary", "active"}:
        raise ValueError("mode de bascule inconnu")
    if not isinstance(canary_percent,int) or isinstance(canary_percent,bool) or not 0<=canary_percent<=100:
        raise ValueError("pourcentage canari hors limites")
    async with pool.acquire() as connection, connection.transaction():
        config = await connection.fetchrow("SELECT * FROM core_rollout_config WHERE singleton FOR UPDATE")
        if config is None:
            raise ValueError("configuration de bascule absente")
        qualification_id = None
        if mode in {"canary","active"}:
            await connection.execute("LOCK TABLE code_articles,code_editions,core_rollout_comparisons IN SHARE MODE")
            report = await activation_status(connection)
            if not report["eligible"]:
                raise ValueError("activation refusée : "+", ".join(report["blockers"]))
            qualification_id = report["qualification"]["id"]
        row = await connection.fetchrow("""UPDATE core_rollout_config SET mode=$1,
          canary_percent=$2,qualification_id=$3,updated_at=now() WHERE singleton RETURNING *""",
          mode,100 if mode == "active" else canary_percent if mode == "canary" else 0,qualification_id)
        return dict(row)


def choose_generation(config: dict[str, Any], message_id: str, *, qualified: bool) -> str:
    if not qualified or config.get("mode") not in {"canary","active"}:
        return "legacy"
    bucket = int(hashlib.sha256(str(UUID(str(message_id))).encode()).hexdigest()[:8],16)%10000
    return GENERATION if config["mode"] == "active" or bucket<int(config.get("canary_percent",0))*100 else "legacy"


async def generation_for_capture(connection: Any, message_id: str) -> str:
    """À appeler dans la transaction de nouvelle capture, sous savepoint appelant."""
    config = await connection.fetchrow("SELECT * FROM core_rollout_config WHERE singleton FOR SHARE")
    if not config or config["mode"] in {"legacy","shadow"}:
        return "legacy"
    if config["qualification_id"] is None:
        return "legacy"
    qualified = await _capture_qualified(connection, config["qualification_id"])
    return choose_generation(dict(config),message_id,qualified=qualified)


async def _cli(options: argparse.Namespace) -> dict[str, Any]:
    import asyncpg
    from sentimail_v3.config import load_settings
    pool = await asyncpg.create_pool(load_settings().database_url, min_size=1, max_size=2)
    try:
        if options.status:
            config = dict(await pool.fetchrow("SELECT * FROM core_rollout_config WHERE singleton"))
        else:
            mode = "legacy" if options.legacy else "shadow" if options.shadow else "canary" if options.canary is not None else "active"
            config = await configure_rollout(pool, mode, canary_percent=options.canary or 0)
        report = await activation_status(pool)
        generations = [dict(r) for r in await pool.fetch("""SELECT engine_generation,count(*) AS messages,
            count(*) FILTER (WHERE delivery_status IN ('captured','analyzing','held','deferred','release_pending')
              AND NOT (delivery_status='held' AND EXISTS (SELECT 1 FROM delivery_cases dc
                WHERE dc.message_id=m.id AND dc.state='ignored'))) AS open
            FROM messages m GROUP BY engine_generation ORDER BY engine_generation""")]
        runs = [dict(r) for r in await pool.fetch("""SELECT engine_generation,status,count(*) AS runs
            FROM verdict_runs WHERE completed_at IS NULL AND status IN ('pending','running','error')
            GROUP BY engine_generation,status ORDER BY engine_generation,status""")]
        from sentimail_v3.judgment.claims import ENGINE
        from sentimail_v3.judgment.prompt import PROMPT_VERSION
        from sentimail_v3.judgment.verdict_retry import ATTEMPTS_CEILING
        from sentimail_v3.supervision.core_health import DRAIN_SQL
        drain = await pool.fetchrow(DRAIN_SQL, ENGINE, PROMPT_VERSION, ATTEMPTS_CEILING)
        remaining = int(drain["legacy_runs_inflight"]) + int(drain["legacy_unclaimed"])
        return {"config": config, "qualification": report, "generations": generations,
                "historical_unfinished_runs": runs, "legacy_engine_jobs_remaining": int(remaining),
                "legacy_drain_complete": remaining == 0}
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Qualifier et basculer les nouvelles captures SentiMail")
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ("status","shadow","legacy","active"):
        group.add_argument("--"+mode, action="store_true")
    group.add_argument("--canary", type=int, metavar="PCT")
    options = parser.parse_args()
    print(json.dumps(asyncio.run(_cli(options)), ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
