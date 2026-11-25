"""Installer, observer, qualifier ou désactiver le classifieur local."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.judgment.classifier import LLM_QUALIFICATION, MIN_SHADOW, model_id, offline_blockers, validate_artifact
from sentimail_v3.judgment.classifier_runtime import MAX_MODEL_AGE, corpus_fingerprint


async def report(pool: Any) -> dict[str, Any]:
    from sentimail_v3.judgment.verdict_engine import PROMPT_VERSION
    config = await pool.fetchrow("SELECT * FROM classifier_config WHERE singleton=true")
    if not config or not config["model_id"]:
        return {"mode": "off", "model_id": None}
    raw = await pool.fetchval("SELECT artifact FROM classifier_models WHERE model_id=$1", config["model_id"])
    artifact = json.loads(raw) if isinstance(raw, str) else raw
    validate_artifact(artifact)
    routing = await pool.fetchrow("SELECT mode,premium_model_name FROM verdict_model_routing WHERE singleton=true")
    premium = routing["premium_model_name"] if routing and routing["mode"] != "off" else await pool.fetchval(
        "SELECT model_name FROM llm_role_providers WHERE role='verdict'")
    observations = await pool.fetchrow("""SELECT
        count(*) AS total,
        count(DISTINCT split_group_hash) FILTER (WHERE eligible) AS eligible_groups,
        count(*) FILTER (WHERE unsafe) AS unsafe
        FROM classifier_observations o JOIN verdict_runs r ON r.id=o.verdict_run_id
        WHERE o.model_id=$1 AND o.reference_model=$2 AND o.reference_prompt=$3
        AND o.created_at > now()-interval '30 days' AND r.status='complete'""",
        config["model_id"], premium, PROMPT_VERSION)
    blockers = offline_blockers(artifact)
    if model_id(artifact) != config["model_id"]:
        blockers.append("empreinte du modèle incorrecte")
    if datetime.now(timezone.utc) - datetime.fromisoformat(artifact["trained_at"]) > MAX_MODEL_AGE:
        blockers.append("modèle périmé")
    if artifact.get("corpus_sha256") != await corpus_fingerprint(pool):
        blockers.append("corpus normatif modifié ou non identifié")
    if artifact.get("qualification") != LLM_QUALIFICATION and observations["eligible_groups"] < MIN_SHADOW:
        blockers.append(f"moins de {MIN_SHADOW} groupes éligibles comparés au juge de référence")
    if observations["unsafe"]:
        blockers.append("divergence de livraison avec le juge de référence")
    return {"mode": config["mode"], "model_id": config["model_id"],
            "qualification": artifact.get("qualification", "expert"),
            "trained_at": artifact.get("trained_at"), "threshold": artifact.get("threshold"),
            "reference_model": premium, "shadow": dict(observations),
            "training": artifact.get("training"), "evaluation": artifact.get("evaluation"),
            "enforcement_blockers": blockers}


async def configure(pool: Any, *, artifact: dict[str, Any] | None = None,
                    mode: str | None = None, expected: tuple[str | None, str] | None = None,
                    automated: bool = False) -> dict[str, Any]:
    if mode not in {None, "off", "shadow", "enforced"}:
        raise ValueError("mode inconnu")
    if artifact is not None:
        validate_artifact(artifact)
        if len(json.dumps(artifact)) > 2_000_000:
            raise ValueError("modèle trop volumineux")
        if mode == "enforced":
            raise ValueError("un nouveau modèle commence toujours en observation")
        mode = "shadow"
    async with pool.acquire() as connection, connection.transaction():
        locked = await connection.fetchrow("SELECT * FROM classifier_config WHERE singleton=true FOR UPDATE")
        if expected is not None and (locked["model_id"], locked["mode"]) != expected:
            raise ValueError("configuration modifiée pendant la qualification")
        if automated:
            automation = await connection.fetchrow("SELECT * FROM classifier_automation WHERE singleton=true FOR UPDATE")
            if not automation["enabled"] or not automation["auto_activate"]:
                raise ValueError("activation automatique désactivée")
        if artifact is not None:
            identifier = model_id(artifact)
            await connection.execute("INSERT INTO classifier_models(model_id,artifact) VALUES ($1,$2::jsonb) "
                                     "ON CONFLICT (model_id) DO NOTHING", identifier, json.dumps(artifact, allow_nan=False))
            await connection.execute("UPDATE classifier_config SET model_id=$1 WHERE singleton=true", identifier)
        if mode == "enforced":
            state = await report(connection)
            if not state.get("model_id") or state.get("enforcement_blockers"):
                raise ValueError("activation refusée : " + "; ".join(state.get("enforcement_blockers", ["aucun modèle"])))
        if mode:
            await connection.execute("UPDATE classifier_config SET mode=$1,updated_at=now() WHERE singleton=true", mode)
            await connection.execute("INSERT INTO audit_log(actor,action,payload) "
                                     "VALUES ($1,'classifier.configured',$2::jsonb)",
                                     "classifier_cycle" if automated else "operator",
                                     json.dumps({"mode": mode, "model_id": model_id(artifact) if artifact else None}))
    return await report(pool)


async def main_async() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument("--install", type=Path, help="installe un JSON en mode observation")
    commands.add_argument("--status", action="store_true")
    commands.add_argument("--off", action="store_true")
    commands.add_argument("--shadow", action="store_true")
    commands.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    artifact = json.loads(args.install.read_text(encoding="utf-8")) if args.install else None
    mode = "off" if args.off else "shadow" if args.shadow else "enforced" if args.enforce else None
    pool = await asyncpg.create_pool(load_settings().database_url, min_size=1, max_size=2)
    try:
        result = await configure(pool, artifact=artifact, mode=mode) if artifact or mode else await report(pool)
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main_async())
