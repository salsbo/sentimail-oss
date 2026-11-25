"""Cycle CPU borné : corrections SMTP, candidat versionné, test indépendant."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.judgment.classifier import LLM_QUALIFICATION, model_id, number, offline_blockers, predict
from sentimail_v3.judgment.classifier_runtime import corpus_fingerprint
from sentimail_v3.supervision.adjudication import adjudicate
from sentimail_v3.supervision.classifier import configure, report
from sentimail_v3.supervision.classifier_corpus import export
from sentimail_v3.supervision.classifier_training import expert_label, load_corpus
from sentimail_v3.supervision.training import fingerprint

LOCK_ID = 9045090


async def apply_reviews(pool: Any) -> int:
    completed = 0
    for _ in range(100):
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow("""SELECT * FROM classifier_review_queue
                WHERE status='submitted' ORDER BY submitted_at,id LIMIT 1 FOR UPDATE SKIP LOCKED""")
            if row is None:
                break
            _, label_id = await adjudicate(connection, sample_id=row["sample_id"],
                label=row["label"], reason_code=row["reason_code"], operator=row["operator"])
            await connection.execute("""UPDATE classifier_review_queue
                SET status='done',completed_at=now(),label_id=$2 WHERE id=$1""", row["id"], label_id)
            completed += 1
    return completed


async def review_queue(pool: Any, directory: Path, artifact: dict[str, Any]) -> int:
    corpus = load_corpus(directory)
    experts = {r["group"] for part in ("train", "valid", "test") for r in corpus[part]
               if expert_label(r) is not None}
    available = {int(r["id"]) for r in await pool.fetch("""SELECT t.id FROM training_samples t
        JOIN messages m ON m.id=t.message_id WHERE coalesce(m.body_text,'')<>'' OR coalesce(m.body_html,'')<>''
        OR EXISTS(SELECT 1 FROM external_analyses e WHERE e.message_id=m.id
                  AND coalesce(e.result->>'extracted_text','')<>'')""")}
    choices = {}
    for part, rows in corpus.items():
        for row in rows:
            if row["group"] in experts or row["sample_id"] not in available:
                continue
            choices[row["group"]] = row
    from sentimail_v3.supervision.dataset import split_of
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute("DELETE FROM classifier_review_queue WHERE status='queued' AND group_hash=ANY($1::text[])", list(experts))
        for group, row in choices.items():
            try:
                eligible = predict(artifact, row["dossier"])["eligible"]
            except (ValueError, TypeError, KeyError):
                continue
            await connection.execute("""INSERT INTO classifier_review_queue
                (sample_id,group_hash,partition,eligible) VALUES ($1,$2,$3,$4)
                ON CONFLICT(group_hash) DO UPDATE SET sample_id=EXCLUDED.sample_id,
                    partition=EXCLUDED.partition,eligible=EXCLUDED.eligible
                WHERE classifier_review_queue.status='queued'""",
                row["sample_id"], group, split_of(group), eligible)
    return len(choices)


async def advance(pool: Any, artifact: dict[str, Any], *, auto_activate: bool) -> dict[str, Any]:
    """Promeut les candidats corrigés avec contrôle du contrat et arrêt opérateur."""
    current = await report(pool)
    if not auto_activate:
        return current
    # Un arrêt explicite n'est jamais annulé par l'entretien.
    if current.get("mode") == "off":
        return current
    # Le contrat LLM permet de promouvoir un nouveau candidat corrigé, après
    # son test indépendant. Le verrou CAS respecte toujours l'arrêt opérateur.
    if (artifact.get("qualification") == LLM_QUALIFICATION
            and model_id(artifact) != current.get("model_id") and not offline_blockers(artifact)):
        installed = await configure(pool, artifact=artifact, automated=True,
                                    expected=(current["model_id"], current["mode"]))
        if not installed.get("enforcement_blockers"):
            return await configure(pool, mode="enforced", automated=True,
                                   expected=(installed["model_id"], "shadow"))
        return installed
    if current.get("mode") == "enforced":
        return current
    if not current.get("enforcement_blockers"):
        return await configure(pool, mode="enforced", automated=True,
                               expected=(current["model_id"], current["mode"]))
    active_raw = await pool.fetchval("SELECT artifact FROM classifier_models WHERE model_id=$1", current.get("model_id"))
    active = json.loads(active_raw) if isinstance(active_raw, str) else active_raw
    # Le modèle déjà qualifié hors ligne garde son identité et ses observations.
    # Un candidat différent recommence toujours par shadow, jamais par enforced.
    obsolete = any(reason in current["enforcement_blockers"] for reason in (
        "modèle périmé", "corpus normatif modifié ou non identifié", "empreinte du modèle incorrecte"))
    if (offline_blockers(active or {}) or obsolete) and not offline_blockers(artifact):
        return await configure(pool, artifact=artifact, automated=True,
                               expected=(current["model_id"], current["mode"]))
    return current


async def run_once(pool: Any, *, force: bool = False) -> dict[str, Any]:
    async with pool.acquire() as lock:
        if not await lock.fetchval("SELECT pg_try_advisory_lock($1)", LOCK_ID):
            return {"status": "busy"}
        try:
            config = await pool.fetchrow("SELECT * FROM classifier_automation WHERE singleton=true")
            if not config["enabled"]:
                return {"status": "disabled"}
            reviewed = await apply_reviews(pool)
            # Une correction A/B active ou retirée change cette empreinte,
            # indépendamment de la revue facultative dans l'admin.
            feedback_revision = await pool.fetchval("""SELECT md5(coalesce(jsonb_agg(
                jsonb_build_array(id,label,source) ORDER BY id)::text,'[]'))
                FROM labels WHERE active AND is_ground_truth""")
            previous = json.loads(config["report"]) if isinstance(config["report"], str) else config["report"]
            corrected = (previous or {}).get("feedback_revision") != feedback_revision
            # Le dernier candidat, même refusé, doit avoir été évalué sur le
            # Code actuel. Comparer au seul modèle actif relancerait sans fin
            # un candidat insuffisant ; attendre 24 h laisse le repli en panne.
            candidate_corpus = await pool.fetchval(
                "SELECT artifact->>'corpus_sha256' FROM classifier_models WHERE model_id=$1",
                config["candidate_model_id"])
            corpus_changed = candidate_corpus != await corpus_fingerprint(pool)
            due = force or reviewed or corrected or corpus_changed or not config["last_completed_at"] or (
                datetime.now(timezone.utc) - config["last_completed_at"] >= timedelta(hours=24))
            if not due:
                if config["candidate_model_id"]:
                    raw = await pool.fetchval("SELECT artifact FROM classifier_models WHERE model_id=$1", config["candidate_model_id"])
                    await advance(pool, json.loads(raw) if isinstance(raw, str) else raw,
                                  auto_activate=config["auto_activate"])
                return {"status": "not_due"}
            await pool.execute("UPDATE classifier_automation SET status='running',last_started_at=now() WHERE singleton=true")
            with tempfile.TemporaryDirectory(prefix="sentimail-classifier-") as temporary:
                directory = Path(temporary)
                manifest = await export(pool, directory)
                threshold_raw = await pool.fetchval("""SELECT m.artifact->>'threshold'
                    FROM classifier_config c JOIN classifier_models m USING(model_id) WHERE c.singleton=true""")
                threshold = max(.995, number(float(threshold_raw or .995), .95, .99999))
                # Un seuil opérateur plus prudent ne doit pas être abaissé
                # par le prochain entraînement automatique.
                manifest["threshold"] = threshold
                manifest["qualification"] = LLM_QUALIFICATION
                dataset = fingerprint(manifest)
                if dataset == config["dataset_id"] and config["candidate_model_id"]:
                    raw = await pool.fetchval("SELECT artifact FROM classifier_models WHERE model_id=$1", config["candidate_model_id"])
                    artifact = json.loads(raw) if isinstance(raw, str) else raw
                    trained = False
                else:
                    # Travail CPU dans un processus séparé : un entraînement
                    # bloqué peut être tué sans immobiliser le caretaker.
                    import sys
                    process = await asyncio.create_subprocess_exec(sys.executable, "-m",
                        "sentimail_v3.supervision.classifier_training", str(directory),
                        str(directory / "model.json"), "--threshold", str(threshold), "--qualification", LLM_QUALIFICATION, stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL)
                    try:
                        await asyncio.wait_for(process.wait(), timeout=300)
                    except BaseException:
                        process.kill()
                        await process.wait()
                        raise
                    if process.returncode:
                        raise RuntimeError("échec de l'entraînement CPU")
                    artifact = json.loads((directory / "model.json").read_text())
                    trained = True
                identifier = model_id(artifact)
                await pool.execute("INSERT INTO classifier_models(model_id,artifact) VALUES ($1,$2::jsonb) ON CONFLICT DO NOTHING",
                                   identifier, json.dumps(artifact, allow_nan=False))
                queued = await review_queue(pool, directory, artifact)
            active = await advance(pool, artifact, auto_activate=config["auto_activate"])
            result = {"feedback_revision": feedback_revision, "qualification": artifact.get("qualification"), "trained": trained, "reviews_applied": reviewed, "review_groups": queued,
                "candidate_model_id": identifier, "candidate_blockers": offline_blockers(artifact),
                "training": artifact["training"], "evaluation": artifact["evaluation"],
                "exclusions": manifest["exclusions"], "source_quality": manifest["source_quality"],
                "active_model_id": active.get("model_id"), "mode": active.get("mode")}
            async with pool.acquire() as connection, connection.transaction():
                await connection.execute("""UPDATE classifier_automation SET status='ok',last_completed_at=now(),
                    dataset_id=$1,candidate_model_id=$2,report=$3::jsonb WHERE singleton=true""",
                    dataset, identifier, json.dumps(result))
                await connection.execute("INSERT INTO audit_log(actor,action,payload) VALUES ('classifier_cycle','classifier.cycle_completed',$1::jsonb)", json.dumps(result))
            return result
        except Exception as exc:
            await pool.execute("UPDATE classifier_automation SET status='error',report=jsonb_build_object('error',$1::text) WHERE singleton=true", type(exc).__name__)
            raise
        finally:
            await lock.execute("SELECT pg_advisory_unlock($1)", LOCK_ID)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    pool = await asyncpg.create_pool(load_settings().database_url, min_size=1, max_size=2)
    try:
        print(json.dumps(await run_once(pool, force=args.force), ensure_ascii=False, default=str))
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
