"""Poser une qualification expertisée sur un échantillon désensibilisé."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings

LABELS = ("legitimate", "spam", "suspect", "dangerous")
REASONS = (
    "confirmed_legitimate",
    "confirmed_spam",
    "confirmed_phishing",
    "insufficient_evidence",
    "corrected_user_preference",
    "other",
)


async def adjudicate(
    connection: Any,
    *,
    sample_id: int,
    label: str,
    reason_code: str,
    operator: str,
) -> tuple[int, int]:
    """Remplace l'avis expert actif, sans modifier les préférences utilisateur."""
    if label not in LABELS:
        raise ValueError("qualification expert inconnue")
    if reason_code not in REASONS:
        raise ValueError("motif d'adjudication inconnu")
    sample = await connection.fetchrow(
        "SELECT * FROM training_samples WHERE id=$1",
        sample_id,
    )
    if sample is None:
        raise ValueError("échantillon introuvable")
    target_sample_id = sample_id
    if sample["kind"] != "ground_truth":
        target_sample_id = int(
            await connection.fetchval(
                """
                INSERT INTO training_samples (
                    message_id,kind,dossier,dossier_sha256,schema_version,
                    model_classification,model_decision,prompt_version,
                    teacher_model_name,teacher_model_version,teacher_provider,
                    teacher_target,split_group_hash
                ) VALUES (
                    $1,'ground_truth',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
                )
                ON CONFLICT (kind,dossier_sha256) DO UPDATE SET
                    split_group_hash=coalesce(
                        training_samples.split_group_hash,EXCLUDED.split_group_hash
                    ),
                    teacher_target=coalesce(
                        training_samples.teacher_target,EXCLUDED.teacher_target
                    )
                RETURNING id
                """,
                sample["message_id"],
                sample["dossier"],
                sample["dossier_sha256"],
                sample["schema_version"],
                sample["model_classification"],
                sample["model_decision"],
                sample["prompt_version"],
                sample["teacher_model_name"],
                sample["teacher_model_version"],
                sample["teacher_provider"],
                sample["teacher_target"],
                sample["split_group_hash"],
            )
        )
    await connection.execute(
        """
        UPDATE labels l SET active=false,updated_at=now()
        FROM training_sample_annotations a
        WHERE a.sample_id=$1 AND a.label_id=l.id
          AND a.authority='expert' AND l.active=true
        """,
        target_sample_id,
    )
    context = json.dumps(
        {
            "training_sample_id": target_sample_id,
            "source_sample_id": sample_id,
            "reason_code": reason_code,
            "authority": "expert",
            "operator": operator[:120],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    row = await connection.fetchrow(
        """
        INSERT INTO labels (
            message_id,source,label,confidence,is_ground_truth,context
        ) VALUES ($1,'expert_adjudication',$2,1,true,$3::jsonb)
        RETURNING id,created_at
        """,
        sample["message_id"],
        label,
        context,
    )
    label_id = int(row["id"])
    await connection.execute(
        """
        INSERT INTO training_sample_annotations (
            sample_id,label_id,label,source,authority,scope,confidence,labelled_at
        ) VALUES ($1,$2,$3,'expert_adjudication','expert','security',1,$4)
        """,
        target_sample_id,
        label_id,
        label,
        row["created_at"],
    )
    await connection.execute(
        """
        INSERT INTO audit_log(actor,action,payload)
        VALUES ($1,'training.sample_adjudicated',$2::jsonb)
        """,
        operator[:120],
        context,
    )
    return target_sample_id, label_id


async def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.adjudication",
        description="Qualifie un échantillon du corpus après revue experte.",
    )
    parser.add_argument("sample_id", type=int)
    parser.add_argument("label", choices=LABELS)
    parser.add_argument("--reason-code", choices=REASONS, required=True)
    parser.add_argument("--operator", default="operator")
    arguments = parser.parse_args()
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        async with pool.acquire() as connection, connection.transaction():
            target_sample_id, label_id = await adjudicate(
                connection,
                sample_id=arguments.sample_id,
                label=arguments.label,
                reason_code=arguments.reason_code,
                operator=arguments.operator,
            )
    finally:
        await pool.close()
    print(json.dumps({"sample_id": target_sample_id, "label_id": label_id}))


if __name__ == "__main__":
    asyncio.run(_main())
