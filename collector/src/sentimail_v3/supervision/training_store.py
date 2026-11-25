"""Écriture atomique des qualifications dans le corpus permanent."""

from __future__ import annotations

import json
from typing import Any

from sentimail_v3.supervision.training import (
    SCHEMA,
    canonical_dossier,
    safe_teacher_target,
    split_group_hash,
)


def annotation_provenance(source: str) -> tuple[str, str]:
    """Une préférence de boîte n'est pas une expertise de sécurité."""
    if source == "smtp_feedback_user":
        return "user", "mailbox_preference"
    return "expert", "security"


async def store_ground_truth_sample(
    connection: Any, message_id: str, label: str
) -> int | None:
    """Lie le dernier dossier conservable au dernier label actif correspondant.

    Un dossier identique peut recevoir plusieurs annotations. La ligne de
    matière reste unique et la table d'annotations porte tous les avis.
    """
    row = await connection.fetchrow(
        """
        SELECT l.id AS label_id, l.label, l.source, l.confidence, l.created_at,
               vr.input_snapshot, vr.response, vr.model_name
        FROM labels l
        JOIN investigations i ON i.message_id = l.message_id
        JOIN verdict_runs vr ON vr.investigation_id = i.id
        WHERE l.message_id=$1::uuid
          AND l.is_ground_truth=true
          AND l.active=true
          AND l.label=$2
          AND vr.input_snapshot IS NOT NULL
        ORDER BY l.created_at DESC, vr.completed_at DESC NULLS LAST,
                 vr.created_at DESC
        LIMIT 1
        """,
        message_id,
        label,
    )
    if row is None:
        return None
    dossier = row["input_snapshot"]
    if isinstance(dossier, str):
        dossier = json.loads(dossier)
    canonical = canonical_dossier(dossier)
    response = row["response"]
    if isinstance(response, str):
        response = json.loads(response)
    response = response if isinstance(response, dict) else {}
    verdict = response.get("verdict")
    target = safe_teacher_target(verdict) if isinstance(verdict, dict) else None
    metadata = response.get("api") if isinstance(response.get("api"), dict) else {}
    dossier_text = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    # PostgreSQL a produit l'empreinte historique sur jsonb::text. On lui
    # laisse donc calculer cette valeur au lieu de supposer la même sérialisation
    # en Python. Le groupe de split, lui, a son propre contrat canonique.
    sample_id = await connection.fetchval(
        """
        INSERT INTO training_samples (
            label_id, message_id, kind, dossier, dossier_sha256, human_label,
            schema_version, split_group_hash, teacher_model_name,
            teacher_model_version, teacher_provider, teacher_target
        ) VALUES (
            $1, $2::uuid, 'ground_truth', $3::jsonb,
            encode(sha256(convert_to(($3::jsonb)::text, 'UTF8')), 'hex'),
            $4, $5, $6,
            $7, $8, $9, $10::jsonb
        )
        ON CONFLICT (kind, dossier_sha256) DO UPDATE SET
            split_group_hash=coalesce(
                training_samples.split_group_hash, EXCLUDED.split_group_hash
            ),
            teacher_model_name=coalesce(
                training_samples.teacher_model_name, EXCLUDED.teacher_model_name
            ),
            teacher_model_version=coalesce(
                training_samples.teacher_model_version, EXCLUDED.teacher_model_version
            ),
            teacher_provider=coalesce(
                training_samples.teacher_provider, EXCLUDED.teacher_provider
            ),
            teacher_target=coalesce(
                training_samples.teacher_target, EXCLUDED.teacher_target
            )
        RETURNING id
        """,
        row["label_id"],
        message_id,
        dossier_text,
        label,
        SCHEMA,
        split_group_hash(canonical),
        row["model_name"],
        metadata.get("system_fingerprint"),
        metadata.get("provider"),
        json.dumps(target, ensure_ascii=False, separators=(",", ":"))
        if target is not None
        else None,
    )
    authority, scope = annotation_provenance(str(row["source"]))
    await connection.execute(
        """
        INSERT INTO training_sample_annotations (
            sample_id, label_id, label, source, authority, scope, confidence,
            labelled_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT DO NOTHING
        """,
        sample_id,
        row["label_id"],
        row["label"],
        row["source"],
        authority,
        scope,
        row["confidence"],
        row["created_at"],
    )
    return int(sample_id)
