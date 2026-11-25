"""Un corpus de sécurité qui conserve la trace des préférences écartées."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentimail_v3.judgment.classifier_runtime import corpus_fingerprint
from sentimail_v3.supervision.dataset import collect, dataset_id, quality, split_of, write_jsonl
from sentimail_v3.judgment.classifier import group_id


async def export(pool: Any, destination: Path) -> dict[str, Any]:
    async with pool.acquire() as connection, connection.transaction(isolation="repeatable_read", readonly=True):
        humans = await collect(connection, "ground_truth")
        teachers = await collect(connection, "form_example")
        source_quality = await quality(connection)
        source_quality["conflicting_samples"] = sum(r.get("label_authority") == "conflict" for r in humans)
        fingerprint = await corpus_fingerprint(connection)
        gaps = await connection.fetch("""SELECT g.label_id,g.source FROM training_label_gaps g""")
        labelled = {int(r["id"]) for r in await connection.fetch("""SELECT DISTINCT t.id
            FROM training_samples t JOIN labels l ON l.message_id=t.message_id
            WHERE l.active AND l.is_ground_truth AND t.kind='form_example'""")}
    # Même un label sans dossier interdit que son message devienne enseignant.
    # Les préférences contradictoires restent présentes : leur groupe entier
    # sera exclu de la distillation, au lieu de disparaître de l'export.
    for row in teachers:
        row["has_human_feedback"] = row["sample_id"] in labelled
    expert_conflicts = 0
    for row in humans:
        labels = {a["label"] for a in row["annotations"]
                  if a["authority"] == "expert" and a["scope"] == "security"}
        expert_conflicts += int(len(labels) > 1)
    destination.mkdir(parents=True, exist_ok=True)
    parts = {name: [] for name in ("train", "valid", "test")}
    for row in humans:
        parts[split_of(group_id(row["dossier"]))].append(row)
    for name, rows in parts.items():
        write_jsonl(destination / f"{name}.jsonl", rows)
    write_jsonl(destination / "form_examples.jsonl", teachers)
    manifest = {
        "dataset_id": dataset_id([*humans, *teachers]),
        "corpus_sha256": fingerprint,
        "source_quality": source_quality,
        "quality": {
            "unmaterialized_labels": sum(g["source"] != "smtp_feedback_user" for g in gaps),
            "conflicting_samples": expert_conflicts,
        },
        "exclusions": {
            "mailbox_labels_without_dossier": [g["label_id"] for g in gaps if g["source"] == "smtp_feedback_user"],
            "preference_conflicts": [r["sample_id"] for r in humans
                                     if r.get("label_authority") == "conflict"
                                     and not any(a["authority"] == "expert" for a in r["annotations"])],
            "teacher_samples_with_feedback": len(labelled),
        },
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return manifest
