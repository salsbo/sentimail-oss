"""Exporter un corpus versionné, désensibilisé et vérifiable.

Les qualifications humaines servent à mesurer. Les jugements du modèle ne
servent qu'à apprendre la forme de la réponse. Les deux matières restent dans
des fichiers distincts et le manifeste porte leurs provenances, leurs lacunes
et l'empreinte exacte de l'export.

Le découpage n'est pas aléatoire ligne par ligne. Une signature stable des
familles et codes de preuve garde les dossiers voisins dans le même groupe,
afin qu'un quasi-duplicat ne soit pas à la fois appris et testé.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.supervision.training import (
    SCHEMA,
    SCHEMA_ALIASES,
    canonical_dossier,
    split_group_hash,
)

SPLITS = (("train", 0.7), ("valid", 0.15), ("test", 0.15))
EXPORT_VERSION = "sentimail-training-export-2"
OUTPUT_FILES = (
    "train.jsonl",
    "valid.jsonl",
    "test.jsonl",
    "form_examples.jsonl",
    "manifest.json",
)


def _bucket(sample: dict[str, Any]) -> str:
    """Retourne le groupe persistant, avec un repli pour les anciens exports."""
    stored = str(sample.get("split_group_hash") or "")
    if len(stored) == 64 and all(char in "0123456789abcdef" for char in stored):
        return stored[:16]
    dossier = sample.get("dossier") or {}
    if not isinstance(dossier, dict):
        raise TypeError("dossier absent du corpus")
    return split_group_hash(dossier)[:16]


def split_of(bucket: str) -> str:
    """Répartition stable : un même groupe retombe toujours du même côté."""
    position = int(bucket[:8], 16) / 0xFFFFFFFF
    running = 0.0
    for name, share in SPLITS:
        running += share
        if position < running:
            return name
    return SPLITS[-1][0]


def _decode_json(value: object) -> object:
    if isinstance(value, str):
        return json.loads(value)
    return value


async def _annotations(pool: asyncpg.Pool[Any]) -> dict[int, list[dict[str, Any]]]:
    rows = await pool.fetch(
        """
        SELECT a.sample_id, a.label_id,
               coalesce(l.label, a.label) AS label,
               coalesce(l.source, a.source) AS source,
               a.authority, a.scope,
               coalesce(l.confidence, a.confidence) AS confidence,
               coalesce(l.created_at, a.labelled_at) AS labelled_at
        FROM training_sample_annotations a
        LEFT JOIN labels l ON l.id = a.label_id
        WHERE coalesce(l.active, true) = true
        ORDER BY a.sample_id, a.authority, labelled_at, a.id
        """
    )
    result: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        result.setdefault(int(row["sample_id"]), []).append(
            {
                "label_id": int(row["label_id"])
                if row["label_id"] is not None
                else None,
                "label": str(row["label"]),
                "source": str(row["source"]),
                "authority": str(row["authority"]),
                "scope": str(row["scope"]),
                "confidence": (
                    float(row["confidence"]) if row["confidence"] is not None else None
                ),
                "labelled_at": str(row["labelled_at"]),
            }
        )
    return result


def resolve_label(sample: dict[str, Any]) -> tuple[str | None, str]:
    """Choisit une cible sans faire passer une préférence pour une expertise."""
    annotations = sample.get("annotations")
    values = annotations if isinstance(annotations, list) else []
    experts = {
        str(value.get("label"))
        for value in values
        if isinstance(value, dict) and value.get("authority") == "expert"
    }
    users = {
        str(value.get("label"))
        for value in values
        if isinstance(value, dict) and value.get("authority") == "user"
    }
    chosen = experts or users
    if len(chosen) == 1:
        return next(iter(chosen)), "expert" if experts else "user"
    if len(chosen) > 1:
        return None, "conflict"
    legacy = sample.get("human_label")
    if legacy:
        return str(legacy), "legacy"
    return None, "missing"


async def collect(pool: asyncpg.Pool[Any], kind: str) -> list[dict[str, Any]]:
    rows = await pool.fetch(
        """
        SELECT id, label_id, kind, dossier, dossier_sha256, human_label,
               model_classification, model_decision, prompt_version,
               schema_version, created_at, teacher_model_name,
               teacher_model_version, teacher_provider, teacher_target,
               split_group_hash
        FROM training_samples
        WHERE kind=$1 AND schema_version = ANY($2::text[])
        ORDER BY created_at, id
        """,
        kind,
        list(SCHEMA_ALIASES),
    )
    annotations = await _annotations(pool) if kind == "ground_truth" else {}
    samples: list[dict[str, Any]] = []
    for row in rows:
        source_schema = str(row["schema_version"])
        dossier = canonical_dossier(_decode_json(row["dossier"]))
        sample = {
            "sample_id": int(row["id"]),
            "kind": str(row["kind"]),
            "dossier": dossier,
            "dossier_sha256": str(row["dossier_sha256"]),
            "source_schema_version": source_schema,
            "split_group_hash": str(
                row["split_group_hash"] or split_group_hash(dossier)
            ),
            "human_label": row["human_label"],
            "annotations": annotations.get(int(row["id"]), []),
            "model_classification": row["model_classification"],
            "model_decision": row["model_decision"],
            "prompt_version": row["prompt_version"],
            "teacher_model_name": row["teacher_model_name"],
            "teacher_model_version": row["teacher_model_version"],
            "teacher_provider": row["teacher_provider"],
            "teacher_target": _decode_json(row["teacher_target"]),
            "observed_at": str(row["created_at"]),
        }
        if kind == "ground_truth":
            sample["human_label"], sample["label_authority"] = resolve_label(sample)
        samples.append(sample)
    return samples


async def quality(pool: asyncpg.Pool[Any]) -> dict[str, int]:
    row = await pool.fetchrow(
        """
        SELECT
          (SELECT count(*) FROM labels
           WHERE is_ground_truth=true AND active=true) AS active_labels,
          (SELECT count(*) FROM training_sample_annotations a
           JOIN labels l ON l.id=a.label_id
           WHERE l.is_ground_truth=true AND l.active=true) AS materialized_labels,
          (SELECT count(*) FROM training_label_gaps) AS unmaterialized_labels,
          (SELECT count(*) FROM training_samples
           WHERE kind='form_example' AND teacher_target IS NOT NULL) AS teacher_targets,
          (SELECT count(*) FROM training_samples
           WHERE kind='ground_truth' AND teacher_target IS NOT NULL)
             AS ground_truth_teacher_targets,
          (SELECT count(*) FROM training_samples
           WHERE kind='form_example') AS form_examples
        """
    )
    if not row:
        return {}
    # asyncpg.Record s'itère sur les valeurs, contrairement à un dictionnaire.
    column_names = row.keys()
    return {key: int(row[key] or 0) for key in column_names}


def _json_line(sample: dict[str, Any]) -> str:
    return json.dumps(sample, ensure_ascii=False, sort_keys=True, default=str)


def write_jsonl(path: Path, samples: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(_json_line(sample) + "\n" for sample in samples),
        encoding="utf-8",
    )
    temporary.replace(path)


def dataset_id(samples: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(EXPORT_VERSION.encode())
    for sample in sorted(
        samples, key=lambda value: (str(value["kind"]), int(value["sample_id"]))
    ):
        digest.update(_json_line(sample).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def _prepare_destination(destination: Path, *, overwrite: bool) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    existing = [
        destination / name for name in OUTPUT_FILES if (destination / name).exists()
    ]
    if existing and not overwrite:
        raise FileExistsError(
            "export déjà présent : utiliser --force ou un nouveau répertoire"
        )


async def export(
    destination: Path, *, overwrite: bool = False, strict: bool = False
) -> dict[str, Any]:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        ground_truth = await collect(pool, "ground_truth")
        form_examples = await collect(pool, "form_example")
        corpus_quality = await quality(pool)
        from sentimail_v3.judgment.classifier_runtime import corpus_fingerprint
        corpus_sha256 = await corpus_fingerprint(pool)
    finally:
        await pool.close()

    conflicts = sum(
        1 for sample in ground_truth if sample.get("label_authority") == "conflict"
    )
    eligible = [sample for sample in ground_truth if sample.get("human_label")]
    if strict and (corpus_quality.get("unmaterialized_labels", 0) or conflicts):
        raise ValueError(
            "corpus incomplet : labels non matérialisés ou annotations contradictoires"
        )

    _prepare_destination(destination, overwrite=overwrite)
    parts: dict[str, list[dict[str, Any]]] = {name: [] for name, _ in SPLITS}
    for sample in eligible:
        parts[split_of(_bucket(sample))].append(sample)
    for name, samples in parts.items():
        write_jsonl(destination / f"{name}.jsonl", samples)
    write_jsonl(destination / "form_examples.jsonl", form_examples)

    labels: dict[str, int] = {}
    authorities: dict[str, int] = {}
    source_schemas: dict[str, int] = {}
    for sample in ground_truth:
        key = str(sample.get("human_label") or "sans_label")
        labels[key] = labels.get(key, 0) + 1
        authority = str(sample.get("label_authority") or "missing")
        authorities[authority] = authorities.get(authority, 0) + 1
        schema = str(sample.get("source_schema_version") or "unknown")
        source_schemas[schema] = source_schemas.get(schema, 0) + 1

    all_samples = [*eligible, *form_examples]
    identifier = dataset_id(all_samples)
    manifest = {
        "export_version": EXPORT_VERSION,
        "dataset_id": identifier,
        "corpus_sha256": corpus_sha256,
        "schema_version": SCHEMA,
        "ground_truth_total": len(ground_truth),
        "ground_truth_eligible": len(eligible),
        "form_examples_total": len(form_examples),
        "labels": labels,
        "label_authorities": authorities,
        "source_schema_versions": source_schemas,
        "splits": {name: len(samples) for name, samples in parts.items()},
        "quality": {**corpus_quality, "conflicting_samples": conflicts},
        "personal_data": "absent by construction",
        "warning": (
            "form_examples enseigne la forme, jamais la vérité ; seule une "
            "qualification expertisée mesure la sécurité universelle"
        ),
    }
    temporary = destination / "manifest.json.tmp"
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination / "manifest.json")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.dataset",
        description="Exporte un corpus versionné, désensibilisé et vérifiable.",
    )
    parser.add_argument("destination", help="répertoire de sortie")
    parser.add_argument(
        "--force",
        action="store_true",
        help="remplace uniquement les fichiers d'export connus",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="refuse tout label non matérialisé ou conflit d'annotations",
    )
    arguments = parser.parse_args()
    manifest = asyncio.run(
        export(
            Path(arguments.destination),
            overwrite=arguments.force,
            strict=arguments.strict,
        )
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
