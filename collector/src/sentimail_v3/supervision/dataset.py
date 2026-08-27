"""Export du corpus d'entraînement, en lecture seule.

Deux matières distinctes, qui ne valent pas la même chose et ne doivent jamais
être confondues.

Les **qualifications humaines** sont la vérité terrain : elles disent ce qu'un
message était réellement, et elles seules peuvent servir à mesurer un modèle.

Les **jugements du modèle** n'enseignent que la forme : lire un dossier, séparer
charge et décharge, ne citer que les indices présents, produire la décision
attendue. Ils sont utiles pour apprendre la méthode, jamais pour établir la
vérité, et l'export les sépare pour qu'on ne puisse pas s'y tromper.

Le découpage n'est pas aléatoire : deux messages d'une même campagne se
ressemblent au point qu'un tirage au sort mettrait des quasi-jumeaux de part et
d'autre, et le modèle paraîtrait bien meilleur qu'il n'est. Les échantillons
sont donc groupés par familles de preuves avant d'être répartis.
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
from sentimail_v3.supervision.training import SCHEMA

SPLITS = (("train", 0.7), ("valid", 0.15), ("test", 0.15))


def _bucket(sample: dict[str, Any]) -> str:
    """Regroupe les dossiers qui se ressemblent, pour ne pas les séparer."""
    dossier = sample.get("dossier") or {}
    # L'ordre d'écriture ne doit rien changer : deux envois d'une même campagne
    # se ressemblent, quel que soit l'ordre dans lequel leurs indices sont
    # apparus. Sans ce tri, ils tomberaient de part et d'autre du découpage et
    # le modèle paraîtrait meilleur qu'il n'est.
    families = sorted(str(value) for value in (dossier.get("evidence_families") or []))
    codes = sorted(
        str(clue.get("clue_code")) for clue in (dossier.get("clues") or [])
    )
    signature = "|".join(families) + "#" + "|".join(codes[:8])
    return hashlib.sha256(signature.encode()).hexdigest()[:16]


def split_of(bucket: str) -> str:
    """Répartition stable : un même groupe retombe toujours du même côté."""
    position = int(bucket[:8], 16) / 0xFFFFFFFF
    running = 0.0
    for name, share in SPLITS:
        running += share
        if position < running:
            return name
    return SPLITS[-1][0]


async def collect(pool: asyncpg.Pool[Any], kind: str) -> list[dict[str, Any]]:
    rows = await pool.fetch(
        """
        SELECT id, label_id, kind, dossier, dossier_sha256, human_label,
               model_classification, model_decision, prompt_version, created_at
        FROM training_samples
        WHERE kind=$1 AND schema_version=$2
        ORDER BY created_at
        """,
        kind,
        SCHEMA,
    )
    samples = []
    for row in rows:
        dossier = row["dossier"]
        if isinstance(dossier, str):
            dossier = json.loads(dossier)
        samples.append(
            {
                "sample_id": int(row["id"]),
                "kind": str(row["kind"]),
                "dossier": dossier,
                "dossier_sha256": str(row["dossier_sha256"]),
                "human_label": row["human_label"],
                "model_classification": row["model_classification"],
                "model_decision": row["model_decision"],
                "prompt_version": row["prompt_version"],
                "observed_at": str(row["created_at"]),
            }
        )
    return samples


def write_jsonl(path: Path, samples: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(sample, ensure_ascii=False, sort_keys=True) + "\n"
            for sample in samples
        ),
        encoding="utf-8",
    )


async def export(destination: Path) -> dict[str, Any]:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        ground_truth = await collect(pool, "ground_truth")
        form_examples = await collect(pool, "form_example")
    finally:
        await pool.close()

    destination.mkdir(parents=True, exist_ok=True)
    parts: dict[str, list[dict[str, Any]]] = {name: [] for name, _ in SPLITS}
    for sample in ground_truth:
        parts[split_of(_bucket(sample))].append(sample)
    for name, samples in parts.items():
        write_jsonl(destination / f"{name}.jsonl", samples)
    write_jsonl(destination / "form_examples.jsonl", form_examples)

    labels: dict[str, int] = {}
    for sample in ground_truth:
        key = str(sample.get("human_label") or "sans_label")
        labels[key] = labels.get(key, 0) + 1
    manifest = {
        "schema_version": SCHEMA,
        "ground_truth_total": len(ground_truth),
        "form_examples_total": len(form_examples),
        "labels": labels,
        "splits": {name: len(samples) for name, samples in parts.items()},
        "personal_data": "absent by construction",
        "warning": (
            "form_examples enseigne la forme, jamais la vérité : ne jamais "
            "l'utiliser pour mesurer un modèle."
        ),
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.dataset",
        description="Exporte le corpus d'entrainement fige, sans donnee personnelle.",
    )
    parser.add_argument("destination", help="repertoire de sortie")
    arguments = parser.parse_args()
    manifest = asyncio.run(export(Path(arguments.destination)))
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
