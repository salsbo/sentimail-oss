"""Entraîner hors ligne un modèle CPU et exporter ses seuls coefficients JSON."""

from __future__ import annotations

import argparse
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentimail_v3.judgment.classifier import (
    LLM_QUALIFICATION, POLICY, SCHEMA, features, group_id, model_id, number, offline_blockers, predict,
)
from sentimail_v3.supervision.dataset import split_of
from sentimail_v3.supervision.training import canonical_dossier, fingerprint


def load_corpus(directory: Path) -> dict[str, list[dict[str, Any]]]:
    """Recalcule les groupes : un hash fourni par le fichier n'est pas une preuve."""
    parts = {name: [] for name in ("train", "valid", "test", "form_examples")}
    for name in ("train", "valid", "test", "form_examples"):
        for line in (directory / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            row["dossier"] = canonical_dossier(row["dossier"])
            row["group"] = group_id(row["dossier"])
            # Les anciens exports gardent un groupe historique parfois antérieur
            # à la normalisation des familles. On repartitionne l'ensemble,
            # enseignant compris, sans jamais mélanger train et test.
            destination = "form_examples" if name == "form_examples" else split_of(row["group"])
            parts[destination].append(row)
    return parts


def expert_label(row: dict[str, Any]) -> int | None:
    labels = {a["label"] for a in row.get("annotations", [])
              if a.get("authority") == "expert" and a.get("scope") == "security"}
    if len(labels) != 1:
        return None
    label = next(iter(labels))
    if label not in {"legitimate", "spam", "suspect", "dangerous"}:
        return None
    return int(label == "legitimate")


def correction_label(row: dict[str, Any]) -> int | None:
    """A/B actifs servent de cibles corrigées, sans devenir des expertises."""
    if any(a.get("authority") == "expert" for a in row.get("annotations", [])):
        return None
    labels = {a["label"] for a in row.get("annotations", [])
              if a.get("authority") == "user" and a.get("scope") == "mailbox_preference"}
    if len(labels) != 1 or not labels <= {"legitimate", "spam", "suspect", "dangerous"}:
        return None
    return int(next(iter(labels)) == "legitimate")


def corrected_label(row: dict[str, Any]) -> int | None:
    """Une expertise éventuelle prime ; sinon la correction SMTP fait foi."""
    if any(a.get("authority") == "expert" for a in row.get("annotations", [])):
        return expert_label(row)
    return correction_label(row)


def teacher_label(row: dict[str, Any]) -> int | None:
    """Ni les préférences SMTP ni nos propres prédictions ne nous enseignent."""
    if row.get("teacher_provider") in {"local_classifier", "authenticated_sender_policy"}:
        return None
    target = row.get("teacher_target") or {}
    if target.get("classification") == "legitimate" and target.get("delivery_decision") == "deliver":
        return 1
    if target.get("classification") in {"spam", "suspect", "dangerous", "undetermined"}:
        return 0
    return None


def unique_rows(rows: list[dict[str, Any]], labeler: Any) -> list[tuple[dict[str, Any], int]]:
    """Un groupe ne compte qu'une fois ; une contradiction le rend inutilisable."""
    groups: dict[str, list[tuple[dict[str, Any], int]]] = {}
    excluded = set()
    for row in rows:
        label = labeler(row)
        if labeler in {expert_label, corrected_label} and label is None and any(
            (labeler is corrected_label or a.get("authority") == "expert" and a.get("scope") == "security")
            for a in row.get("annotations", [])
        ):
            excluded.add(row["group"])
        if label is not None:
            groups.setdefault(row["group"], []).append((row, label))
    return [values[-1] for group, values in groups.items()
            if group not in excluded and len({label for _, label in values}) == 1]


def measure(artifact: dict[str, Any], rows: list[tuple[dict[str, Any], int]]) -> dict[str, Any]:
    accepted = unsafe = invalid = adverse = 0
    squared_error = 0.0
    reasons: dict[str, int] = {}
    for row, label in rows:
        adverse += int(label == 0)
        try:
            prediction = predict(artifact, row["dossier"])
            squared_error += (prediction["probability"] - label) ** 2
            accepted += int(prediction["eligible"])
            unsafe += int(prediction["eligible"] and label == 0)
            reason = prediction["reason"]
        except (KeyError, TypeError, ValueError):
            invalid += 1
            reason = "invalid_dossier"
        reasons[reason] = reasons.get(reason, 0) + 1
    total = len(rows)
    return {"total": total, "adverse": adverse, "accepted": accepted, "unsafe": unsafe,
            "invalid": invalid, "coverage": accepted / total if total else 0,
            "brier": squared_error / (total - invalid) if total > invalid else None,
            # Borne unilatérale exacte à 95 %, uniquement si zéro erreur observée.
            "error_upper_95": 1 - 0.05 ** (1 / accepted) if accepted and not unsafe else None,
            "reasons": reasons}


def train(directory: Path, threshold: float = 0.995, qualification: str = "expert") -> dict[str, Any]:
    from sklearn import __version__ as sklearn_version
    from sklearn.exceptions import ConvergenceWarning
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression

    number(threshold, 0.95, 0.99999)
    if qualification not in {"expert", LLM_QUALIFICATION}:
        raise ValueError("contrat de qualification inconnu")
    corpus = load_corpus(directory)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    # Toute annotation humaine écarte le groupe enseignant. Une préférence
    # n'est pas une cible universelle, et l'enseignant ne doit pas l'écraser.
    annotated = {row["group"] for part in ("train", "valid", "test") for row in corpus[part]}
    annotated.update(row["group"] for row in corpus["form_examples"] if row.get("has_human_feedback"))
    teachers = [row for row in corpus["form_examples"] if row["group"] not in annotated]
    expert_train = unique_rows(corpus["train"], expert_label)
    teacher_train = unique_rows([r for r in teachers if split_of(r["group"]) == "train"], teacher_label)
    corrections = []
    if qualification == LLM_QUALIFICATION:
        # Les contradictions, même entre dossiers, écartent le groupe entier.
        human_train = unique_rows(corpus["train"], corrected_label)
        expert_train = [(r, label) for r, label in human_train if expert_label(r) is not None]
        corrections = [(r, label) for r, label in human_train if expert_label(r) is None]
    selected = [(r, label, 1.0) for r, label in expert_train]
    selected += [(r, label, 1.0) for r, label in corrections]
    selected += [(r, label, 0.25) for r, label in teacher_train]
    values, labels, weights, rules_versions = [], [], [], set()
    skipped = 0
    for row, label, weight in selected:
        try:
            value = features(row["dossier"])
        except (KeyError, ValueError, TypeError):
            skipped += 1
            continue
        values.append(value)
        labels.append(label)
        weights.append(weight)
        rules_versions.add(str(row["dossier"]["judgment_rules"].get("version") or ""))
    if len(values) < 20 or set(labels) != {0, 1}:
        raise ValueError("il faut au moins 20 groupes d'entraînement et les deux classes")
    vectorizer = DictVectorizer(sparse=True)
    matrix = vectorizer.fit_transform(values)
    estimator = LogisticRegression(C=1.0, max_iter=2000, random_state=0, solver="lbfgs")
    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        estimator.fit(matrix, labels, sample_weight=weights)
    artifact = {
        "schema": SCHEMA, "policy": POLICY, "qualification": qualification,
        "algorithm": "sklearn.linear_model.LogisticRegression",
        "sklearn_version": sklearn_version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": fingerprint(corpus),
        "split_strategy": "sha256-unique-clue-codes-70-15-15-v1",
        "corpus_sha256": manifest.get("corpus_sha256"),
        "corpus_quality": manifest.get("quality", {}),
        "corpus_exclusions": manifest.get("exclusions", {}),
        "weights": dict(zip(vectorizer.get_feature_names_out().tolist(), estimator.coef_[0].tolist())),
        "intercept": float(estimator.intercept_[0]), "threshold": threshold,
        "rules_versions": sorted(rules_versions),
        "training": {"groups": len(values), "expert_groups": len(expert_train),
                     "teacher_groups": len(teacher_train), "correction_groups": len(corrections), "skipped": skipped,
                     "legitimate": sum(labels), "other": len(labels) - sum(labels)},
    }
    evaluation = {}
    for part in ("valid", "test"):
        evaluation[f"correction_{part}"] = measure(artifact, unique_rows(corpus[part], correction_label))
        evaluation[f"expert_{part}"] = measure(artifact, unique_rows(corpus[part], expert_label))
        evaluation[f"teacher_{part}"] = measure(artifact, unique_rows(
            [r for r in teachers if split_of(r["group"]) == part], teacher_label))
    artifact["evaluation"] = evaluation
    # Vérifie l'export numérique contre la bibliothèque qui a entraîné le modèle.
    from sentimail_v3.judgment.classifier import probability
    for value, expected in zip(values, estimator.predict_proba(matrix)[:, 1]):
        if abs(probability(artifact, value) - expected) > 1e-10:
            raise ValueError("l'export JSON diverge de scikit-learn")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--threshold", type=float, default=0.995)
    parser.add_argument("--qualification", choices=("expert", LLM_QUALIFICATION), default="expert")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("le modèle existe déjà : choisir un nouveau nom de version")
    artifact = train(args.dataset, args.threshold, args.qualification)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(artifact, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"model_id": model_id(artifact), "training": artifact["training"],
                      "evaluation": artifact["evaluation"],
                      "enforcement_blockers": offline_blockers(artifact)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
