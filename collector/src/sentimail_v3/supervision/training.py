"""La forme d'un dossier qui survit à l'oubli : compacte et désensibilisée.

Trois besoins convergent vers la même représentation.

Le premier est la confidentialité : le dossier soumis au juge était persisté
intégralement, corps du message compris, et échappait à la fenêtre de rétention
qui efface pourtant le message lui-même.

Le deuxième est la taille : jusqu'à deux mégaoctets et demi par jugement, pour
une matière dont seuls les indices et les règles importent après coup.

Le troisième est l'apprentissage : une qualification humaine ne vaut, pour
entraîner un modèle, que si la forme du dossier qui l'a motivée lui survit. La
rétention efface le message à trente jours ; le corpus serait vide avant d'être
constitué.

Ce que cette vue conserve : les indices avec leur direction, leur force et leur
article, les règles de jugement, la couverture d'analyse, les familles de
preuves. Ce qu'elle écarte : le sujet, le corps, les adresses, les URL, les
noms de fichiers — tout ce qui identifie une personne plutôt qu'un raisonnement.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sentimail_v3.code.families import FAMILIES, converging_families, family_of

SCHEMA = "sentimail-v3-training-view-1"
_MAX_CLUES = 60
_MAX_SIGNALS = 20


def _clue_view(clue: object) -> dict[str, object] | None:
    if not isinstance(clue, dict) or not clue.get("clue_code"):
        return None
    return {
        "clue_code": str(clue.get("clue_code")),
        "article_code": str(clue.get("article_code") or ""),
        "direction": str(clue.get("direction") or ""),
        "strength": int(clue.get("strength") or 0),
        "confidence": float(clue.get("confidence") or 0),
        # L'énoncé décrit la règle appliquée, pas le message : il reste.
        "statement": str(clue.get("statement") or "")[:300],
        "occurrence_count": int(clue.get("occurrence_count") or 1),
    }


def _families(clues: list[dict[str, object]]) -> list[str]:
    """Regroupe les indices par famille, avec le découpage du jugement.

    Le préfixe du code d'indice ne dit pas toujours le sujet : les constats du
    bac à sable commencent tous par ATTACHMENT_ ou URL_ quel que soit l'article
    qui les fonde. L'apprentissage rangeait donc les preuves autrement que le
    jugement, et ce qui était appris ne correspondait pas à ce qui avait été
    jugé. C'est l'article qui fait foi, ici comme ailleurs.
    """
    return sorted(
        {
            famille
            for famille in (family_of(clue.get("article_code")) for clue in clues)
            if famille in FAMILIES
        }
    )


def compact_dossier(dossier: dict[str, object]) -> dict[str, object]:
    """Vue conservable d'un dossier : ce qui a fondé la décision, et rien d'autre."""
    clues = [
        view
        for view in (_clue_view(clue) for clue in dossier.get("clues") or [])
        if view is not None
    ][:_MAX_CLUES]
    message = dossier.get("message") if isinstance(dossier.get("message"), dict) else {}
    deep = (
        dossier.get("deep_analysis")
        if isinstance(dossier.get("deep_analysis"), dict)
        else {}
    )
    history = deep.get("history") if isinstance(deep.get("history"), dict) else {}
    rules = (
        dossier.get("judgment_rules")
        if isinstance(dossier.get("judgment_rules"), dict)
        else {}
    )
    return {
        "schema": SCHEMA,
        "clues": clues,
        "evidence_families": _families(clues),
        # La couverture détaillée n'est pas conservée : elle se redérive
        # entièrement des indices ci-dessus, et l'écrire ici doublerait le
        # volume d'une vue archivée pour chaque message. Seule la convergence
        # est retenue, parce qu'elle résume en trois mots ce que l'apprentissage
        # doit pouvoir relire : quelles familles fortes se sont rejointes.
        "converging_families": converging_families(clues),
        "counts": {
            "favorable": sum(1 for c in clues if c["direction"] == "favorable"),
            "adverse": sum(1 for c in clues if c["direction"] == "adverse"),
            "neutral": sum(1 for c in clues if c["direction"] == "neutral"),
            "favorable_points": int(message.get("favorable_points") or 0),
            "adverse_points": int(message.get("adverse_points") or 0),
        },
        "investigation_status": str(message.get("investigation_status") or ""),
        "attachments": int(message.get("attachment_count") or 0),
        "judgment_rules": {
            key: rules.get(key)
            for key in (
                "confidence_required",
                "deep_execution_complete",
                "static_investigation_complete",
                "authenticated_sender_policy",
                "trusted_sender",
                "material_danger_evidence",
                "legitimate_confirmations",
                "adverse_confirmations",
                "url_coverage",
            )
            if key in rules
        },
        "deep_analysis": {
            "complete": bool(deep.get("complete")),
            "url_coverage": deep.get("url_coverage") or {},
            "signals": [
                {
                    "article_code": str(signal.get("article_code") or ""),
                    "kind": str(signal.get("kind") or ""),
                }
                for signal in (deep.get("signals") or [])[:_MAX_SIGNALS]
                if isinstance(signal, dict)
            ],
        },
        "history": {
            "previous_message_count": int(history.get("previous_message_count") or 0),
            "ground_truth_labels": history.get("ground_truth_labels") or {},
            "persistent_allow": bool(history.get("persistent_allow")),
            "persistent_hold": bool(history.get("persistent_hold")),
            "sender_domain_age_days": history.get("sender_domain_age_days"),
            "hour_previously_seen": history.get("hour_previously_seen"),
            "size_zscore": history.get("size_zscore"),
        },
        "learned_signals": dossier.get("learned_signals") or [],
    }


def fingerprint(value: Any) -> str:
    """Empreinte stable d'une vue, pour relier un échantillon à son dossier."""
    import json

    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()
    ).hexdigest()
