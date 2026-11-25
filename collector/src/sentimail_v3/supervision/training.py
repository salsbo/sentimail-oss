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
noms de fichiers : tout ce qui identifie une personne plutôt qu'un raisonnement.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sentimail_v3.code.families import (
    FAMILIES,
    converging_families,
    family_coverage,
    family_of,
)

SCHEMA = "sentimail-v3-training-view-1"
SCHEMA_ALIASES = frozenset({SCHEMA, "sentinel-v3-training-view-1"})
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


_URL_COVERAGE_FIELDS = frozenset(
    {
        "strategy",
        "base_budget",
        "hard_budget",
        "adaptive_budget",
        "actionable_total",
        "actionable_representatives_total",
        "actionable_representatives_analyzed",
        "exact_or_equivalent_urls_collapsed",
        "primary_actionable_total",
        "actionable_apexes_total",
        "actionable_apexes_analyzed",
        "uninspected_representatives",
        "coverage_limited",
        "render_resources_total",
        "render_resources_analyzed",
        "actionable_analyzed",
    }
)


def _coverage_view(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): item
        for key, item in value.items()
        if key in _URL_COVERAGE_FIELDS
        and isinstance(item, (bool, int, float, str))
    }


def _material_evidence_view(value: object) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "article_code": str(item.get("article_code") or "")[:40],
                "clue_code": str(item.get("clue_code") or "")[:100],
                "material_kind": str(item.get("material_kind") or "")[:80],
                "strength": int(item.get("strength") or 0),
            }
        )
    return result[:20]


def _judgment_rules_view(
    value: object, clues: list[dict[str, object]]
) -> dict[str, object]:
    rules = value if isinstance(value, dict) else {}
    result = {
        "version": str(rules.get("version") or "")[:80],
        "verdict_is_final": bool(rules.get("verdict_is_final", True)),
        "confidence_required": float(rules.get("confidence_required") or 0),
        "deep_execution_complete": bool(rules.get("deep_execution_complete")),
        "static_investigation_complete": bool(
            rules.get("static_investigation_complete")
        ),
        "incomplete_analysis_is_decisive": bool(
            rules.get("incomplete_analysis_is_decisive", True)
        ),
        "authenticated_sender_policy": str(
            rules.get("authenticated_sender_policy") or "none"
        )[:20],
        "trusted_sender": bool(rules.get("trusted_sender")),
        "identity_destination_conflict": bool(rules.get("identity_destination_conflict")),
        # Chez qui ne veut que les vrais doutes, un verdict suspect peut être
        # livré : sans ces deux faits, la cible se contredirait.
        "ask_only_on_real_doubt": bool(rules.get("ask_only_on_real_doubt")),
        "real_doubt": bool(rules.get("real_doubt")),
        "family_coverage": family_coverage(clues),
        "converging_families": converging_families(clues),
        "material_danger_evidence": _material_evidence_view(
            rules.get("material_danger_evidence")
        ),
        "legitimate_confirmations": int(rules.get("legitimate_confirmations") or 0),
        "adverse_confirmations": int(rules.get("adverse_confirmations") or 0),
        "url_coverage": _coverage_view(rules.get("url_coverage")),
        # Les seuils et la pièce jointe : sans eux, la mesure à 60 jours des
        # règles de seuil serait impossible depuis la vue conservée, comme
        # elle l'était pour learned_reduction. Une vue plus ancienne relit
        # None pour la pièce jointe (inconnu), jamais un faux « complet ».
        "attachment_analysis_complete": (
            rules["attachment_analysis_complete"]
            if isinstance(rules.get("attachment_analysis_complete"), bool)
            else None
        ),
        "allow_identity_authenticated": bool(
            rules.get("allow_identity_authenticated")
        ),
        "learned_reduction": float(rules.get("learned_reduction") or 0),
        "authenticated_allow_reduction": float(
            rules.get("authenticated_allow_reduction") or 0
        ),
        "threshold_reduction_applied": float(
            rules.get("threshold_reduction_applied") or 0
        ),
        "reduction_suspended_by": [
            str(code)[:100]
            for code in (
                rules.get("reduction_suspended_by")
                if isinstance(rules.get("reduction_suspended_by"), list)
                else []
            )[:8]
        ],
    }
    return result


def _learned_signals_view(value: object) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict) or not item.get("clue_code"):
            continue
        result.append(
            {
                "clue_code": str(item.get("clue_code"))[:100],
                "confirmed_legitimate": int(item.get("confirmed_legitimate") or 0),
                "confirmed_adverse": int(item.get("confirmed_adverse") or 0),
                "distinct_senders": int(item.get("distinct_senders") or 0),
            }
        )
    return result[:20]


def _label_counts_view(value: object) -> dict[str, int]:
    labels = value if isinstance(value, dict) else {}
    return {
        name: int(labels.get(name) or 0)
        for name in ("legitimate", "spam", "suspect", "dangerous")
        if labels.get(name)
    }


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
        # llm_budget n'était jamais conservé : la fréquence de troncature du
        # dossier envoyé au modèle restait immesurable.
        "llm_truncated": bool(
            (
                dossier.get("llm_budget")
                if isinstance(dossier.get("llm_budget"), dict)
                else {}
            ).get("truncated_for_llm")
        ),
        "judgment_rules": _judgment_rules_view(rules, clues),
        "deep_analysis": {
            "complete": bool(deep.get("complete")),
            "url_coverage": _coverage_view(deep.get("url_coverage")),
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
            "ground_truth_labels": _label_counts_view(
                history.get("ground_truth_labels")
            ),
            "persistent_allow": bool(history.get("persistent_allow")),
            "persistent_hold": bool(history.get("persistent_hold")),
            "sender_domain_age_days": history.get("sender_domain_age_days"),
            "hour_previously_seen": history.get("hour_previously_seen"),
            "size_zscore": history.get("size_zscore"),
        },
        "learned_signals": _learned_signals_view(dossier.get("learned_signals")),
    }


def fingerprint(value: Any) -> str:
    """Empreinte stable d'une vue, pour relier un échantillon à son dossier."""
    import json

    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()
    ).hexdigest()


def canonical_dossier(value: object) -> dict[str, object]:
    """Normalise et assainit un dossier historique par liste blanche.

    Les deux versions 1 ont le même contrat. Seul le nom du produit a changé.
    Refuser tout autre schéma empêche un export de mélanger silencieusement des
    représentations dont les champs n'auraient pas le même sens. La
    reconstruction explicite retire aussi les anciens énoncés libres.
    """
    if not isinstance(value, dict):
        raise TypeError("le dossier d'apprentissage n'est pas un objet")
    schema = str(value.get("schema") or "")
    if schema not in SCHEMA_ALIASES:
        raise ValueError(f"schéma d'apprentissage non pris en charge : {schema!r}")
    clues = [
        clue
        for clue in (_clue_view(item) for item in value.get("clues") or [])
        if clue is not None
    ][:_MAX_CLUES]
    counts = value.get("counts") if isinstance(value.get("counts"), dict) else {}
    deep = (
        value.get("deep_analysis")
        if isinstance(value.get("deep_analysis"), dict)
        else {}
    )
    history = value.get("history") if isinstance(value.get("history"), dict) else {}
    deep_signals = deep.get("signals") if isinstance(deep.get("signals"), list) else []
    return {
        "schema": SCHEMA,
        "clues": clues,
        "evidence_families": _families(clues),
        "converging_families": converging_families(clues),
        "counts": {
            name: int(counts.get(name) or 0)
            for name in (
                "favorable",
                "adverse",
                "neutral",
                "favorable_points",
                "adverse_points",
            )
        },
        "investigation_status": str(value.get("investigation_status") or "")[:40],
        "attachments": int(value.get("attachments") or 0),
        "llm_truncated": bool(value.get("llm_truncated")),
        "judgment_rules": _judgment_rules_view(value.get("judgment_rules"), clues),
        "deep_analysis": {
            "complete": bool(deep.get("complete")),
            "url_coverage": _coverage_view(deep.get("url_coverage")),
            "signals": [
                {
                    "article_code": str(item.get("article_code") or "")[:40],
                    "kind": str(item.get("kind") or "")[:80],
                }
                for item in deep_signals[:_MAX_SIGNALS]
                if isinstance(item, dict)
            ],
        },
        "history": {
            "previous_message_count": int(history.get("previous_message_count") or 0),
            "ground_truth_labels": _label_counts_view(
                history.get("ground_truth_labels")
            ),
            "persistent_allow": bool(history.get("persistent_allow")),
            "persistent_hold": bool(history.get("persistent_hold")),
            "sender_domain_age_days": history.get("sender_domain_age_days"),
            "hour_previously_seen": history.get("hour_previously_seen"),
            "size_zscore": history.get("size_zscore"),
        },
        "learned_signals": _learned_signals_view(value.get("learned_signals")),
    }


def split_group_hash(dossier: dict[str, object]) -> str:
    """Groupe stable et désensibilisé pour séparer train, valid et test."""
    families = sorted(str(value) for value in dossier.get("evidence_families") or [])
    clues = dossier.get("clues") if isinstance(dossier.get("clues"), list) else []
    codes = sorted(
        str(clue.get("clue_code"))
        for clue in clues
        if isinstance(clue, dict) and clue.get("clue_code")
    )
    signature = "|".join(families) + "#" + "|".join(codes)
    return hashlib.sha256(signature.encode()).hexdigest()


def safe_teacher_target(result: dict[str, object]) -> dict[str, object]:
    """Cible de distillation bornée aux décisions et aux codes de preuve.

    Les motivations libres peuvent reprendre une identité ou un passage du
    courrier. Elles restent dans le verdict soumis à la rétention et ne sont
    jamais recopiées dans le corpus permanent.
    """
    attack = result.get("attack") if isinstance(result.get("attack"), dict) else {}

    def codes(name: str) -> list[str]:
        values = result.get(name)
        return [str(value) for value in values[:30]] if isinstance(values, list) else []

    techniques = attack.get("techniques") if isinstance(attack, dict) else []
    return {
        "classification": str(result.get("classification") or "undetermined"),
        "confidence": float(result.get("confidence") or 0.0),
        "delivery_decision": str(result.get("delivery_decision") or "ask_user"),
        "doubt": bool(result.get("verdict_doubt")),
        "supporting_clue_codes": codes("supporting_clue_codes"),
        "contradicting_clue_codes": codes("contradicting_clue_codes"),
        "attack_techniques": (
            [str(value) for value in techniques[:20]]
            if isinstance(techniques, list)
            else []
        ),
    }
